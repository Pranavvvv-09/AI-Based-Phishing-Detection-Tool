import hashlib
import json
import re
import threading
import time
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from werkzeug.security import generate_password_hash

from phishguard.config import ConfigError, load_settings
from phishguard.incidents import IncidentStore, new_incident_id
from phishguard.mailbox import Mailbox
from phishguard.poller import Poller
from phishguard.web import PACKAGE_DIR, chip_class, create_app, overview, pct

from .imap_fake import FakeServer
from .test_poller import MarkerScorer, email
from .test_scorer import scorer as stub_scorer

FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).resolve().parent.parent
PASSWORD = "correct horse battery staple"
QFOLDER = "PhishGuard-Quarantine"
HTMX = {"HX-Request": "true"}
# sha512 of the npm tarball was checked against registry.npmjs.org when vendoring;
# this pins the extracted file so a silent swap fails the tests.
HTMX_SHA256 = "e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447"


def settings(**overrides):
    env = {"FLASK_SECRET_KEY": "s" * 40, "ADMIN_USERNAME": "admin",
           "ADMIN_PASSWORD_HASH": generate_password_hash(PASSWORD), "MODE": "quarantine",
           "IMAP_USER": "me@example.test", "IMAP_APP_PASSWORD": "app-pass",
           "IMAP_POLL_SECONDS": "30", **overrides}
    return load_settings(env)


@pytest.fixture
def world(tmp_path):
    """A fake mailbox, an incident store, a poller and the web app sharing them."""
    server = FakeServer()
    store = IncidentStore(tmp_path / "reports", tmp_path / "quarantine")
    config = settings()

    def connect():
        return Mailbox.connect(config.imap_host, config.imap_user, config.imap_app_password,
                               factory=server.factory)

    poller = Poller(config, store, connect, scorer=MarkerScorer())
    app = create_app(config, scorer=stub_scorer(p_email=0.9, p_sms=0.9), store=store,
                     connect=connect)
    client = TestClient(app, base_url="https://testserver")  # Secure cookies need https
    return server, store, poller, app, client


@pytest.fixture
def client(world):
    return world[4]


def csrf_of(client, path="/login"):
    return re.search(r'"X-CSRF-Token": "([^"]+)"', client.get(path).text).group(1)


def api_csrf(client):
    """The CSRF token the React dashboard gets from /api/session (after login)."""
    return client.get("/api/session").json()["csrf"]


def login(client, password=PASSWORD, username="admin", next_url=""):
    return client.post("/login", data={"csrf_token": csrf_of(client), "username": username,
                                       "password": password, "next": next_url},
                       follow_redirects=False)


def quarantine_one(world, marker="PHISH"):
    server, store, poller, _, _ = world
    poller.poll_once()
    server.deliver(email(len(server.messages("INBOX")) + 100, marker))
    poller.poll_once()
    return [r for r in store.quarantined() if not r.get("restored_at")][-1]["incident_id"]


def restore(client, incident, token):
    headers = {"X-CSRF-Token": token} if token else {}
    return client.post(f"/api/restore/{incident}", headers=headers)


# ---------------------------------------------------------------- start-up


@pytest.mark.parametrize("overrides", [
    {"FLASK_SECRET_KEY": "change-me"}, {"FLASK_SECRET_KEY": "short"},
    {"ADMIN_PASSWORD_HASH": "change-me"}, {"ADMIN_PASSWORD_HASH": "plaintext-password"},
])
def test_app_refuses_to_start_with_unsafe_secrets(overrides, tmp_path):
    with pytest.raises(ConfigError):
        create_app(settings(**overrides), store=IncidentStore(tmp_path, tmp_path))


def test_app_starts_without_an_api_key(tmp_path):
    create_app(settings(API_KEY=""), store=IncidentStore(tmp_path, tmp_path))


def test_vendored_htmx_is_the_pinned_file():
    data = (PACKAGE_DIR / "static" / "htmx.min.js").read_bytes()
    assert hashlib.sha256(data).hexdigest() == HTMX_SHA256


# ---------------------------------------------------------------- one command: poller thread


def test_background_poller_runs_with_the_app_and_stops_on_shutdown(tmp_path):
    server = FakeServer()
    server.deliver(email(1))
    store = IncidentStore(tmp_path / "r", tmp_path / "q")
    config = settings()
    app = create_app(config, scorer=MarkerScorer(), store=store,
                     connect=lambda: Mailbox.connect("h", "u", "app-pass",
                                                     factory=server.factory))
    with TestClient(app, base_url="https://testserver") as client:
        background = app.state.app_state["background"]
        assert background.running
        deadline = time.time() + 5
        while store.load_state().get("INBOX") is None and time.time() < deadline:
            time.sleep(0.05)
        assert store.load_state()["INBOX"]["last_uid"] == 1  # it polled the inbox
        login(client)
        assert "Watching me@example.test" in client.get("/api/session").json()["poller"]["text"]
    assert not background.running  # stopped cleanly with the app


def test_no_poller_without_mailbox_credentials(tmp_path):
    app = create_app(settings(IMAP_APP_PASSWORD=""), store=IncidentStore(tmp_path, tmp_path))
    with TestClient(app, base_url="https://testserver") as client:
        assert app.state.app_state["background"] is None
        login(client)
        session = client.get("/api/session").json()
        assert session["poller"]["state"] == "off" and "not connected" in session["poller"]["text"]


# ---------------------------------------------------------------- login


@pytest.mark.parametrize("path", ["/", "/scan"])
def test_pages_require_login(client, path):
    response = client.get(path, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"].startswith("/login")


@pytest.mark.parametrize("path", ["/api/session", "/api/quarantine", "/api/overview"])
def test_api_without_session_is_401_json(client, path):
    response = client.get(path)
    assert response.status_code == 401 and response.json() == {"error": "log in first"}


def test_htmx_requests_after_session_expiry_redirect_the_whole_page(client):
    response = client.post("/scan", headers=HTMX)
    assert response.status_code == 401 and response.headers["hx-redirect"] == "/login"


def test_login_and_logout(world):
    _, store, _, _, client = world
    assert login(client, password="nope").status_code == 401
    assert "Wrong user name" in login(client, username="root").text
    response = login(client)
    assert response.status_code == 303 and response.headers["location"] == "/"
    assert client.get("/").status_code == 200
    assert client.post("/logout", data={}).status_code == 400  # CSRF token required
    client.post("/logout", data={"csrf_token": api_csrf(client)})
    assert client.get("/", follow_redirects=False).status_code == 303
    assert [e["event"] for e in store.audit_tail()] == [
        "web_login_failed", "web_login_failed", "web_login"]
    assert PASSWORD not in store.audit.path.read_text()


def test_login_needs_csrf_token(client):
    response = client.post("/login", data={"username": "admin", "password": PASSWORD})
    assert response.status_code == 400


@pytest.mark.parametrize("target", ["//evil.test/x", "https://evil.test/", "/\\evil.test"])
def test_no_open_redirect_after_login(client, target):
    assert login(client, next_url=target).headers["location"] == "/"


def test_login_is_rate_limited(client):
    codes = [login(client, password="wrong").status_code for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429


def test_session_cookie_flags(client):
    cookie = login(client).headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=strict" in cookie


# ---------------------------------------------------------------- headers


def test_security_headers_and_no_inline_script(client):
    response = client.get("/login")
    csp = response.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe" not in csp
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert re.findall(r"<script[^>]*>", response.text) == [
        '<script src="/static/htmx.min.js" defer>']
    assert '"allowEval": false' in response.text  # htmx never evaluates strings
    assert client.get("/docs").status_code == 404


# ---------------------------------------------------------------- dashboard


def test_dashboard_serves_the_react_app(world):
    _, _, _, _, client = world
    login(client)
    page = client.get("/")
    assert page.status_code == 200 and '<div id="root"></div>' in page.text
    scripts = re.findall(r'<script[^>]*src="([^"]+)"', page.text)
    assert len(scripts) == 1 and scripts[0].startswith("/static/app/assets/")
    assert "<script>" not in page.text and "style=" not in page.text  # CSP: no inline code
    assert client.get(scripts[0]).status_code == 200
    assert "font-src 'self'" in page.headers["content-security-policy"]


def test_session_api_gives_the_dashboard_its_csrf_token_and_status(world):
    _, _, _, _, client = world
    login(client)
    session = client.get("/api/session").json()
    assert session["user"] == "admin" and session["mode"] == "quarantine"
    assert session["csrf"] == csrf_of(client, "/scan")  # same token as the server pages
    assert session["threshold"] == 0.8


def test_quarantine_api_has_what_the_table_needs(world):
    _, _, _, _, client = world
    incident = quarantine_one(world)
    login(client)
    data = client.get("/api/quarantine").json()
    (row,) = data["rows"]
    assert row["incident_id"] == incident and row["kind"] == "email"
    assert row["status"] == "held" and row["score"] == 0.97
    assert row["reasons"] and {"source", "code", "detail", "weight"} <= set(row["reasons"][0])
    assert data["kpis"] == {"scanned": 1, "quarantined": 1, "restored": 0, "held": 1}


def test_overview_api_counts_today_and_the_top_signals(world):
    _, _, _, _, client = world
    incident = quarantine_one(world)
    login(client)
    data = client.get("/api/overview?days=7").json()
    assert data["days"] == 7 and len(data["series"]) == 7
    assert data["series"][-1] == {"date": datetime.now(UTC).date().isoformat(),
                                  "scanned": 1, "quarantined": 1, "restored": 0}
    assert data["current"] == {"scanned": 1, "quarantined": 1, "restored": 0,
                               "released": 0, "mean_score": 0.97}
    assert data["previous"] == {"scanned": 0, "quarantined": 0, "restored": 0,
                                "released": 0, "mean_score": None}
    assert data["held"] == 1
    assert data["signals"] == []  # the stub scorer's only reason has weight 0

    assert restore(client, incident, api_csrf(client)).status_code == 200
    after = client.get("/api/overview?days=7").json()
    assert after["current"]["restored"] == 1 and after["current"]["released"] == 1
    assert after["held"] == 0


@pytest.mark.parametrize("days", ["1", "365", "abc"])
def test_overview_api_only_offers_the_three_ranges(world, days):
    _, _, _, _, client = world
    login(client)
    assert client.get(f"/api/overview?days={days}").status_code in (400, 422)


def test_overview_splits_the_window_from_the_one_before(tmp_path):
    store = IncidentStore(tmp_path / "reports", tmp_path / "quarantine")
    today = date(2026, 10, 8)
    for day in ("2026-10-08", "2026-10-02", "2026-10-01", "2026-09-20"):
        store.audit.path.parent.mkdir(parents=True, exist_ok=True)
        with store.audit.path.open("a") as log:
            log.write(json.dumps({"ts": f"{day}T10:00:00Z", "event": "scanned"}) + "\n")
    store.write_report("20261008T100000Z-aaaaaaaa", {"verdict": {"reasons": [
        {"code": "dmarc_fail", "weight": 1.4}, {"code": "verified_sender", "weight": -2.0},
        {"code": "dmarc_fail", "weight": 0.5}]}})
    store.save_quarantine("20261008T100000Z-aaaaaaaa", {
        "incident_id": "20261008T100000Z-aaaaaaaa", "quarantined_at": "2026-10-08T10:00:00Z",
        "restored_at": "2026-10-08T11:00:00Z", "score": 0.9})
    store.save_quarantine("20261001T100000Z-bbbbbbbb", {
        "incident_id": "20261001T100000Z-bbbbbbbb", "quarantined_at": "2026-10-01T10:00:00Z",
        "restored_at": None, "score": 0.99})
    data = overview(store, 7, today=today)
    assert [d["date"] for d in data["series"]] == [f"2026-10-0{d}" for d in range(2, 9)]
    assert data["current"] == {"scanned": 2, "quarantined": 1, "restored": 1,
                               "released": 1, "mean_score": 0.9}
    # 09-20 is older than both windows.
    assert data["previous"] == {"scanned": 1, "quarantined": 1, "restored": 0,
                                "released": 0, "mean_score": 0.99}
    assert data["held"] == 1
    # Only evidence towards phishing, once per message; the older message is out of range.
    assert data["signals"] == [{"code": "dmarc_fail", "count": 1}]


def test_untrusted_message_fields_stay_data(world):
    server, _, poller, _, client = world
    poller.poll_once()
    server.deliver(b"From: <img src=x onerror=alert(1)>@evil.test\r\n"
                   b"Subject: <b>PHISH</b>\r\nMessage-ID: <x@y>\r\n\r\nPHISH")
    poller.poll_once()
    login(client)
    response = client.get("/api/quarantine")
    assert response.headers["content-type"].startswith("application/json")
    # React renders these as text; the frontend never injects HTML.
    source = "".join(p.read_text() for p in (ROOT / "frontend" / "src").rglob("*.tsx"))
    assert "dangerouslySetInnerHTML" not in source and ".innerHTML" not in source


@pytest.mark.parametrize(("weight", "css"), [
    (2.5, "chip up strong"), (1.2, "chip up medium"), (0.4, "chip up weak"),
    (-2.0, "chip down strong"), (-1.0, "chip down medium"), (-0.3, "chip down weak"),
])
def test_chip_colour_follows_direction_and_strength(weight, css):
    assert chip_class(weight) == css


# ---------------------------------------------------------------- restore


def test_restore_moves_the_message_back_and_updates_the_table_data(world):
    server, store, poller, _, client = world
    incident = quarantine_one(world)
    login(client)
    response = restore(client, incident, api_csrf(client))
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "restored" and body["to_folder"] == "INBOX"
    # The real IMAP effect: out of quarantine, back in the inbox ...
    assert server.messages(QFOLDER) == {}
    assert any(b"PHISH" in raw for raw in server.messages("INBOX").values())
    # ... the data the dashboard re-fetches shows it ...
    data = client.get("/api/quarantine").json()
    assert data["rows"][0]["status"] == "restored" and data["kpis"]["restored"] == 1
    # ... and the poller leaves the released message alone.
    assert poller.poll_once().quarantined == 0
    assert "skipped_released" in [e["event"] for e in store.audit_tail()]


def test_restore_twice_is_a_conflict(world):
    _, _, _, _, client = world
    incident = quarantine_one(world)
    login(client)
    token = api_csrf(client)
    assert restore(client, incident, token).status_code == 200
    again = restore(client, incident, token)
    assert again.status_code == 409 and "already restored" in again.json()["error"]


def test_restore_requires_login_and_csrf(world):
    server, _, _, _, client = world
    incident = quarantine_one(world)
    assert restore(client, incident, None).status_code == 401
    login(client)
    assert restore(client, incident, None).status_code == 403
    assert restore(client, incident, "forged-token").status_code == 403
    assert len(server.messages(QFOLDER)) == 1  # nothing moved


def test_restore_unknown_incident(world):
    _, _, _, _, client = world
    login(client)
    token = api_csrf(client)
    assert restore(client, new_incident_id(), token).status_code == 404
    missing = restore(client, "not-an-id", token)
    assert missing.status_code == 404 and "No such quarantined message" in missing.json()["error"]


def test_mail_server_failure_keeps_the_message_held(world):
    server, store, _, _, client = world
    incident = quarantine_one(world)
    login(client)
    token = api_csrf(client)
    server.fail_connect = 1
    failed = restore(client, incident, token)
    assert failed.status_code == 502 and "cannot connect" in failed.json()["error"]
    assert client.get("/api/quarantine").json()["rows"][0]["status"] == "held"  # retry OK
    record = store.load_quarantine(incident)
    assert not record.get("restored_at") and "restore_started_at" not in record
    assert restore(client, incident, token).status_code == 200


def test_restore_without_mailbox_credentials(tmp_path):
    store = IncidentStore(tmp_path / "r", tmp_path / "q")
    client = TestClient(create_app(settings(IMAP_APP_PASSWORD=""), store=store),
                        base_url="https://testserver")
    incident = new_incident_id()
    store.save_quarantine(incident, {"content_sha256": "ab"})
    login(client)
    response = restore(client, incident, api_csrf(client))
    assert response.status_code == 503 and "IMAP_APP_PASSWORD" in response.json()["error"]


def test_concurrent_clicks_move_the_message_once(world):
    server, _, _, _, client = world
    incident = quarantine_one(world)
    login(client)
    token = api_csrf(client)
    codes: list[int] = []
    threads = [threading.Thread(target=lambda: codes.append(
        restore(client, incident, token).status_code)) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert codes.count(200) == 1 and set(codes) <= {200, 409}
    moves = [c for c in server.commands if c[:2] == ("UID", "MOVE") and c[-1] == "INBOX"]
    assert len(moves) == 1


def test_restore_is_rate_limited(world):
    _, _, _, _, client = world
    login(client)
    token = api_csrf(client)
    codes = [restore(client, new_incident_id(), token).status_code for _ in range(11)]
    assert codes[:10] == [404] * 10 and codes[10] == 429


# ---------------------------------------------------------------- quick scan


def scan(client, **data):
    files = data.pop("files", None)
    return client.post("/scan", data={"csrf_token": csrf_of(client, "/scan"), **data},
                       files=files, headers=HTMX)


def test_quick_scan_sms_returns_the_verdict_panel(world):
    _, store, _, _, client = world
    login(client)
    response = scan(client, kind="sms", text="Your SBI KYC expires, reply now",
                    sender="<script>alert(1)</script>")
    assert response.status_code == 200 and "<html" not in response.text
    assert "Why?" in response.text and 'class="chip' in response.text
    assert "<script>alert(1)</script>" not in response.text
    (entry,) = [e for e in store.audit_tail() if e["event"] == "web_scan"]
    assert entry["kind"] == "sms" and "text" not in entry  # message content never logged


def test_quick_scan_pasted_raw_email_uses_the_header_checks(client):
    login(client)
    raw = (FIXTURES / "phish_spoofed_sender.eml").read_text()
    response = scan(client, kind="email", text=raw)
    assert "Phishing" in response.text and "dmarc" in response.text.lower()


def test_quick_scan_plain_email_text_and_upload(client):
    login(client)
    assert "email" in scan(client, kind="email", text="Please verify your account").text
    raw = (FIXTURES / "phish_spoofed_sender.eml").read_bytes()
    upload = scan(client, kind="email", files={"eml": ("m.eml", raw, "message/rfc822")})
    assert "Phishing" in upload.text


def test_quick_scan_validation(client):
    login(client)
    assert scan(client, kind="email", text="  ").status_code == 400
    assert scan(client, kind="sms", text="x" * 5001).status_code == 400
    assert scan(client, kind="fax", text="hello").status_code in (400, 422)
    no_csrf = client.post("/scan", data={"kind": "sms", "text": "hi"}, headers=HTMX)
    assert no_csrf.status_code == 400


def test_full_page_scan_without_htmx(client):
    login(client)
    response = client.post("/scan", data={"csrf_token": csrf_of(client, "/scan"),
                                          "kind": "sms", "text": "hello there friend"})
    assert response.status_code == 200 and "<html" in response.text and "Why?" in response.text


def test_scores_never_display_as_certain():
    assert (pct(0.9997), pct(0.0002), pct(0.5), pct(None)) == (">99.9%", "<0.1%", "50.0%", "-")
