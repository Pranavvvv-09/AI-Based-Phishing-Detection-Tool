import json
import re
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from werkzeug.security import generate_password_hash

from phishguard.config import ConfigError, load_settings
from phishguard.incidents import IncidentStore, new_incident_id
from phishguard.mailbox import Mailbox
from phishguard.poller import Poller
from phishguard.web import create_app, pct

from .imap_fake import FakeServer
from .test_poller import MarkerScorer, email
from .test_scorer import scorer as stub_scorer

FIXTURES = Path(__file__).parent / "fixtures"
PASSWORD = "correct horse battery staple"
API_KEY = "k" * 43
QFOLDER = "PhishGuard-Quarantine"


def settings(**overrides):
    env = {"FLASK_SECRET_KEY": "s" * 40, "API_KEY": API_KEY, "ADMIN_USERNAME": "admin",
           "ADMIN_PASSWORD_HASH": generate_password_hash(PASSWORD), "MODE": "quarantine",
           "IMAP_USER": "me@example.test", "IMAP_APP_PASSWORD": "app-pass", **overrides}
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
    page = client.get(path).text
    return re.search(r'<meta name="csrf-token" content="([^"]+)"', page).group(1)


def login(client, password=PASSWORD, username="admin", next_url=""):
    token = csrf_of(client)
    return client.post("/login", data={"csrf_token": token, "username": username,
                                       "password": password, "next": next_url},
                       follow_redirects=False)


def quarantine_one(world, marker="PHISH"):
    server, store, poller, _, _ = world
    poller.poll_once()
    server.deliver(email(len(server.messages("INBOX")) + 100, marker))
    poller.poll_once()
    return [r for r in store.quarantined() if not r.get("restored_at")][-1]["incident_id"]


# ---------------------------------------------------------------- fail closed


@pytest.mark.parametrize("overrides", [
    {"FLASK_SECRET_KEY": "change-me"}, {"FLASK_SECRET_KEY": "short"}, {"API_KEY": ""},
    {"API_KEY": "too-short"}, {"ADMIN_PASSWORD_HASH": "change-me"},
    {"ADMIN_PASSWORD_HASH": "plaintext-password"},
])
def test_app_refuses_to_start_with_unsafe_secrets(overrides, tmp_path):
    with pytest.raises(ConfigError):
        create_app(settings(**overrides), store=IncidentStore(tmp_path, tmp_path))


# ---------------------------------------------------------------- auth


@pytest.mark.parametrize("path", ["/", "/dashboard", f"/incidents/{new_incident_id()}"])
def test_pages_require_login(client, path):
    response = client.get(path, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"].startswith("/login")


def test_login_logout_and_audit(world):
    _, store, _, _, client = world
    assert login(client, password="nope").status_code == 401
    assert "Wrong user name" in login(client, username="root").text
    response = login(client)
    assert response.status_code == 303 and response.headers["location"] == "/"
    assert client.get("/dashboard").status_code == 200
    assert client.post("/logout", data={}).status_code == 400  # CSRF token required
    client.post("/logout", data={"csrf_token": csrf_of(client, "/dashboard")})
    assert client.get("/dashboard", follow_redirects=False).status_code == 303
    events = [e["event"] for e in store.audit_tail()]
    assert events == ["web_login_failed", "web_login_failed", "web_login"]
    assert PASSWORD not in store.audit.path.read_text()


def test_login_needs_csrf_token(client):
    response = client.post("/login", data={"username": "admin", "password": PASSWORD})
    assert response.status_code == 400


def test_session_rotates_on_login(client):
    before = csrf_of(client)
    login(client)
    assert csrf_of(client, "/") != before


@pytest.mark.parametrize("target", ["//evil.test/x", "https://evil.test/", "/\\evil.test"])
def test_no_open_redirect_after_login(client, target):
    assert login(client, next_url=target).headers["location"] == "/"


def test_local_redirect_after_login_is_kept(client):
    assert login(client, next_url="/dashboard").headers["location"] == "/dashboard"


def test_login_is_rate_limited(client):
    codes = [login(client, password="wrong").status_code for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429


def test_session_cookie_flags(client):
    cookie = login(client).headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=strict" in cookie


# ---------------------------------------------------------------- headers


def test_security_headers(client):
    response = client.get("/login")
    csp = response.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp
    assert "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert "<script>" not in response.text  # only the external /static/app.js
    assert client.get("/docs").status_code == 404  # no auto-generated API docs


def test_static_script_uses_textcontent_not_innerhtml(client):
    script = client.get("/static/app.js").text
    assert "textContent" in script and "eval(" not in script
    for sink in (".innerHTML", ".outerHTML", "insertAdjacentHTML", "document.write"):
        assert sink not in script


# ---------------------------------------------------------------- scanning UI


def test_sms_scan_shows_explained_verdict_and_escapes_input(world):
    _, store, _, _, client = world
    login(client)
    response = client.post("/scan/sms", data={"csrf_token": csrf_of(client, "/"),
                                               "text": "Your SBI KYC expires, reply now",
                                               "sender": "<script>alert(1)</script>"})
    assert response.status_code == 200 and "Why?" in response.text
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text
    (entry,) = [e for e in store.audit_tail() if e["event"] == "web_scan"]
    assert entry["kind"] == "sms" and "text" not in entry  # no message content logged


def test_email_upload_scan(client):
    login(client)
    raw = (FIXTURES / "phish_spoofed_sender.eml").read_bytes()
    response = client.post("/scan/email", data={"csrf_token": csrf_of(client, "/")},
                           files={"eml": ("m.eml", raw, "message/rfc822")})
    assert response.status_code == 200 and "Phishing" in response.text


def test_scan_forms_without_csrf_are_rejected(client):
    login(client)
    assert client.post("/scan/sms", data={"text": "hello"}).status_code == 400


# ---------------------------------------------------------------- dashboard


def test_dashboard_shows_quarantine_with_weights_and_restore_buttons(world):
    _, _, _, _, client = world
    incident = quarantine_one(world)
    login(client)
    page = client.get("/dashboard").text
    assert f'data-restore="{incident}"' in page
    assert "text_model" in page  # the explainable weights shown per row
    detail = client.get(f"/incidents/{incident}").text
    assert "Restore to inbox" in detail and "Why?" in detail


def test_incident_ids_are_validated(client):
    login(client)
    assert client.get("/incidents/..%2F..%2Fetc%2Fpasswd").status_code == 404
    assert client.get(f"/incidents/{new_incident_id()}").status_code == 404


def test_dashboard_reports_a_tampered_audit_log(world):
    _, store, _, _, client = world
    quarantine_one(world)
    lines = store.audit.path.read_text().splitlines()
    store.audit.path.write_text("\n".join(lines[1:]) + "\n")
    login(client)
    assert "TAMPERED" in client.get("/dashboard").text


def test_untrusted_message_fields_are_escaped_on_the_dashboard(world):
    server, store, poller, _, client = world
    poller.poll_once()
    server.deliver(b"From: <img src=x onerror=alert(1)>@evil.test\r\n"
                   b"Subject: <b>PHISH</b>\r\nMessage-ID: <x@y>\r\n\r\nPHISH")
    poller.poll_once()
    login(client)
    page = client.get("/dashboard").text
    assert "<img src=x" not in page and "<b>PHISH</b>" not in page


# ---------------------------------------------------------------- restore API


def restore(client, incident, token=None, **headers):
    if token is not None:
        headers["X-CSRF-Token"] = token
    return client.post(f"/api/restore/{incident}", headers=headers)


def test_restore_button_flow_moves_mail_back_and_updates_the_table(world):
    server, store, poller, _, client = world
    incident = quarantine_one(world)
    assert len(server.messages(QFOLDER)) == 1
    login(client)
    token = csrf_of(client, "/dashboard")

    before = client.get("/api/quarantine").json()
    assert before["rows"][0]["status"] == "held" and before["stats"]["held"] == 1
    response = restore(client, incident, token)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "restored" and body["to_folder"] == "INBOX"
    assert body["restored_by"].startswith("web:admin@")

    # Real IMAP effect: out of the quarantine folder, back in the inbox.
    assert server.messages(QFOLDER) == {}
    assert any(b"PHISH" in raw for raw in server.messages("INBOX").values())
    # The table the UI re-fetches now shows it restored, with no Restore button.
    after = client.get("/api/quarantine").json()
    assert after["rows"][0]["status"] == "restored" and after["stats"]["held"] == 0
    assert f'data-restore="{incident}"' not in client.get("/dashboard").text
    # And the poller leaves the released message alone.
    assert poller.poll_once().quarantined == 0
    events = [e["event"] for e in store.audit_tail()]
    assert "restored" in events and "skipped_released" in events


def test_restore_twice_is_a_conflict(world):
    _, _, _, _, client = world
    incident = quarantine_one(world)
    login(client)
    token = csrf_of(client, "/dashboard")
    assert restore(client, incident, token).status_code == 200
    second = restore(client, incident, token)
    assert second.status_code == 409 and "already restored" in second.json()["error"]


def test_restore_requires_login_and_csrf(world):
    server, _, _, _, client = world
    incident = quarantine_one(world)
    assert restore(client, incident).status_code == 401
    login(client)
    assert restore(client, incident).status_code == 403
    assert restore(client, incident, "forged-token").status_code == 403
    assert len(server.messages(QFOLDER)) == 1  # nothing moved


def test_restore_with_api_key(world):
    server, _, _, _, client = world
    incident = quarantine_one(world)
    assert restore(client, incident, Authorization="Bearer " + "x" * 43).status_code == 401
    response = restore(client, incident, Authorization=f"Bearer {API_KEY}")
    assert response.status_code == 200 and response.json()["restored_by"].startswith("web:api")
    assert server.messages(QFOLDER) == {}


def test_restore_unknown_or_malformed_incident(world):
    _, _, _, _, client = world
    login(client)
    token = csrf_of(client, "/dashboard")
    assert restore(client, new_incident_id(), token).status_code == 404
    assert restore(client, "not-an-id", token).status_code == 404


def test_restore_reports_mail_server_failures_and_keeps_the_record_held(world):
    server, store, _, _, client = world
    incident = quarantine_one(world)
    login(client)
    token = csrf_of(client, "/dashboard")
    server.fail_connect = 1
    failed = restore(client, incident, token)
    assert failed.status_code == 502 and "cannot connect" in failed.json()["error"]
    record = store.load_quarantine(incident)
    assert not record.get("restored_at") and "restore_started_at" not in record
    assert len(server.messages(QFOLDER)) == 1
    server.password = "changed"
    assert "login failed" in restore(client, incident, token).json()["error"]
    server.password = "app-pass"
    assert restore(client, incident, token).status_code == 200


def test_restore_when_message_was_removed_by_hand(world):
    server, _, _, _, client = world
    incident = quarantine_one(world)
    server.folders[QFOLDER]["msgs"].clear()
    login(client)
    response = restore(client, incident, csrf_of(client, "/dashboard"))
    assert response.status_code == 502 and "not found" in response.json()["error"]


def test_restore_without_mailbox_credentials_is_unavailable(tmp_path):
    store = IncidentStore(tmp_path / "r", tmp_path / "q")
    app = create_app(settings(IMAP_APP_PASSWORD=""), store=store)
    client = TestClient(app, base_url="https://testserver")
    incident = new_incident_id()
    store.save_quarantine(incident, {"content_sha256": "ab"})
    response = restore(client, incident, Authorization=f"Bearer {API_KEY}")
    assert response.status_code == 503 and "IMAP_APP_PASSWORD" in response.json()["error"]


def test_concurrent_restores_move_the_message_once(world):
    server, _, _, _, client = world
    incident = quarantine_one(world)
    login(client)
    token = csrf_of(client, "/dashboard")
    codes: list[int] = []

    def attempt():
        codes.append(restore(client, incident, token).status_code)

    threads = [threading.Thread(target=attempt) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(codes).count(200) == 1 and set(codes) <= {200, 409}
    moves = [c for c in server.commands if c[:2] == ("UID", "MOVE") and c[-1] == "INBOX"]
    assert len(moves) == 1


def test_restore_is_rate_limited(world):
    _, _, _, _, client = world
    login(client)
    token = csrf_of(client, "/dashboard")
    codes = [restore(client, new_incident_id(), token).status_code for _ in range(11)]
    assert codes[:10] == [404] * 10 and codes[10] == 429


def test_quarantine_api_needs_auth(client):
    assert client.get("/api/quarantine").status_code == 401
    ok = client.get("/api/quarantine", headers={"Authorization": f"Bearer {API_KEY}"})
    assert ok.status_code == 200 and ok.json()["rows"] == []


# ---------------------------------------------------------------- scan API


def auth(key=API_KEY):
    return {"Authorization": f"Bearer {key}"}


def test_scan_api_requires_the_key(client):
    assert client.post("/api/v1/scan/sms", json={"text": "hi"}).status_code == 401
    wrong = client.post("/api/v1/scan/sms", json={"text": "hi"}, headers=auth("x" * 43))
    assert wrong.status_code == 401 and wrong.headers["www-authenticate"].startswith("Bearer")
    assert client.get("/api/health").json() == {"status": "ok"}


def test_scan_api_sms_and_email(client):
    response = client.post("/api/v1/scan/sms", headers=auth(),
                           json={"text": "Your KYC expires today, reply now", "sender": "x"})
    assert response.status_code == 200 and response.json()["kind"] == "sms"
    raw = (FIXTURES / "phish_spoofed_sender.eml").read_bytes()
    response = client.post("/api/v1/scan/email", headers=auth(), content=raw)
    assert response.json()["action"] == "quarantine"


@pytest.mark.parametrize("body", [
    {"text": 5}, {"text": ""}, {"text": "x" * 5001}, {"text": "hi", "sender": 7},
    {"text": "hi", "sender": "s" * 101}, ["not", "an", "object"],
])
def test_scan_api_rejects_bad_sms_input(client, body):
    response = client.post("/api/v1/scan/sms", headers={**auth(), "Content-Type":
                           "application/json"}, content=json.dumps(body))
    assert response.status_code == 400 and "error" in response.json()


def test_scan_api_rejects_empty_and_oversized_email(world):
    _, _, _, app, client = world
    assert client.post("/api/v1/scan/email", headers=auth()).status_code == 400
    limit = app.state.settings.max_email_bytes + 64 * 1024
    response = client.post("/api/v1/scan/email", headers=auth(), content=b"x" * (limit + 1))
    assert response.status_code == 413


def test_scan_api_is_rate_limited(client):
    codes = [client.post("/api/v1/scan/sms", headers=auth(), json={"text": "hello there"})
             .status_code for _ in range(61)]
    assert codes[-1] == 429 and set(codes[:60]) == {200}


def test_scores_never_display_as_certain():
    assert (pct(0.9997), pct(0.0002), pct(0.5), pct(None)) == (">99.9%", "<0.1%", "50.0%", "-")
