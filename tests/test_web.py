import json
import re
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

from phishguard.config import ConfigError, load_settings
from phishguard.incidents import IncidentStore, new_incident_id
from phishguard.web import create_app

from .test_scorer import scorer as stub_scorer

FIXTURES = Path(__file__).parent / "fixtures"
PASSWORD = "correct horse battery staple"  # noqa: S105 - test credential
API_KEY = "k" * 43


def settings(**overrides):
    env = {"FLASK_SECRET_KEY": "s" * 40, "API_KEY": API_KEY, "ADMIN_USERNAME": "admin",
           "ADMIN_PASSWORD_HASH": generate_password_hash(PASSWORD), **overrides}
    return load_settings(env)


@pytest.fixture
def app(tmp_path):
    store = IncidentStore(tmp_path / "reports", tmp_path / "quarantine")
    app = create_app(settings(), scorer=stub_scorer(p_email=0.9, p_sms=0.9), store=store)
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def csrf(client, path="/login"):
    page = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" type="hidden" value="([^"]+)"', page).group(1)


def login(client, password=PASSWORD, username="admin", next_url=""):
    token = csrf(client)
    url = "/login" + (f"?next={next_url}" if next_url else "")
    return client.post(url, data={"csrf_token": token, "username": username,
                                  "password": password})


# ---------------------------------------------------------------- fail closed


@pytest.mark.parametrize("overrides", [
    {"FLASK_SECRET_KEY": "change-me"}, {"FLASK_SECRET_KEY": "short"},
    {"API_KEY": ""}, {"ADMIN_PASSWORD_HASH": "change-me"},
    {"ADMIN_PASSWORD_HASH": "plaintext-password"},
])
def test_app_refuses_to_start_with_unsafe_secrets(overrides, tmp_path):
    with pytest.raises(ConfigError):
        create_app(settings(**overrides), store=IncidentStore(tmp_path, tmp_path))


# ---------------------------------------------------------------- auth


@pytest.mark.parametrize("path", ["/", "/dashboard", f"/incidents/{new_incident_id()}"])
def test_pages_require_login(client, path):
    response = client.get(path)
    assert response.status_code == 302 and "/login" in response.headers["Location"]


def test_login_logout_and_audit(client, app):
    assert "Wrong user name" in login(client, password="nope").get_data(as_text=True)
    assert "Wrong user name" in login(client, username="root").get_data(as_text=True)
    response = login(client)
    assert response.status_code == 302 and response.headers["Location"] == "/"
    assert client.get("/dashboard").status_code == 200
    assert client.post("/logout").status_code == 400  # CSRF token required
    token = csrf(client, "/dashboard")
    client.post("/logout", data={"csrf_token": token})
    assert client.get("/dashboard").status_code == 302
    events = [e["event"] for e in app.extensions["phishguard_store"].audit_tail()]
    assert events == ["web_login_failed", "web_login_failed", "web_login"]
    assert PASSWORD not in app.extensions["phishguard_store"].audit.path.read_text()


def test_login_needs_csrf_token(client):
    response = client.post("/login", data={"username": "admin", "password": PASSWORD})
    assert response.status_code == 400


@pytest.mark.parametrize("target", ["//evil.test/x", "https://evil.test/", "/\\evil.test"])
def test_no_open_redirect_after_login(client, target):
    assert login(client, next_url=target).headers["Location"] == "/"


def test_local_redirect_after_login_is_kept(client):
    assert login(client, next_url="/dashboard").headers["Location"] == "/dashboard"


def test_login_is_rate_limited(client):
    codes = [login(client, password="wrong").status_code for _ in range(6)]
    assert codes[:5] == [200] * 5 and codes[5] == 429


def test_session_cookie_flags(client):
    cookie = login(client).headers.get("Set-Cookie")
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=Lax" in cookie


# ---------------------------------------------------------------- headers


def test_security_headers(client):
    response = client.get("/login")
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert "<script" not in response.get_data(as_text=True)


# ---------------------------------------------------------------- scanning UI


def test_sms_scan_shows_explained_verdict_and_escapes_input(client, app):
    login(client)
    token = csrf(client, "/")
    response = client.post("/", data={"csrf_token": token, "sms-csrf_token": token,
                                      "sms-text": "Your SBI KYC expires, reply now",
                                      "sms-sender": "<script>alert(1)</script>"})
    page = response.get_data(as_text=True)
    assert response.status_code == 200 and "Why?" in page and "text_model" in page
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    (entry,) = [e for e in app.extensions["phishguard_store"].audit_tail()
                if e["event"] == "web_scan"]
    assert entry["kind"] == "sms" and "text" not in entry  # no message content logged


def test_email_upload_scan(client):
    login(client)
    token = csrf(client, "/")
    data = {"email-csrf_token": token,
            "email-eml": ((FIXTURES / "phish_spoofed_sender.eml").open("rb"), "m.eml")}
    page = client.post("/", data=data, content_type="multipart/form-data").get_data(True)
    assert "Phishing" in page and "quarantine" in page


def test_scan_form_without_csrf_is_rejected(client):
    login(client)
    response = client.post("/", data={"sms-text": "hello"})
    assert response.status_code in (200, 400)
    assert "Why?" not in response.get_data(as_text=True)


# ---------------------------------------------------------------- dashboard


def write_incident(store, action="quarantined"):
    incident = new_incident_id()
    verdict = {"score": 0.97, "label": "phishing", "action": "quarantine", "kind": "email",
               "analysed": True, "components": {},
               "reasons": [{"source": "header", "code": "dmarc_fail", "detail": "<b>x</b>",
                            "weight": 1.4, "strength": "medium"}],
               "summary": {"from": "evil@example.test", "subject": "<i>Pay now</i>"}}
    store.write_report(incident, {"created_at": "2026-10-08T10:00:00Z", "mode": "quarantine",
                                  "action_taken": action, "message_id": "<m@x>",
                                  "content_sha256": "ab",
                                  "mailbox": {"host": "h", "folder": "INBOX", "uid": 3},
                                  "verdict": verdict})
    store.audit.append("scanned", uid=3, action_taken=action, incident_id=incident)
    return incident


def test_dashboard_and_incident_pages(client, app):
    store = app.extensions["phishguard_store"]
    incident = write_incident(store)
    login(client)
    page = client.get("/dashboard").get_data(as_text=True)
    assert incident in page and "intact" in page
    assert "<i>Pay now</i>" not in page and "&lt;i&gt;Pay now" in page
    detail = client.get(f"/incidents/{incident}").get_data(as_text=True)
    assert "dmarc_fail" in detail and "<b>x</b>" not in detail
    assert client.get("/incidents/../../etc/passwd").status_code == 404
    assert client.get(f"/incidents/{new_incident_id()}").status_code == 404


def test_dashboard_reports_a_tampered_audit_log(client, app):
    store = app.extensions["phishguard_store"]
    write_incident(store)
    write_incident(store)
    lines = store.audit.path.read_text().splitlines()
    store.audit.path.write_text(lines[1] + "\n")
    login(client)
    assert "TAMPERED" in client.get("/dashboard").get_data(as_text=True)


def test_web_app_has_no_mailbox_changing_routes(app):
    writable = {rule.rule for rule in app.url_map.iter_rules()
                if rule.methods & {"POST", "PUT", "PATCH", "DELETE"}}
    assert writable == {"/login", "/logout", "/", "/api/v1/scan/email", "/api/v1/scan/sms"}


# ---------------------------------------------------------------- API


def auth(key=API_KEY):
    return {"Authorization": f"Bearer {key}"}


def test_api_requires_the_key(client):
    assert client.post("/api/v1/scan/sms", json={"text": "hi"}).status_code == 401
    wrong = client.post("/api/v1/scan/sms", json={"text": "hi"}, headers=auth("x" * 43))
    assert wrong.status_code == 401 and wrong.headers["WWW-Authenticate"].startswith("Bearer")
    assert client.get("/api/v1/health").get_json() == {"status": "ok"}


def test_api_sms_and_email(client):
    response = client.post("/api/v1/scan/sms", headers=auth(),
                           json={"text": "Your KYC expires today, reply now", "sender": "x"})
    data = response.get_json()
    assert response.status_code == 200 and data["kind"] == "sms" and data["reasons"]
    raw = (FIXTURES / "phish_spoofed_sender.eml").read_bytes()
    response = client.post("/api/v1/scan/email", headers=auth(), data=raw,
                           content_type="message/rfc822")
    assert response.get_json()["action"] == "quarantine"


@pytest.mark.parametrize("body", [
    {"text": 5}, {"text": ""}, {"text": "x" * 5001}, {"text": "hi", "sender": 7},
    {"text": "hi", "sender": "s" * 101}, ["not", "an", "object"],
])
def test_api_rejects_bad_sms_input(client, body):
    response = client.post("/api/v1/scan/sms", headers=auth(), data=json.dumps(body),
                           content_type="application/json")
    assert response.status_code == 400 and "error" in response.get_json()


def test_api_rejects_empty_and_oversized_email(client, app):
    assert client.post("/api/v1/scan/email", headers=auth()).status_code == 400
    too_big = b"x" * (app.config["MAX_CONTENT_LENGTH"] + 1)
    response = client.post("/api/v1/scan/email", headers=auth(), data=too_big)
    assert response.status_code == 413 and response.get_json() == {"error": "Too large."}


def test_api_is_rate_limited(client):
    codes = [client.post("/api/v1/scan/sms", headers=auth(), json={"text": "hello there"})
             .status_code for _ in range(61)]
    assert codes[-1] == 429 and set(codes[:60]) == {200}


def test_scores_never_display_as_certain(app):
    pct = app.jinja_env.filters["pct"]
    assert (pct(0.9997), pct(0.0002), pct(0.5)) == (">99.9%", "<0.1%", "50.0%")
