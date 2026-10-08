"""Web UI, JSON API and read-only admin dashboard.

Run locally::

    python -m phishguard.web          # http://127.0.0.1:5000 (WEB_HOST / WEB_PORT)

Routes
------
* ``/login``, ``/logout``        one admin account (ADMIN_USERNAME + ADMIN_PASSWORD_HASH)
* ``/``                          scan an uploaded ``.eml`` or a pasted SMS (login required)
* ``/dashboard``                 counts, recent incidents, quarantine, audit-log check
* ``/incidents/<id>``            one incident report with its explanation
* ``POST /api/v1/scan/email``    raw RFC 822 bytes in the body
* ``POST /api/v1/scan/sms``      JSON ``{"text": "...", "sender": "..."}``
* ``GET /api/v1/health``         liveness only, no details

Security decisions
------------------
* **Fail closed:** the app refuses to start while FLASK_SECRET_KEY, ADMIN_PASSWORD_HASH
  or API_KEY are missing, placeholders, or (secret key) shorter than 32 characters.
* **Read-only dashboard:** nothing in the web app can move, restore or delete mail;
  restore stays a deliberate CLI action. Its only writes are audit entries.
* **Authentication:** password checked with werkzeug's hash, always (even for an
  unknown user name, so timing doesn't reveal it); API key compared in constant time.
  Login is rate limited (5/minute, 20/hour per address), the API 60/minute.
* **Sessions:** HttpOnly, SameSite=Lax, Secure (WEB_COOKIE_SECURE), 30-minute lifetime;
  every form, including logout, carries a CSRF token. Redirects after login are only
  to local paths.
* **No script, strict CSP:** pages use no JavaScript; ``default-src 'none'`` with only
  the local stylesheet allowed, no framing, no referrer, no caching of pages.
* **Untrusted content stays text:** Jinja autoescaping on; verdict strings are already
  sanitised (control and bidi characters removed) by ``Verdict.to_dict``.
* **Bounded input:** request bodies are capped at MAX_EMAIL_BYTES plus form overhead;
  SMS text at 5,000 characters. Message bodies are never stored or logged.
"""

from __future__ import annotations

import hmac
import secrets
from collections import Counter
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (
    LoginManager,
    UserMixin,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_wtf.file import FileField, FileRequired
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, StringField, TextAreaField
from wtforms.validators import DataRequired, Length

from .config import ConfigError, Settings, load_settings
from .incidents import IncidentStore, valid_incident_id
from .scorer import MAX_SMS_CHARS
from .sms_checks import MAX_SENDER_CHARS

ROOT = Path(__file__).resolve().parents[2]
FORM_OVERHEAD_BYTES = 64 * 1024
MIN_SECRET_KEY_CHARS = 32
# A real hash of a random password: unknown user names cost the same time to reject.
_DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(16))

CSP = ("default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; "
       "frame-ancestors 'none'; base-uri 'none'")


class Admin(UserMixin):
    def __init__(self, username: str) -> None:
        self.id = username


class LoginForm(FlaskForm):
    username = StringField("User name", validators=[DataRequired(), Length(max=100)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=200)])


class EmailForm(FlaskForm):
    eml = FileField(".eml file", validators=[FileRequired()])


class SmsForm(FlaskForm):
    text = TextAreaField("SMS text", validators=[DataRequired(), Length(max=MAX_SMS_CHARS)])
    sender = StringField("Sender (optional)", validators=[Length(max=MAX_SENDER_CHARS)])


class LogoutForm(FlaskForm):
    pass


def check_web_secrets(settings: Settings) -> None:
    missing = [name for name in settings.missing_secrets() if name != "IMAP_APP_PASSWORD"]
    if missing:
        raise ConfigError(f"set {', '.join(missing)} in .env before starting the web app")
    if len(settings.flask_secret_key) < MIN_SECRET_KEY_CHARS:
        raise ConfigError(f"FLASK_SECRET_KEY must be at least {MIN_SECRET_KEY_CHARS} characters")
    if not settings.admin_password_hash.startswith(("scrypt:", "pbkdf2:")):
        raise ConfigError("ADMIN_PASSWORD_HASH must be a werkzeug password hash")


def _is_local_path(target: str) -> bool:
    parts = urlsplit(target)
    return (not parts.scheme and not parts.netloc and target.startswith("/")
            and not target.startswith("//") and "\\" not in target)


def dashboard_stats(store: IncidentStore) -> dict:
    entries = store.audit_tail()
    scanned = [e for e in entries if e.get("event") == "scanned"]
    actions = Counter(e.get("action_taken") for e in scanned)
    last_poll = next((e["ts"] for e in reversed(entries)
                      if e.get("event") in ("scanned", "cursor_reset")), None)
    ok, count, problem = store.audit.verify()
    quarantine = store.quarantined()
    return {
        "scanned": len(scanned),
        "actions": {key: actions.get(key, 0) for key in
                    ("quarantined", "would_quarantine", "flagged_for_review", "delivered",
                     "quarantine_failed")},
        "web_scans": sum(e.get("event") == "web_scan" for e in entries),
        "errors": sum(e.get("event") in ("poll_error", "login_failed") for e in entries),
        "last_poll": last_poll,
        "audit": {"ok": ok, "entries": count, "problem": problem},
        "held": sum(not r.get("restored_at") for r in quarantine),
        "restored": sum(bool(r.get("restored_at")) for r in quarantine),
    }


def create_app(settings: Settings | None = None, scorer=None,
               store: IncidentStore | None = None) -> Flask:
    if settings is None:
        dotenv = ROOT / ".env"
        settings = load_settings(dotenv_path=dotenv if dotenv.exists() else None)
    check_web_secrets(settings)
    if store is None:
        store = IncidentStore(ROOT / "reports", ROOT / "quarantine")

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=settings.flask_secret_key,
        MAX_CONTENT_LENGTH=settings.max_email_bytes + FORM_OVERHEAD_BYTES,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=settings.web_cookie_secure,
        SESSION_COOKIE_NAME="phishguard_session",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        REMEMBER_COOKIE_DURATION=timedelta(0),
        WTF_CSRF_TIME_LIMIT=1800,
    )
    csrf = CSRFProtect(app)
    limiter = Limiter(get_remote_address, app=app, default_limits=["300 per hour"],
                      storage_uri="memory://")
    login_manager = LoginManager(app)
    login_manager.login_view = "login"
    login_manager.session_protection = "strong"
    state: dict = {"scorer": scorer}

    @login_manager.user_loader
    def load_user(user_id: str):
        return Admin(user_id) if hmac.compare_digest(user_id, settings.admin_username) else None

    def get_scorer():
        if state["scorer"] is None:
            from .scorer import Scorer

            try:
                state["scorer"] = Scorer(settings)
            except Exception:  # noqa: BLE001 - missing/invalid model: report, don't crash
                abort(503, "Models are not available. Run: python scripts/bootstrap.py")
        return state["scorer"]

    def audit_scan(kind: str, verdict, via: str) -> None:
        store.audit.append("web_scan", kind=kind, via=via, verdict=verdict.action,
                           score=None if verdict.score is None else round(verdict.score, 4))

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if not request.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.template_filter("pct")
    def pct(score: float) -> str:
        """Probability as a percentage that never claims certainty."""
        if score >= 0.999:
            return ">99.9%"
        if score <= 0.001:
            return "<0.1%"
        return f"{score * 100:.1f}%"

    @app.context_processor
    def inject():
        return {"logout_form": LogoutForm(), "mode": settings.mode}

    # ------------------------------------------------------------------ auth

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute;20 per hour", methods=["POST"])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            name_ok = hmac.compare_digest(form.username.data.encode(),
                                          settings.admin_username.encode())
            hashed = settings.admin_password_hash if name_ok else _DUMMY_HASH
            password_ok = check_password_hash(hashed, form.password.data)
            if name_ok and password_ok:
                login_user(Admin(settings.admin_username))
                store.audit.append("web_login", user=settings.admin_username,
                                   address=get_remote_address())
                target = request.args.get("next", "")
                return redirect(target if _is_local_path(target) else url_for("scan"))
            store.audit.append("web_login_failed", address=get_remote_address())
            flash("Wrong user name or password.")
        return render_template("login.html", form=form)

    @app.post("/logout")
    @login_required
    def logout():
        if LogoutForm().validate_on_submit():
            logout_user()
        return redirect(url_for("login"))

    # ------------------------------------------------------------------ scanning

    @app.route("/", methods=["GET", "POST"])
    @login_required
    def scan():
        email_form, sms_form = EmailForm(prefix="email"), SmsForm(prefix="sms")
        verdict = None
        if request.method == "POST":
            if "email-eml" in request.files and email_form.validate_on_submit():
                raw = email_form.eml.data.read(settings.max_email_bytes + 1)
                verdict = get_scorer().scan_email_bytes(raw)
                audit_scan("email", verdict, "web")
            elif "sms-text" in request.form and sms_form.validate_on_submit():
                verdict = get_scorer().scan_sms(sms_form.text.data, sms_form.sender.data or "")
                audit_scan("sms", verdict, "web")
            else:
                flash("Please choose an .eml file or enter an SMS text.")
        return render_template("scan.html", email_form=email_form, sms_form=sms_form,
                               verdict=verdict.to_dict() if verdict else None)

    # ------------------------------------------------------------------ dashboard

    @app.get("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", stats=dashboard_stats(store),
                               incidents=store.recent_reports(50),
                               quarantine=store.quarantined()[-50:][::-1],
                               settings=settings)

    @app.get("/incidents/<incident_id>")
    @login_required
    def incident(incident_id: str):
        if not valid_incident_id(incident_id):
            abort(404)
        try:
            report = store.load_report(incident_id)
        except KeyError:
            abort(404)
        record = None
        try:
            record = store.load_quarantine(incident_id)
        except (KeyError, ValueError):
            pass
        return render_template("incident.html", report=report, record=record)

    # ------------------------------------------------------------------ API

    def require_api_key() -> None:
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(
            token.strip().encode(), settings.api_key.encode()
        ):
            response = jsonify(error="missing or invalid API key")
            response.status_code = 401
            response.headers["WWW-Authenticate"] = 'Bearer realm="phishguard"'
            abort(response)

    @app.get("/api/v1/health")
    @csrf.exempt
    def health():
        return jsonify(status="ok")

    @app.post("/api/v1/scan/email")
    @csrf.exempt
    @limiter.limit("60 per minute")
    def api_scan_email():
        require_api_key()
        raw = request.get_data(cache=False)
        if not raw:
            return jsonify(error="send the raw .eml bytes as the request body"), 400
        verdict = get_scorer().scan_email_bytes(raw)
        audit_scan("email", verdict, "api")
        return jsonify(verdict.to_dict())

    @app.post("/api/v1/scan/sms")
    @csrf.exempt
    @limiter.limit("60 per minute")
    def api_scan_sms():
        require_api_key()
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get("text"), str):
            return jsonify(error='send JSON {"text": "...", "sender": "..."}'), 400
        sender = data.get("sender", "")
        if not isinstance(sender, str) or len(sender) > MAX_SENDER_CHARS:
            return jsonify(error=f"sender must be a string of at most {MAX_SENDER_CHARS} "
                                 "characters"), 400
        if not data["text"].strip() or len(data["text"]) > MAX_SMS_CHARS:
            return jsonify(error=f"text must be 1-{MAX_SMS_CHARS} characters"), 400
        verdict = get_scorer().scan_sms(data["text"], sender)
        audit_scan("sms", verdict, "api")
        return jsonify(verdict.to_dict())

    # ------------------------------------------------------------------ errors

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(413)
    @app.errorhandler(429)
    @app.errorhandler(500)
    @app.errorhandler(503)
    def error(exc):
        code = getattr(exc, "code", 500) or 500
        messages = {413: "Too large.", 429: "Too many requests, slow down.",
                    404: "Not found.", 503: getattr(exc, "description", "Unavailable.")}
        message = messages.get(code, "Request failed.")
        if request.path.startswith("/api/"):
            return jsonify(error=message), code
        return render_template("error.html", code=code, message=message), code

    app.extensions["phishguard_store"] = store
    return app


def main() -> int:
    import sys

    try:
        dotenv = ROOT / ".env"
        settings = load_settings(dotenv_path=dotenv if dotenv.exists() else None)
        app = create_app(settings)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    # Flask's development server, never in debug mode (the debugger runs arbitrary code).
    # For anything beyond your own machine, run behind a TLS reverse proxy.
    app.run(host=settings.web_host, port=settings.web_port, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
