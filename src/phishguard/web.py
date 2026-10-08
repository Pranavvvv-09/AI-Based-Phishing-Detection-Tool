"""FastAPI web app: scan page, quarantine dashboard with Restore, and a JSON API.

Run locally::

    python -m phishguard.web          # http://127.0.0.1:5000 (WEB_HOST / WEB_PORT)

Pages (login required)
----------------------
* ``/``                       scan an uploaded ``.eml`` or a pasted SMS
* ``/dashboard``              counts, quarantined mail with its top weighted reasons and a
                              **Restore** button, recent incidents, audit-log check
* ``/incidents/{id}``         one incident: every reason with its weight, and Restore

API
---
* ``POST /api/restore/{id}``  move a quarantined message back to the inbox over IMAP
                              (session + ``X-CSRF-Token`` header, or ``Bearer API_KEY``)
* ``GET  /api/quarantine``    the quarantine table as JSON (the dashboard refreshes from it)
* ``POST /api/v1/scan/email`` raw RFC 822 bytes; ``POST /api/v1/scan/sms`` JSON
  ``{"text", "sender"}`` (``Bearer API_KEY``)
* ``GET  /api/health``        liveness only

Security decisions
------------------
* **Fail closed:** refuses to start while FLASK_SECRET_KEY (also used for the session
  cookie), ADMIN_PASSWORD_HASH or API_KEY are missing, placeholders, or too short.
* **Restore is the only mailbox change**, and it is guarded: a logged-in session *and*
  a CSRF token (or the API key), 10 restores per minute, one restore per message at a
  time, every attempt in the audit log. It moves the message back (IMAP MOVE); nothing
  is ever deleted. The record is marked *before* the move so a poller running in
  another process can't re-quarantine the message.
* **Sessions:** signed cookie, HttpOnly, SameSite=Strict, Secure (WEB_COOKIE_SECURE),
  30 minutes idle, 12 hours absolute; cleared on login (no fixation) and logout.
* **Login:** werkzeug password hash, constant-time comparisons, a dummy hash for unknown
  user names, 5 attempts per minute and 20 per hour per address.
* **Browser hardening:** CSP allows only this app's own script and stylesheet (no inline
  code, so injected markup can't run), no framing, no referrer, no caching. The script
  builds table rows with ``textContent``, never ``innerHTML``.
* **Bounded input:** request bodies are capped at MAX_EMAIL_BYTES plus form overhead,
  SMS text at 5,000 characters. Message bodies are never stored or logged.
"""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections import Counter, deque
from pathlib import Path
from typing import Annotated
from urllib.parse import quote, urlsplit

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from werkzeug.security import check_password_hash, generate_password_hash

from .config import ConfigError, Settings, load_settings
from .incidents import IncidentStore, valid_incident_id
from .mailbox import Mailbox, MailboxError
from .scorer import MAX_SMS_CHARS
from .sms_checks import MAX_SENDER_CHARS

PACKAGE_DIR = Path(__file__).resolve().parent
ROOT = PACKAGE_DIR.parents[1]
FORM_OVERHEAD_BYTES = 64 * 1024
MIN_SECRET_KEY_CHARS = 32
SESSION_IDLE_SECONDS = 30 * 60
SESSION_ABSOLUTE_SECONDS = 12 * 3600
TOP_REASONS = 4
# A real hash of a random password: unknown user names cost the same time to reject.
_DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(16))

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
       "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")


# --------------------------------------------------------------------- helpers


class RateLimiter:
    """In-memory sliding-window limits, e.g. ``[(5, 60), (20, 3600)]`` per key."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limits: list[tuple[int, int]]) -> None:
        now = time.monotonic()
        window = max(seconds for _, seconds in limits)
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] > window:
                hits.popleft()
            for count, seconds in limits:
                if sum(1 for t in hits if now - t <= seconds) >= count:
                    raise HTTPException(429, "Too many requests, slow down.")
            hits.append(now)


class LoginRequired(Exception):
    pass


def check_web_secrets(settings: Settings) -> None:
    missing = [name for name in settings.missing_secrets() if name != "IMAP_APP_PASSWORD"]
    if missing:
        raise ConfigError(f"set {', '.join(missing)} in .env before starting the web app")
    if len(settings.flask_secret_key) < MIN_SECRET_KEY_CHARS:
        raise ConfigError(f"FLASK_SECRET_KEY must be at least {MIN_SECRET_KEY_CHARS} characters")
    if len(settings.api_key) < MIN_SECRET_KEY_CHARS:
        raise ConfigError(f"API_KEY must be at least {MIN_SECRET_KEY_CHARS} characters")
    if not settings.admin_password_hash.startswith(("scrypt:", "pbkdf2:")):
        raise ConfigError("ADMIN_PASSWORD_HASH must be a werkzeug password hash")


def is_local_path(target: str) -> bool:
    parts = urlsplit(target)
    return (not parts.scheme and not parts.netloc and target.startswith("/")
            and not target.startswith("//") and "\\" not in target)


def pct(score: float | None) -> str:
    """Probability as a percentage that never claims certainty."""
    if score is None:
        return "-"
    if score >= 0.999:
        return ">99.9%"
    if score <= 0.001:
        return "<0.1%"
    return f"{score * 100:.1f}%"


def when(timestamp: str | None) -> str:
    """``2026-10-08T16:16:46Z`` -> ``2026-10-08 16:16 UTC``."""
    return f"{timestamp.replace('T', ' ')[:16]} UTC" if timestamp else ""


def quarantine_rows(store: IncidentStore, limit: int = 200) -> list[dict]:
    """Quarantined messages, newest first, each with its top weighted reasons."""
    rows = []
    for record in sorted(store.quarantined(), key=lambda r: r.get("incident_id", ""),
                         reverse=True)[:limit]:
        reasons: list[dict] = []
        try:
            verdict = store.load_report(record["incident_id"]).get("verdict", {})
            reasons = [{k: r.get(k) for k in ("source", "code", "detail", "weight")}
                       for r in verdict.get("reasons", [])[:TOP_REASONS]]
        except (KeyError, OSError, ValueError):
            pass
        if record.get("restored_at"):
            status = "restored"
        elif record.get("restore_started_at"):
            status = "restoring"
        else:
            status = "held"
        rows.append({
            "incident_id": record["incident_id"],
            "quarantined_at": record.get("quarantined_at"),
            "from": record.get("from", ""),
            "subject": record.get("subject", ""),
            "score": record.get("score"),
            "score_text": pct(record.get("score")),
            "status": status,
            "restored_at": record.get("restored_at"),
            "restored_by": record.get("restored_by"),
            "reasons": reasons,
        })
    return rows


def dashboard_stats(store: IncidentStore) -> dict:
    entries = store.audit_tail()
    scanned = [e for e in entries if e.get("event") == "scanned"]
    actions = Counter(e.get("action_taken") for e in scanned)
    last_poll = next((e["ts"] for e in reversed(entries)
                      if e.get("event") in ("scanned", "cursor_reset")), None)
    ok, count, problem = store.audit.verify()
    records = store.quarantined()
    return {
        "scanned": len(scanned),
        "actions": {key: actions.get(key, 0) for key in
                    ("quarantined", "would_quarantine", "flagged_for_review", "delivered",
                     "quarantine_failed")},
        "web_scans": sum(e.get("event") == "web_scan" for e in entries),
        "errors": sum(e.get("event") in ("poll_error", "login_failed") for e in entries),
        "last_poll": last_poll,
        "audit": {"ok": ok, "entries": count, "problem": problem},
        "held": sum(not r.get("restored_at") for r in records),
        "restored": sum(bool(r.get("restored_at")) for r in records),
    }


class BodySizeLimit:
    """ASGI middleware: reject bodies over ``limit`` bytes, declared or streamed."""

    def __init__(self, app, limit: int) -> None:
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        declared = dict(scope.get("headers", [])).get(b"content-length")
        if declared and declared.isdigit() and int(declared) > self.limit:
            response = JSONResponse({"error": "Too large."}, status_code=413)
            return await response(scope, receive, send)
        seen = 0

        async def limited_receive():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.limit:
                    raise HTTPException(413, "Too large.")
            return message

        return await self.app(scope, limited_receive, send)


# ------------------------------------------------------------------------- app


def create_app(settings: Settings | None = None, scorer=None,
               store: IncidentStore | None = None, connect=None) -> FastAPI:
    """Build the app. ``connect`` (tests) replaces the real IMAP connection."""
    if settings is None:
        dotenv = ROOT / ".env"
        settings = load_settings(dotenv_path=dotenv if dotenv.exists() else None)
    check_web_secrets(settings)
    store = store or IncidentStore(ROOT / "reports", ROOT / "quarantine")
    limiter = RateLimiter()
    templates = Jinja2Templates(directory=str(PACKAGE_DIR / "templates"))
    templates.env.filters["pct"] = pct
    templates.env.filters["when"] = when
    state: dict = {"scorer": scorer, "poller": None}

    app = FastAPI(title="PhishGuard", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.settings, app.state.limiter = store, settings, limiter
    app.mount("/static", StaticFiles(directory=str(PACKAGE_DIR / "static")), name="static")

    # ------------------------------------------------------------- middleware

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # Added last = runs first: sessions must exist before the routes read them.
    app.add_middleware(SessionMiddleware, secret_key=settings.flask_secret_key,
                       session_cookie="phishguard_session", max_age=SESSION_IDLE_SECONDS,
                       same_site="strict", https_only=settings.web_cookie_secure)
    app.add_middleware(BodySizeLimit, limit=settings.max_email_bytes + FORM_OVERHEAD_BYTES)

    # ------------------------------------------------------------- auth helpers

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def csrf_token(request: Request) -> str:
        token = request.session.get("csrf")
        if not token:
            token = request.session["csrf"] = secrets.token_urlsafe(32)
        return token

    def csrf_ok(request: Request, supplied: str | None) -> bool:
        expected = request.session.get("csrf", "")
        return bool(expected and supplied) and hmac.compare_digest(supplied, expected)

    def session_user(request: Request) -> str | None:
        user, since = request.session.get("user"), request.session.get("login_at", 0)
        if not isinstance(user, str) or not hmac.compare_digest(user, settings.admin_username):
            return None
        if time.time() - since > SESSION_ABSOLUTE_SECONDS:
            request.session.clear()
            return None
        return user

    def require_page_login(request: Request) -> str:
        user = session_user(request)
        if user is None:
            raise LoginRequired
        return user

    def bearer_ok(request: Request) -> bool:
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        return scheme.lower() == "bearer" and hmac.compare_digest(
            token.strip().encode(), settings.api_key.encode())

    def require_api_key(request: Request) -> None:
        if not bearer_ok(request):
            raise HTTPException(401, "missing or invalid API key",
                                headers={"WWW-Authenticate": 'Bearer realm="phishguard"'})

    def require_reader(request: Request) -> str:
        """Session or API key (read-only API)."""
        if bearer_ok(request):
            return "api"
        user = session_user(request)
        if user is None:
            raise HTTPException(401, "log in or send the API key")
        return user

    def require_writer(request: Request) -> str:
        """API key, or a session *plus* its CSRF token (state-changing API)."""
        if bearer_ok(request):
            return "api"
        user = session_user(request)
        if user is None:
            raise HTTPException(401, "log in or send the API key")
        if not csrf_ok(request, request.headers.get("x-csrf-token")):
            raise HTTPException(403, "missing or invalid CSRF token")
        return user

    def page(request: Request, name: str, status: int = 200, **context) -> HTMLResponse:
        context.update(user=session_user(request), csrf=csrf_token(request),
                       mode=settings.mode)
        return templates.TemplateResponse(request, name, context, status_code=status)

    def get_scorer():
        if state["scorer"] is None:
            from .scorer import Scorer

            try:
                state["scorer"] = Scorer(settings)
            except Exception:  # noqa: BLE001 - missing/invalid model: report, don't crash
                raise HTTPException(
                    503, "Models are not available. Run: python scripts/bootstrap.py"
                ) from None
        return state["scorer"]

    def get_poller():
        if state["poller"] is None:
            if not settings.imap_user or "IMAP_APP_PASSWORD" in settings.missing_secrets():
                raise HTTPException(503, "Restore needs IMAP_USER and IMAP_APP_PASSWORD "
                                         "in .env")
            from .poller import Poller

            def real_connect() -> Mailbox:
                return Mailbox.connect(settings.imap_host, settings.imap_user,
                                       settings.imap_app_password)

            state["poller"] = Poller(settings, store, connect or real_connect)
        return state["poller"]

    def audit_scan(kind: str, verdict, via: str) -> None:
        store.audit.append("web_scan", kind=kind, via=via, verdict=verdict.action,
                           score=None if verdict.score is None else round(verdict.score, 4))

    # ------------------------------------------------------------- errors

    @app.exception_handler(LoginRequired)
    async def to_login(request: Request, exc: LoginRequired):
        return RedirectResponse(f"/login?next={quote(request.url.path)}", status_code=303)

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        message = exc.detail if isinstance(exc.detail, str) else "Request failed."
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": message}, status_code=exc.status_code,
                                headers=exc.headers)
        return page(request, "error.html", status=exc.status_code, code=exc.status_code,
                    message=message)

    @app.exception_handler(RequestValidationError)
    async def bad_request(request: Request, exc: RequestValidationError):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": "invalid request"}, status_code=400)
        return page(request, "error.html", status=400, code=400, message="Invalid request.")

    # ------------------------------------------------------------- login

    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request, next: str = ""):  # noqa: A002 - query parameter name
        return page(request, "login.html", next=next if is_local_path(next) else "")

    @app.post("/login")
    def login(request: Request, username: Annotated[str, Form(max_length=100)],
              password: Annotated[str, Form(max_length=200)],
              csrf: Annotated[str, Form(alias="csrf_token")] = "",
              next: Annotated[str, Form()] = ""):  # noqa: A002
        limiter.hit(f"login:{client_ip(request)}", [(5, 60), (20, 3600)])
        if not csrf_ok(request, csrf):
            raise HTTPException(400, "Your form expired, please try again.")
        name_ok = hmac.compare_digest(username.encode(), settings.admin_username.encode())
        hashed = settings.admin_password_hash if name_ok else _DUMMY_HASH
        if check_password_hash(hashed, password) and name_ok:
            request.session.clear()  # new session on login: no fixation
            request.session.update(user=settings.admin_username, login_at=time.time(),
                                   csrf=secrets.token_urlsafe(32))
            store.audit.append("web_login", user=settings.admin_username,
                               address=client_ip(request))
            return RedirectResponse(next if is_local_path(next) else "/", status_code=303)
        store.audit.append("web_login_failed", address=client_ip(request))
        return page(request, "login.html", status=401, error="Wrong user name or password.",
                    next=next if is_local_path(next) else "")

    @app.post("/logout")
    def logout(request: Request, csrf: Annotated[str, Form(alias="csrf_token")] = ""):
        if not csrf_ok(request, csrf):
            raise HTTPException(400, "Your form expired, please try again.")
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    # ------------------------------------------------------------- scanning

    @app.get("/", response_class=HTMLResponse)
    def scan_page(request: Request):
        require_page_login(request)
        return page(request, "scan.html")

    @app.post("/scan/email", response_class=HTMLResponse)
    def scan_email(request: Request, eml: Annotated[UploadFile, File()],
                   csrf: Annotated[str, Form(alias="csrf_token")] = ""):
        require_page_login(request)
        if not csrf_ok(request, csrf):
            raise HTTPException(400, "Your form expired, please try again.")
        raw = eml.file.read(settings.max_email_bytes + 1)
        if not raw:
            return page(request, "scan.html", status=400, error="That file is empty.")
        verdict = get_scorer().scan_email_bytes(raw)
        audit_scan("email", verdict, "web")
        return page(request, "scan.html", verdict=verdict.to_dict())

    @app.post("/scan/sms", response_class=HTMLResponse)
    def scan_sms(request: Request, text: Annotated[str, Form(max_length=MAX_SMS_CHARS)],
                 sender: Annotated[str, Form(max_length=MAX_SENDER_CHARS)] = "",
                 csrf: Annotated[str, Form(alias="csrf_token")] = ""):
        require_page_login(request)
        if not csrf_ok(request, csrf):
            raise HTTPException(400, "Your form expired, please try again.")
        if not text.strip():
            return page(request, "scan.html", status=400, error="Enter the SMS text.")
        verdict = get_scorer().scan_sms(text, sender)
        audit_scan("sms", verdict, "web")
        return page(request, "scan.html", verdict=verdict.to_dict(), sms_text=text,
                    sms_sender=sender)

    # ------------------------------------------------------------- dashboard

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard(request: Request):
        require_page_login(request)
        return page(request, "dashboard.html", stats=dashboard_stats(store),
                    rows=quarantine_rows(store), incidents=store.recent_reports(50),
                    settings=settings)

    @app.get("/incidents/{incident_id}", response_class=HTMLResponse)
    def incident(request: Request, incident_id: str):
        require_page_login(request)
        if not valid_incident_id(incident_id):
            raise HTTPException(404, "Not found.")
        try:
            report = store.load_report(incident_id)
        except KeyError:
            raise HTTPException(404, "Not found.") from None
        try:
            record = store.load_quarantine(incident_id)
        except (KeyError, ValueError):
            record = None
        return page(request, "incident.html", report=report, record=record)

    # ------------------------------------------------------------- quarantine API

    @app.get("/api/quarantine")
    def api_quarantine(request: Request):
        require_reader(request)
        stats = dashboard_stats(store)
        return {"rows": quarantine_rows(store),
                "stats": {"held": stats["held"], "restored": stats["restored"],
                          "quarantined": stats["actions"]["quarantined"],
                          "scanned": stats["scanned"]}}

    @app.post("/api/restore/{incident_id}")
    def api_restore(request: Request, incident_id: str):
        from .poller import AlreadyRestored, RestoreInProgress

        actor = require_writer(request)
        limiter.hit(f"restore:{client_ip(request)}", [(10, 60)])
        if not valid_incident_id(incident_id):
            raise HTTPException(404, "No such incident.")
        poller = get_poller()
        try:
            record = poller.restore(incident_id, actor=f"web:{actor}@{client_ip(request)}")
        except KeyError:
            raise HTTPException(404, "No such quarantined message.") from None
        except AlreadyRestored as exc:
            raise HTTPException(409, str(exc)) from None
        except RestoreInProgress as exc:
            raise HTTPException(409, str(exc)) from None
        except MailboxError as exc:  # our own messages: no secrets, no server text
            raise HTTPException(502, f"Mail server: {exc}") from None
        except OSError as exc:
            raise HTTPException(502, f"Mail server unreachable ({type(exc).__name__})") \
                from None
        return {"incident_id": incident_id, "status": "restored",
                "restored_at": record["restored_at"], "restored_by": record["restored_by"],
                "to_folder": record["source_folder"]}

    # ------------------------------------------------------------- scan API

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.post("/api/v1/scan/email")
    async def api_scan_email(request: Request):
        require_api_key(request)
        limiter.hit(f"api:{client_ip(request)}", [(60, 60)])
        raw = await request.body()
        if not raw:
            raise HTTPException(400, "send the raw .eml bytes as the request body")
        verdict = get_scorer().scan_email_bytes(raw)
        audit_scan("email", verdict, "api")
        return verdict.to_dict()

    @app.post("/api/v1/scan/sms")
    async def api_scan_sms(request: Request):
        require_api_key(request)
        limiter.hit(f"api:{client_ip(request)}", [(60, 60)])
        try:
            data = await request.json()
        except ValueError:
            data = None
        if not isinstance(data, dict) or not isinstance(data.get("text"), str):
            raise HTTPException(400, 'send JSON {"text": "...", "sender": "..."}')
        sender = data.get("sender", "")
        if not isinstance(sender, str) or len(sender) > MAX_SENDER_CHARS:
            raise HTTPException(400, f"sender must be a string of at most {MAX_SENDER_CHARS} "
                                     "characters")
        if not data["text"].strip() or len(data["text"]) > MAX_SMS_CHARS:
            raise HTTPException(400, f"text must be 1-{MAX_SMS_CHARS} characters")
        verdict = get_scorer().scan_sms(data["text"], sender)
        audit_scan("sms", verdict, "api")
        return verdict.to_dict()

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon():
        return Response(status_code=204)

    return app


def main() -> int:
    import sys

    import uvicorn

    try:
        dotenv = ROOT / ".env"
        settings = load_settings(dotenv_path=dotenv if dotenv.exists() else None)
        app = create_app(settings)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    # Plain HTTP on localhost. For anything beyond your own machine, run behind a TLS
    # reverse proxy (and keep WEB_COOKIE_SECURE=true).
    uvicorn.run(app, host=settings.web_host, port=settings.web_port, server_header=False,
                proxy_headers=False, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
