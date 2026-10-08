"""PhishGuard web console: dashboard with Restore, and Quick Scan.

One command runs everything::

    python -m phishguard.web          # http://127.0.0.1:5000 (WEB_HOST / WEB_PORT)

It starts the web server **and** the mailbox poller (a background thread) when
IMAP_USER and IMAP_APP_PASSWORD are set in ``.env``.

Pages (login required)
----------------------
* ``/``          Dashboard: KPI cards, and the quarantine table with colour-coded
                 explanation chips and a Restore button per message.
* ``/scan``      Quick Scan: paste an email or SMS (or upload an ``.eml``) and see why.

The browser side uses **htmx** (a small vendored script): Restore posts to
``/api/restore/{id}`` and swaps in the updated table row; the KPI cards reload when
the server signals ``kpis-changed``; the table refreshes itself every 30 seconds.

Security, kept deliberately simple
----------------------------------
* One login from ``.env`` (ADMIN_USERNAME + ADMIN_PASSWORD_HASH, a werkzeug hash).
  The app refuses to start with a missing or weak FLASK_SECRET_KEY / password hash.
* Signed session cookie (HttpOnly, SameSite=Strict, Secure unless WEB_COOKIE_SECURE=false),
  30 minutes idle; every POST carries a CSRF token; 5 login attempts per minute.
* Restore is the only action that changes the mailbox: it *moves* the message back to
  the inbox (IMAP MOVE, nothing is deleted), at most 10 per minute, and every attempt
  is written to the hash-chained audit log.
* Strict Content-Security-Policy: only this app's own script and stylesheet may load,
  no inline code. Message text is HTML-escaped by Jinja everywhere.
"""

from __future__ import annotations

import hmac
import re
import secrets
import threading
import time
from collections import Counter, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated
from urllib.parse import quote, urlsplit

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
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
MAX_PASTE_CHARS = 200_000
MIN_SECRET_KEY_CHARS = 32
SESSION_IDLE_SECONDS = 30 * 60
# A real hash of a random password: an unknown user name takes as long to reject.
_DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(16))
# Pasted text that starts with mail headers ("From: ...", "Received: ...") is a raw email.
_LOOKS_LIKE_HEADERS = re.compile(r"\A(?:[A-Za-z][A-Za-z0-9-]{0,40}:[^\n]*\r?\n){2,}")

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
       "font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
       "base-uri 'none'")
# The React dashboard, built by `npm run build` in frontend/ (committed, so Python alone runs it).
DASHBOARD_HTML = PACKAGE_DIR / "static" / "app" / "index.html"


# ------------------------------------------------------------------------ helpers


def check_web_secrets(settings: Settings) -> None:
    """Fail closed: never start with placeholder or weak secrets."""
    missing = [name for name in settings.missing_secrets()
               if name in ("FLASK_SECRET_KEY", "ADMIN_PASSWORD_HASH")]
    if missing:
        raise ConfigError(f"set {', '.join(missing)} in .env before starting the web app")
    if len(settings.flask_secret_key) < MIN_SECRET_KEY_CHARS:
        raise ConfigError(f"FLASK_SECRET_KEY must be at least {MIN_SECRET_KEY_CHARS} characters")
    if not settings.admin_password_hash.startswith(("scrypt:", "pbkdf2:")):
        raise ConfigError("ADMIN_PASSWORD_HASH must be a werkzeug password hash")


def mailbox_configured(settings: Settings) -> bool:
    return bool(settings.imap_user) and "IMAP_APP_PASSWORD" not in settings.missing_secrets()


def is_local_path(target: str) -> bool:
    """Only redirect to paths on this site (no //evil.test, no https://...)."""
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


def chip_class(weight: float) -> str:
    """Colour by direction (red = towards phishing), fill by strength (as Reason.strength)."""
    direction = "up" if weight > 0 else "down"
    size = abs(weight)
    strength = "strong" if size >= 2 else "medium" if size >= 1 else "weak"
    return f"chip {direction} {strength}"


def quarantine_rows(store: IncidentStore, limit: int = 200) -> list[dict]:
    """Quarantined messages, newest first, each with its explanation (reasons)."""
    rows = []
    records = sorted(store.quarantined(), key=lambda r: r.get("incident_id", ""), reverse=True)
    for record in records[:limit]:
        reasons: list[dict] = []
        kind = "email"  # the mailbox poller only quarantines email today
        try:
            verdict = store.load_report(record["incident_id"]).get("verdict", {})
            kind = verdict.get("kind") or kind
            reasons = [{k: r.get(k) for k in ("source", "code", "detail", "weight")}
                       for r in verdict.get("reasons", [])]
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
            "status": status,
            "restored_at": record.get("restored_at"),
            "restored_by": record.get("restored_by"),
            "kind": kind,
            "reasons": reasons,
        })
    return rows


def kpis(store: IncidentStore) -> dict:
    """The three dashboard numbers (plus how many are still held)."""
    scanned = Counter(e.get("action_taken") for e in store.audit_tail()
                      if e.get("event") == "scanned")
    records = store.quarantined()
    return {
        "scanned": sum(scanned.values()),
        "quarantined": len(records),
        "restored": sum(bool(r.get("restored_at")) for r in records),
        "held": sum(not r.get("restored_at") for r in records),
    }


class RateLimiter:
    """In-memory sliding window, e.g. ``hit("login:1.2.3.4", 5, 60)``."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, count: int, seconds: int) -> None:
        now = time.monotonic()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] > seconds:
                hits.popleft()
            if len(hits) >= count:
                raise HTTPException(429, "Too many requests, please wait a minute.")
            hits.append(now)


class BodySizeLimit:
    """ASGI middleware: reject request bodies larger than ``limit`` bytes."""

    def __init__(self, app, limit: int) -> None:
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        declared = dict(scope.get("headers", [])).get(b"content-length")
        if declared and declared.isdigit() and int(declared) > self.limit:
            return await JSONResponse({"error": "Too large."}, 413)(scope, receive, send)
        seen = 0

        async def limited_receive():
            nonlocal seen
            message = await receive()
            seen += len(message.get("body", b""))
            if seen > self.limit:
                raise HTTPException(413, "Too large.")
            return message

        return await self.app(scope, limited_receive, send)


class LoginRequired(Exception):
    pass


# ------------------------------------------------------------------------- app


def create_app(settings: Settings | None = None, scorer=None,
               store: IncidentStore | None = None, connect=None) -> FastAPI:
    """Build the app. ``scorer``, ``store`` and ``connect`` are replaceable for tests."""
    if settings is None:
        dotenv = ROOT / ".env"
        settings = load_settings(dotenv_path=dotenv if dotenv.exists() else None)
    check_web_secrets(settings)
    store = store or IncidentStore(ROOT / "reports", ROOT / "quarantine")
    limiter = RateLimiter()
    templates = Jinja2Templates(directory=str(PACKAGE_DIR / "templates"))
    templates.env.filters.update(pct=pct, when=when, chip=chip_class)
    state: dict = {"scorer": scorer, "poller": None, "background": None}

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
            if not mailbox_configured(settings):
                raise HTTPException(503, "Set IMAP_USER and IMAP_APP_PASSWORD in .env to "
                                         "connect your mailbox.")
            from .poller import Poller

            def real_connect() -> Mailbox:
                return Mailbox.connect(settings.imap_host, settings.imap_user,
                                       settings.imap_app_password)

            state["poller"] = Poller(settings, store, connect or real_connect,
                                     scorer=state["scorer"])
        return state["poller"]

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Start the mailbox poller next to the web server (one command runs both).
        if mailbox_configured(settings):
            get_scorer()  # load the models once; the poller and Quick Scan share them
            get_poller()._scorer = state["scorer"]
            from .poller import BackgroundPoller

            state["background"] = BackgroundPoller(state["poller"])
            state["background"].start()
        yield
        if state["background"] is not None:
            state["background"].shutdown()

    app = FastAPI(title="PhishGuard", docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
    app.state.store, app.state.settings, app.state.app_state = store, settings, state
    app.mount("/static", StaticFiles(directory=str(PACKAGE_DIR / "static")), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    app.add_middleware(SessionMiddleware, secret_key=settings.flask_secret_key,
                       session_cookie="phishguard_session", max_age=SESSION_IDLE_SECONDS,
                       same_site="strict", https_only=settings.web_cookie_secure)
    app.add_middleware(BodySizeLimit, limit=settings.max_email_bytes + FORM_OVERHEAD_BYTES)

    # ------------------------------------------------------------- auth helpers

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def is_htmx(request: Request) -> bool:
        return request.headers.get("hx-request") == "true"

    def csrf_token(request: Request) -> str:
        if "csrf" not in request.session:
            request.session["csrf"] = secrets.token_urlsafe(32)
        return request.session["csrf"]

    def csrf_ok(request: Request, supplied: str | None) -> bool:
        expected = request.session.get("csrf", "")
        return bool(expected and supplied) and hmac.compare_digest(supplied, expected)

    def logged_in(request: Request) -> bool:
        user = request.session.get("user")
        return isinstance(user, str) and hmac.compare_digest(user, settings.admin_username)

    def require_login(request: Request) -> None:
        if not logged_in(request):
            raise LoginRequired

    def poller_status() -> dict:
        background = state["background"]
        poller = state["poller"]
        status = {"mailbox": settings.imap_user, "last_poll_at": None, "error": ""}
        if not mailbox_configured(settings):
            return {**status, "state": "off", "text": "Mailbox not connected (set IMAP_USER "
                                                      "and IMAP_APP_PASSWORD in .env)"}
        last = getattr(poller, "last_poll_at", None)
        error = getattr(poller, "last_error", "")
        status.update(last_poll_at=last, error=error)
        if background is None or not background.running:
            return {**status, "state": "error", "text": f"Poller stopped: {error or 'stopped'}"}
        text = f"Watching {settings.imap_user}. Last check {when(last) or 'starting…'}"
        return {**status, "state": "warn" if error else "ok",
                "text": f"{text}. {error}" if error else text}

    def render(request: Request, name: str, status: int = 200, **context) -> HTMLResponse:
        context.update(logged_in=logged_in(request), csrf=csrf_token(request),
                       mode=settings.mode)
        return templates.TemplateResponse(request, name, context, status_code=status)

    # ------------------------------------------------------------- errors

    @app.exception_handler(LoginRequired)
    async def to_login(request: Request, exc: LoginRequired):
        if is_htmx(request):  # htmx follows HX-Redirect with a full page load
            return Response(status_code=401, headers={"HX-Redirect": "/login"})
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": "log in first"}, status_code=401)
        return RedirectResponse(f"/login?next={quote(request.url.path)}", status_code=303)

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        message = exc.detail if isinstance(exc.detail, str) else "Request failed."
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": message}, status_code=exc.status_code)
        if is_htmx(request):
            return render(request, "_message.html", status=exc.status_code, message=message)
        return render(request, "error.html", status=exc.status_code, code=exc.status_code,
                      message=message)

    # ------------------------------------------------------------- login

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request, next: str = ""):  # noqa: A002 - query parameter
        return render(request, "login.html", next=next if is_local_path(next) else "")

    @app.post("/login")
    def login(request: Request, username: Annotated[str, Form(max_length=100)],
              password: Annotated[str, Form(max_length=200)],
              csrf: Annotated[str, Form(alias="csrf_token")] = "",
              next: Annotated[str, Form()] = ""):  # noqa: A002
        limiter.hit(f"login:{client_ip(request)}", 5, 60)
        if not csrf_ok(request, csrf):
            raise HTTPException(400, "Your form expired, please try again.")
        name_ok = hmac.compare_digest(username.encode(), settings.admin_username.encode())
        password_ok = check_password_hash(
            settings.admin_password_hash if name_ok else _DUMMY_HASH, password)
        if name_ok and password_ok:
            request.session.clear()  # fresh session on login
            request.session.update(user=settings.admin_username,
                                   csrf=secrets.token_urlsafe(32))
            store.audit.append("web_login", user=settings.admin_username,
                               address=client_ip(request))
            return RedirectResponse(next if is_local_path(next) else "/", status_code=303)
        store.audit.append("web_login_failed", address=client_ip(request))
        return render(request, "login.html", status=401, next=next if is_local_path(next) else "",
                      error="Wrong user name or password.")

    @app.post("/logout")
    def logout(request: Request, csrf: Annotated[str, Form(alias="csrf_token")] = ""):
        if not csrf_ok(request, csrf):
            raise HTTPException(400, "Your form expired, please try again.")
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    # ------------------------------------------------------------- dashboard

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        """The React dashboard (frontend/). It loads its data from the JSON API below."""
        require_login(request)
        if not DASHBOARD_HTML.exists():
            raise HTTPException(503, "Dashboard not built. Run: cd frontend && npm ci && "
                                     "npm run build")
        return HTMLResponse(DASHBOARD_HTML.read_text(encoding="utf-8"))

    # ------------------------------------------------------------- quick scan

    @app.get("/scan", response_class=HTMLResponse)
    def scan_page(request: Request):
        require_login(request)
        return render(request, "scan.html", tab="scan")

    @app.post("/scan", response_class=HTMLResponse)
    def scan(request: Request,
             kind: Annotated[str, Form(pattern="^(email|sms)$")] = "email",
             text: Annotated[str, Form(max_length=MAX_PASTE_CHARS)] = "",
             sender: Annotated[str, Form(max_length=MAX_SENDER_CHARS)] = "",
             eml: Annotated[UploadFile | None, File()] = None,
             csrf: Annotated[str, Form(alias="csrf_token")] = ""):
        require_login(request)
        if not csrf_ok(request, csrf):
            raise HTTPException(400, "Your form expired, please reload the page.")
        raw = eml.file.read(settings.max_email_bytes + 1) if eml and eml.filename else b""
        if raw:
            verdict = get_scorer().scan_email_bytes(raw)
        elif not text.strip():
            raise HTTPException(400, "Paste a message or choose an .eml file.")
        elif kind == "sms":
            if len(text) > MAX_SMS_CHARS:
                raise HTTPException(400, f"An SMS can be at most {MAX_SMS_CHARS} characters.")
            verdict = get_scorer().scan_sms(text, sender)
        elif _LOOKS_LIKE_HEADERS.match(text):
            verdict = get_scorer().scan_email_bytes(text.encode("utf-8", "replace"))
        else:
            verdict = get_scorer().scan_text(text, kind="email")
        store.audit.append("web_scan", kind=verdict.kind, verdict=verdict.action,
                           score=None if verdict.score is None else round(verdict.score, 4))
        data = verdict.to_dict()
        page = "_verdict.html" if is_htmx(request) else "scan.html"
        return render(request, page, tab="scan", verdict=data)

    # ------------------------------------------------------------- restore API

    @app.post("/api/restore/{incident_id}")
    def restore(request: Request, incident_id: str):
        """Move a quarantined message back to the inbox (real IMAP MOVE).

        Needs the session cookie and the CSRF token in the ``X-CSRF-Token`` header
        (the dashboard gets it from ``/api/session``).
        """
        from .poller import AlreadyRestored, RestoreInProgress

        require_login(request)
        if not csrf_ok(request, request.headers.get("x-csrf-token")):
            raise HTTPException(403, "Missing or invalid CSRF token, please reload the page.")
        limiter.hit(f"restore:{client_ip(request)}", 10, 60)

        error, status = "", 200
        try:
            if not valid_incident_id(incident_id):
                raise KeyError(incident_id)
            record = get_poller().restore(incident_id,
                                          actor=f"web:{settings.admin_username}")
        except KeyError:
            error, status = "No such quarantined message.", 404
        except (AlreadyRestored, RestoreInProgress) as exc:
            error, status = str(exc), 409
        except MailboxError as exc:  # our own messages: no secrets, no server text
            error, status = f"Mail server: {exc}", 502
        except OSError as exc:
            error, status = f"Mail server unreachable ({type(exc).__name__})", 502

        if error:
            return JSONResponse({"error": error}, status_code=status)
        return {"incident_id": incident_id, "status": "restored",
                "restored_at": record["restored_at"],
                "restored_by": record["restored_by"], "to_folder": record["source_folder"]}

    @app.get("/api/session")
    def api_session(request: Request):
        """What the dashboard needs to start: who is logged in, the CSRF token for
        POST requests, the mode, and whether the mailbox poller is running."""
        require_login(request)
        return {"user": settings.admin_username, "csrf": csrf_token(request),
                "mode": settings.mode, "threshold": settings.quarantine_threshold,
                "poller": poller_status()}

    @app.get("/api/quarantine")
    def api_quarantine(request: Request):
        require_login(request)
        return {"rows": quarantine_rows(store), "kpis": kpis(store)}

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon():
        return RedirectResponse("/static/favicon.svg", status_code=301)

    return app


def main() -> int:
    import logging
    import sys

    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        dotenv = ROOT / ".env"
        settings = load_settings(dotenv_path=dotenv if dotenv.exists() else None)
        app = create_app(settings)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"PhishGuard: open http://{settings.web_host}:{settings.web_port}")
    uvicorn.run(app, host=settings.web_host, port=settings.web_port, server_header=False,
                proxy_headers=False, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
