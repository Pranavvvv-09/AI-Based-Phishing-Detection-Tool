"""Load and validate PhishGuard settings from environment variables.

Secrets are read from the environment (optionally populated from a local ``.env``
file) and are excluded from ``repr`` so they never end up in logs or tracebacks.
Invalid values raise ``ConfigError`` so the app fails closed instead of running
with an unsafe configuration.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

PLACEHOLDER = "change-me"
VALID_MODES = ("monitor", "quarantine")
MAX_EMAIL_BYTES_LIMIT = 25 * 1024 * 1024  # hard ceiling: 25 MB, Gmail's own limit


class ConfigError(ValueError):
    """Raised when a setting is missing or invalid."""


@dataclass(frozen=True)
class Settings:
    imap_host: str
    imap_user: str
    imap_quarantine_folder: str
    imap_poll_seconds: int
    mode: str
    quarantine_threshold: float
    max_email_bytes: int
    admin_username: str
    intel_enabled: bool
    trusted_authserv_id: str
    extra_brands_file: str
    web_host: str
    web_port: int
    web_cookie_secure: bool
    # Secrets: hidden from repr() so printing settings never leaks them.
    imap_app_password: str = field(repr=False)
    api_key: str = field(repr=False)
    flask_secret_key: str = field(repr=False)
    admin_password_hash: str = field(repr=False)

    def missing_secrets(self) -> list[str]:
        """Names of secrets that are empty or still set to the template placeholder."""
        secrets = {
            "IMAP_APP_PASSWORD": self.imap_app_password,
            "API_KEY": self.api_key,
            "FLASK_SECRET_KEY": self.flask_secret_key,
            "ADMIN_PASSWORD_HASH": self.admin_password_hash,
        }
        return [name for name, value in secrets.items() if not value or value == PLACEHOLDER]


def _int(env: Mapping[str, str], name: str, default: int, lo: int, hi: int) -> int:
    raw = env.get(name, str(default))
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer") from None
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}")
    return value


def _float(env: Mapping[str, str], name: str, default: float, lo: float, hi: float) -> float:
    raw = env.get(name, str(default))
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a number") from None
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}")
    return value


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name, str(default)).strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name} must be true or false")


def load_settings(
    env: Mapping[str, str] | None = None, dotenv_path: Path | None = None
) -> Settings:
    """Build validated settings.

    ``env`` defaults to ``os.environ``. When ``dotenv_path`` is given, values from that
    file are loaded first without overriding variables already set in the environment.
    """
    if env is None:
        if dotenv_path is not None:
            from dotenv import load_dotenv

            load_dotenv(dotenv_path, override=False)
        env = os.environ

    mode = env.get("MODE", "monitor").strip().lower()
    if mode not in VALID_MODES:
        raise ConfigError(f"MODE must be one of {VALID_MODES}")

    folder = env.get("IMAP_QUARANTINE_FOLDER", "PhishGuard-Quarantine").strip()
    # Folder names go into IMAP commands; restrict them to a safe character set.
    if not folder or not all(c.isalnum() or c in "-_/" for c in folder):
        raise ConfigError("IMAP_QUARANTINE_FOLDER may only contain letters, digits, - _ /")

    authserv = env.get("TRUSTED_AUTHSERV_ID", "mx.google.com").strip().lower()
    if not authserv or not all(c.isalnum() or c in ".-" for c in authserv):
        raise ConfigError("TRUSTED_AUTHSERV_ID must be a hostname such as mx.google.com")

    web_host = env.get("WEB_HOST", "127.0.0.1").strip()
    if not web_host or not all(c.isalnum() or c in ".:-" for c in web_host):
        raise ConfigError("WEB_HOST must be a hostname or IP address")

    return Settings(
        imap_host=env.get("IMAP_HOST", "imap.gmail.com").strip(),
        imap_user=env.get("IMAP_USER", "").strip(),
        imap_quarantine_folder=folder,
        # Minimum 30 s keeps us well inside provider rate limits.
        imap_poll_seconds=_int(env, "IMAP_POLL_SECONDS", 60, 30, 3600),
        mode=mode,
        quarantine_threshold=_float(env, "QUARANTINE_THRESHOLD", 0.8, 0.5, 1.0),
        max_email_bytes=_int(env, "MAX_EMAIL_BYTES", 5 * 1024 * 1024, 1024, MAX_EMAIL_BYTES_LIMIT),
        admin_username=env.get("ADMIN_USERNAME", "admin").strip(),
        intel_enabled=_bool(env, "INTEL_ENABLED", False),
        trusted_authserv_id=authserv,
        extra_brands_file=env.get("EXTRA_BRANDS_FILE", "").strip(),
        web_host=web_host,
        web_port=_int(env, "WEB_PORT", 5000, 1024, 65535),
        # Browsers treat http://localhost as secure, so Secure cookies work locally too.
        web_cookie_secure=_bool(env, "WEB_COOKIE_SECURE", True),
        imap_app_password=env.get("IMAP_APP_PASSWORD", ""),
        api_key=env.get("API_KEY", ""),
        flask_secret_key=env.get("FLASK_SECRET_KEY", ""),
        admin_password_hash=env.get("ADMIN_PASSWORD_HASH", ""),
    )
