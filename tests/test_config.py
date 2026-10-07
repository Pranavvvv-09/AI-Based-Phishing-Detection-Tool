from pathlib import Path

import pytest

from phishguard.config import ConfigError, load_settings

ROOT = Path(__file__).resolve().parent.parent


def test_defaults_are_safe():
    s = load_settings({})
    assert s.mode == "monitor"  # never quarantine unless explicitly enabled
    assert s.intel_enabled is False  # no third-party lookups by default
    assert s.quarantine_threshold == 0.8


def test_secrets_not_in_repr():
    s = load_settings({"API_KEY": "super-secret-key", "IMAP_APP_PASSWORD": "pw-1234"})
    text = repr(s)
    assert "super-secret-key" not in text
    assert "pw-1234" not in text


def test_placeholder_secrets_reported_missing():
    s = load_settings({"API_KEY": "change-me", "FLASK_SECRET_KEY": "x" * 32})
    missing = s.missing_secrets()
    assert "API_KEY" in missing
    assert "IMAP_APP_PASSWORD" in missing
    assert "FLASK_SECRET_KEY" not in missing


@pytest.mark.parametrize(
    "env",
    [
        {"MODE": "delete"},
        {"QUARANTINE_THRESHOLD": "0.1"},
        {"QUARANTINE_THRESHOLD": "abc"},
        {"IMAP_POLL_SECONDS": "5"},
        {"MAX_EMAIL_BYTES": "999999999999"},
        {"INTEL_ENABLED": "maybe"},
        {"IMAP_QUARANTINE_FOLDER": 'Quarantine" DELETE'},
    ],
)
def test_invalid_values_fail_closed(env):
    with pytest.raises(ConfigError):
        load_settings(env)


def test_env_example_is_loadable_and_has_only_placeholders():
    example = ROOT / ".env.example"
    env = {}
    for line in example.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            env[key] = value
    s = load_settings(env)
    assert set(s.missing_secrets()) == {
        "IMAP_APP_PASSWORD",
        "API_KEY",
        "FLASK_SECRET_KEY",
        "ADMIN_PASSWORD_HASH",
    }
