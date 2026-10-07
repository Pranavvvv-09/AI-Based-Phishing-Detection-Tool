"""Repository-wide safety checks."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Invisible and bidirectional control characters ("Trojan Source", CWE-838): they make
# code or data display differently than it reads. Use \u escapes in source instead.
INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
CHECKED = {".py", ".md", ".toml", ".yaml", ".yml", ".csv", ".json", ".eml", ".txt", ".cfg"}
SKIP = {".venv", ".git", "raw", "processed", "__pycache__", ".ruff_cache", ".pytest_cache"}


def test_no_raw_invisible_or_bidi_characters_in_repo():
    offenders = []
    for path in ROOT.rglob("*"):
        if path.suffix not in CHECKED or not path.is_file():
            continue
        if SKIP & set(path.relative_to(ROOT).parts):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if INVISIBLE.search(text):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == [], f"raw invisible/bidi characters in: {offenders}"
