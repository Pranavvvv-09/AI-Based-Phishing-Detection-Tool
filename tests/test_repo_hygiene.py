"""Repository-wide safety checks."""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Invisible and bidirectional control characters ("Trojan Source", CWE-838): they make
# code or data display differently than it reads. Use \u escapes in source instead.
INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
CHECKED = {".py", ".md", ".toml", ".yaml", ".yml", ".csv", ".json", ".eml", ".txt", ".cfg"}
SKIP = {".venv", ".git", "raw", "processed", "__pycache__", ".ruff_cache", ".pytest_cache"}


def _repo_files() -> list[Path]:
    """Files git tracks (or would track): virtualenvs and caches are never scanned."""
    try:
        listed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],  # noqa: S607
            cwd=ROOT, capture_output=True, check=True, timeout=30,
        ).stdout.decode().split("\0")
        return [ROOT / name for name in listed if name]
    except (OSError, subprocess.SubprocessError):  # not a git checkout (e.g. a source tarball)
        return [p for p in ROOT.rglob("*")
                if not SKIP & set(p.relative_to(ROOT).parts)
                and not any(part.startswith((".venv", "venv")) for part in p.parts)]


def test_no_raw_invisible_or_bidi_characters_in_repo():
    offenders = []
    for path in _repo_files():
        if path.suffix not in CHECKED or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if INVISIBLE.search(text):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == [], f"raw invisible/bidi characters in: {offenders}"
