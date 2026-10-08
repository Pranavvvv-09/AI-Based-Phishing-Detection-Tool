"""Incident reports, quarantine records and a tamper-evident audit log.

Layout (both directories are gitignored)::

    reports/<incident-id>.json     one JSON report per flagged message (no body text)
    reports/audit.log              append-only JSON lines, hash-chained
    reports/poller_state.json      where the poller stopped (UIDVALIDITY + last UID)
    quarantine/<incident-id>.json  what was moved where, so it can be restored

* Reports hold the verdict (already sanitised by ``Verdict.to_dict``) and a few
  header facts, never the body: real phishing bodies contain live links.
* Files are written atomically (temp file + rename) with owner-only permissions.
* Each audit line stores the SHA-256 of the previous line's entry, so deleting or
  editing a line breaks the chain and ``verify`` reports where. (It shows tampering;
  it can't prevent someone with file access from rewriting the whole log.)
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import tempfile
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows: single-process use only
    fcntl = None

GENESIS = "0" * 64
_INCIDENT_ID = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")
MAX_AUDIT_LINE = 64 * 1024


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_incident_id() -> str:
    return f"{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}"


def valid_incident_id(incident_id: str) -> bool:
    """Incident IDs become file names: only our own format is accepted (no paths)."""
    return bool(_INCIDENT_ID.match(incident_id))


def write_json_atomic(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=True, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def read_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} is not a JSON object")
    return data


def _entry_hash(entry: dict) -> str:
    canonical = json.dumps(entry, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class AuditLog:
    """Append-only, hash-chained JSON-lines log."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def _last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        with self.path.open("rb") as handle:
            handle.seek(max(0, self.path.stat().st_size - MAX_AUDIT_LINE))
            last = handle.read().splitlines()[-1]
        return json.loads(last)["hash"]

    def append(self, event: str, **fields: object) -> dict:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            # The poller and the web app may append at the same time: hold an exclusive
            # lock from reading the last hash until the new line is written.
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            entry = {"ts": utc_now(), "event": event, **fields, "prev": self._last_hash()}
            line = {**entry, "hash": _entry_hash(entry)}
            handle.write(json.dumps(line, sort_keys=True, ensure_ascii=True) + "\n")
            handle.flush()
        return line

    def verify(self) -> tuple[bool, int, str]:
        """(ok, lines checked, problem). Detects edited, deleted or reordered lines."""
        if not self.path.exists():
            return True, 0, ""
        prev = GENESIS
        count = 0
        with self.path.open(encoding="utf-8") as handle:
            for number, raw in enumerate(handle, start=1):
                try:
                    line = json.loads(raw)
                    stored = line.pop("hash")
                except (ValueError, KeyError, AttributeError):
                    return False, count, f"line {number} is not a valid audit entry"
                if line.get("prev") != prev:
                    return False, count, f"line {number}: chain broken (line missing or reordered)"
                if _entry_hash(line) != stored:
                    return False, count, f"line {number}: contents were modified"
                prev, count = stored, count + 1
        return True, count, ""


@dataclass
class IncidentStore:
    reports_dir: Path
    quarantine_dir: Path

    def __post_init__(self) -> None:
        self.reports_dir, self.quarantine_dir = Path(self.reports_dir), Path(self.quarantine_dir)
        self.audit = AuditLog(self.reports_dir / "audit.log")

    # ----------------------------------------------------------- incident reports

    def write_report(self, incident_id: str, report: dict) -> Path:
        path = self.reports_dir / f"{incident_id}.json"
        write_json_atomic(path, {"incident_id": incident_id, **report})
        return path

    # -------------------------------------------------------- quarantine records

    def _record_path(self, incident_id: str) -> Path:
        if not valid_incident_id(incident_id):
            raise ValueError("invalid incident id")
        return self.quarantine_dir / f"{incident_id}.json"

    def save_quarantine(self, incident_id: str, record: dict) -> None:
        write_json_atomic(self._record_path(incident_id), {"incident_id": incident_id, **record})

    def load_quarantine(self, incident_id: str) -> dict:
        path = self._record_path(incident_id)
        if not path.exists():
            raise KeyError(incident_id)
        return read_json(path)

    def quarantined(self) -> list[dict]:
        records = []
        for path in sorted(self.quarantine_dir.glob("*.json")):
            if valid_incident_id(path.stem):
                with contextlib.suppress(OSError, ValueError):
                    records.append(read_json(path))
        return records

    def restored_hashes(self) -> set[str]:
        """Content hashes of messages a person released: never re-quarantine them."""
        return {r["content_sha256"] for r in self.quarantined()
                if r.get("restored_at") and r.get("content_sha256")}

    # ------------------------------------------------------------ read side (web)

    def recent_reports(self, limit: int = 100) -> list[dict]:
        """Newest incident reports first (IDs start with a UTC timestamp)."""
        paths = sorted((p for p in self.reports_dir.glob("*.json") if valid_incident_id(p.stem)),
                       key=lambda p: p.stem, reverse=True)
        reports = []
        for path in paths[:limit]:
            with contextlib.suppress(OSError, ValueError):
                reports.append(read_json(path))
        return reports

    def load_report(self, incident_id: str) -> dict:
        if not valid_incident_id(incident_id):
            raise KeyError(incident_id)
        path = self.reports_dir / f"{incident_id}.json"
        if not path.exists():
            raise KeyError(incident_id)
        return read_json(path)

    def audit_tail(self, limit: int = 5000) -> list[dict]:
        """The last ``limit`` audit entries (unverified; see ``audit.verify``)."""
        if not self.audit.path.exists():
            return []
        with self.audit.path.open(encoding="utf-8") as handle:
            lines = deque(handle, maxlen=limit)  # streams: memory bounded by ``limit``
        entries = []
        for raw in lines:
            with contextlib.suppress(ValueError):
                entry = json.loads(raw)
                if isinstance(entry, dict):
                    entries.append(entry)
        return entries

    # ------------------------------------------------------------ poller state

    @property
    def state_path(self) -> Path:
        return self.reports_dir / "poller_state.json"

    def load_state(self) -> dict:
        try:
            return read_json(self.state_path)
        except (OSError, ValueError):
            return {}

    def save_state(self, state: dict) -> None:
        write_json_atomic(self.state_path, state)
