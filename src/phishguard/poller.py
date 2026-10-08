"""Watch your own mailbox over IMAP, score new mail, and quarantine phishing.

Run::

    python -m phishguard.poller run            # poll every IMAP_POLL_SECONDS
    python -m phishguard.poller run --once     # one pass, then exit
    python -m phishguard.poller run --once --backfill 20   # also scan the last 20 messages
    python -m phishguard.poller list           # quarantined messages
    python -m phishguard.poller restore <incident-id>      # move one back to the inbox
    python -m phishguard.poller verify-audit   # check the audit log's hash chain

Behaviour
---------
* ``MODE=monitor`` (default) opens the inbox **read-only** (EXAMINE) and only writes
  reports: messages scoring at the quarantine threshold are recorded as
  ``would_quarantine``. ``MODE=quarantine`` additionally **moves** them to
  ``IMAP_QUARANTINE_FOLDER``. Nothing is ever deleted, marked read or modified.
* "review" verdicts (suspicious, or not fully analysed) are reported, never moved:
  only confident verdicts are acted on automatically.
* Only mail that arrives after the first run is scanned (plus ``--backfill N``). The
  poller remembers the last UID per UIDVALIDITY, so restarts don't rescan the inbox.
* Every message scanned is written to the hash-chained audit log; every flagged
  message gets a JSON incident report; every quarantined message gets a record that
  ``restore`` uses. A restored message is remembered by its content hash and never
  quarantined again.
* Login failures stop the poller immediately (retrying could lock the account);
  network errors are retried with exponential backoff.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import logging
import re
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .config import ConfigError, Settings, load_settings
from .incidents import IncidentStore, new_incident_id, utc_now, valid_incident_id
from .mailbox import LoginError, Mailbox, MailboxError
from .scorer import safe_text

ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = ROOT / "reports"
QUARANTINE_DIR = ROOT / "quarantine"
INBOX = "INBOX"
MAX_PER_POLL = 200  # bounds one pass; the rest is picked up on the next poll
MAX_BACKFILL = 500
MAX_BACKOFF_SECONDS = 30 * 60
_MESSAGE_ID = re.compile(rb"^message-id:[ \t]*(<[^<>\s]{1,250}>)", re.IGNORECASE | re.MULTILINE)

log = logging.getLogger("phishguard.poller")


def message_id_of(raw: bytes) -> str:
    """Message-ID from the header section only ('' if missing or malformed)."""
    head = raw[: 256 * 1024].split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    match = _MESSAGE_ID.search(head)
    return match.group(1).decode("ascii", "replace") if match else ""


def content_hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass
class PollResult:
    scanned: int = 0
    quarantined: int = 0
    would_quarantine: int = 0
    flagged_for_review: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


class Poller:
    def __init__(
        self,
        settings: Settings,
        store: IncidentStore,
        connect: Callable[[], Mailbox],
        scorer=None,
    ) -> None:
        if settings.imap_quarantine_folder.upper() == INBOX:
            raise ConfigError("IMAP_QUARANTINE_FOLDER must not be the inbox")
        self.settings = settings
        self.store = store
        self.connect = connect
        self._scorer = scorer

    @property
    def scorer(self):
        if self._scorer is None:
            from .scorer import Scorer

            self._scorer = Scorer(self.settings)
        return self._scorer

    @property
    def quarantine_mode(self) -> bool:
        return self.settings.mode == "quarantine"

    # ------------------------------------------------------------------ polling

    def poll_once(self, backfill: int = 0) -> PollResult:
        result = PollResult()
        with self.connect() as box:
            if self.quarantine_mode:
                if not box.can_move():
                    raise MailboxError("server can't move messages safely (no MOVE or UIDPLUS)")
                box.ensure_folder(self.settings.imap_quarantine_folder)
            selected = box.select(INBOX, readonly=not self.quarantine_mode)
            cursor = self._cursor(box, selected.uidvalidity, backfill)
            released = self.store.restored_hashes()
            for uid in box.uids_after(cursor)[:MAX_PER_POLL]:
                self._process(box, selected.uidvalidity, uid, released, result)
                self._save_cursor(selected.uidvalidity, uid)
        return result

    def _cursor(self, box: Mailbox, uidvalidity: int, backfill: int) -> int:
        state = self.store.load_state().get(INBOX, {})
        if state.get("uidvalidity") == uidvalidity and isinstance(state.get("last_uid"), int):
            return state["last_uid"]
        # First run, or the server renumbered the folder: start at the newest message
        # instead of rescanning (and possibly moving) the whole inbox.
        uids = box.all_uids()
        backfill = max(0, min(backfill, MAX_BACKFILL))
        start = uids[-backfill - 1] if len(uids) > backfill else 0
        if not backfill:
            start = uids[-1] if uids else 0
        self.store.audit.append("cursor_reset", folder=INBOX, uidvalidity=uidvalidity,
                                start_after_uid=start, backfill=backfill,
                                previous_uidvalidity=state.get("uidvalidity"))
        self._save_cursor(uidvalidity, start)
        return start

    def _save_cursor(self, uidvalidity: int, uid: int) -> None:
        state = self.store.load_state()
        state[INBOX] = {"uidvalidity": uidvalidity, "last_uid": uid, "updated_at": utc_now()}
        self.store.save_state(state)

    def _process(self, box: Mailbox, uidvalidity: int, uid: int, released: set[str],
                 result: PollResult) -> None:
        max_bytes = self.settings.max_email_bytes
        raw = box.fetch(uid, max_bytes)
        if raw is None:
            result.skipped += 1
            self.store.audit.append("vanished", uid=uid, uidvalidity=uidvalidity)
            return
        digest = content_hash(raw)
        if digest in released:
            result.skipped += 1
            self.store.audit.append("skipped_released", uid=uid, content_sha256=digest)
            return

        verdict = self.scorer.scan_email_bytes(raw)
        result.scanned += 1
        message_id = message_id_of(raw)
        if verdict.action == "quarantine":
            taken = "quarantined" if self.quarantine_mode else "would_quarantine"
        elif verdict.action == "review":
            taken = "flagged_for_review"
        else:
            taken = "delivered"

        incident_id = None if taken == "delivered" else new_incident_id()
        moved_to = None
        if taken == "quarantined":
            try:
                moved_to = box.move(uid, self.settings.imap_quarantine_folder)
            except MailboxError as exc:
                taken = "quarantine_failed"
                result.errors.append(f"uid {uid}: {exc}")
                log.error("uid=%s quarantine failed: %s", uid, exc)

        if incident_id:
            summary = verdict.to_dict()
            self.store.write_report(incident_id, {
                "created_at": utc_now(),
                "mode": self.settings.mode,
                "action_taken": taken,
                "mailbox": {"host": self.settings.imap_host, "folder": INBOX,
                            "uid": uid, "uidvalidity": uidvalidity},
                "message_id": safe_text(message_id),
                "content_sha256": digest,
                "bytes_fetched": len(raw),
                "verdict": summary,
            })
        if taken == "quarantined":
            dest_validity, dest_uid = moved_to or (None, None)
            summary = verdict.to_dict()["summary"]
            self.store.save_quarantine(incident_id, {
                "quarantined_at": utc_now(),
                "source_folder": INBOX, "source_uid": uid, "source_uidvalidity": uidvalidity,
                "quarantine_folder": self.settings.imap_quarantine_folder,
                "quarantine_uid": dest_uid, "quarantine_uidvalidity": dest_validity,
                "message_id": message_id, "content_sha256": digest, "fetch_bytes": max_bytes,
                "score": round(verdict.score, 4) if verdict.score is not None else None,
                "from": summary.get("from", ""), "subject": summary.get("subject", ""),
                "restored_at": None,
            })
            result.quarantined += 1
        elif taken == "would_quarantine":
            result.would_quarantine += 1
        elif taken in ("flagged_for_review", "quarantine_failed"):
            result.flagged_for_review += 1

        score = None if verdict.score is None else round(verdict.score, 4)
        self.store.audit.append("scanned", uid=uid, uidvalidity=uidvalidity, score=score,
                                verdict=verdict.action, action_taken=taken,
                                incident_id=incident_id, content_sha256=digest)
        log.info("uid=%s score=%s action=%s incident=%s", uid, score, taken, incident_id or "-")

    # ------------------------------------------------------------------ restore

    def restore(self, incident_id: str, actor: str = "") -> dict:
        """Move a quarantined message back to where it came from."""
        if not valid_incident_id(incident_id):
            raise ValueError("invalid incident id")
        record = self.store.load_quarantine(incident_id)
        if record.get("restored_at"):
            raise ValueError(f"{incident_id} was already restored at {record['restored_at']}")
        with self.connect() as box:
            selected = box.select(record["quarantine_folder"], readonly=False)
            uid = self._locate(box, record, selected.uidvalidity)
            if uid is None:
                raise MailboxError("message not found in the quarantine folder "
                                   "(moved or deleted by hand?)")
            box.move(uid, record["source_folder"])
        record.update(restored_at=utc_now(), restored_by=actor or "unknown")
        self.store.save_quarantine(incident_id, record)
        self.store.audit.append("restored", incident_id=incident_id, by=record["restored_by"],
                                to_folder=record["source_folder"],
                                content_sha256=record.get("content_sha256"))
        return record

    @staticmethod
    def _locate(box: Mailbox, record: dict, uidvalidity: int) -> int | None:
        """The message's UID in the quarantine folder, confirmed by its content hash."""
        candidates: list[int] = []
        if record.get("quarantine_uid") and record.get("quarantine_uidvalidity") == uidvalidity:
            candidates.append(int(record["quarantine_uid"]))
        if record.get("message_id"):
            try:
                candidates += box.find_message_id(record["message_id"])
            except MailboxError:
                pass
        for uid in dict.fromkeys(candidates):
            raw = box.fetch(uid, int(record.get("fetch_bytes", 0)))
            if raw is not None and content_hash(raw) == record.get("content_sha256"):
                return uid
        return None

    # ------------------------------------------------------------------ loop

    def run(self, once: bool = False, backfill: int = 0,
            sleep: Callable[[float], None] = time.sleep) -> int:
        failures = 0
        while True:
            try:
                result = self.poll_once(backfill=backfill)
                backfill = 0  # only on the first pass
                failures = 0
                log.info("poll done: scanned=%d quarantined=%d would_quarantine=%d review=%d "
                         "skipped=%d errors=%d", result.scanned, result.quarantined,
                         result.would_quarantine, result.flagged_for_review, result.skipped,
                         len(result.errors))
                delay = self.settings.imap_poll_seconds
            except LoginError as exc:
                self.store.audit.append("login_failed")
                log.error("%s - stopping (retrying could lock the account)", exc)
                return 2
            except (MailboxError, OSError) as exc:
                failures += 1
                delay = min(self.settings.imap_poll_seconds * 2 ** failures, MAX_BACKOFF_SECONDS)
                self.store.audit.append("poll_error", error=type(exc).__name__)
                log.warning("poll failed (%s: %s); retrying in %ds", type(exc).__name__, exc,
                            delay)
                if once:
                    return 1
            if once:
                return 0
            sleep(delay)


# ---------------------------------------------------------------------- CLI


def _connector(settings: Settings) -> Callable[[], Mailbox]:
    def connect() -> Mailbox:
        return Mailbox.connect(settings.imap_host, settings.imap_user,
                               settings.imap_app_password)
    return connect


def _require_mailbox_settings(settings: Settings) -> None:
    if not settings.imap_user or "IMAP_APP_PASSWORD" in settings.missing_secrets():
        raise ConfigError("set IMAP_USER and IMAP_APP_PASSWORD in .env (see docs/lab-setup.md)")


def main(argv: list[str] | None = None, reports_dir: Path = REPORTS_DIR,
         quarantine_dir: Path = QUARANTINE_DIR, connect: Callable[[], Mailbox] | None = None,
         settings: Settings | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m phishguard.poller",
                                     description="Scan your own mailbox and quarantine phishing.")
    sub = parser.add_subparsers(dest="command", required=True)
    run_cmd = sub.add_parser("run", help="poll the inbox")
    run_cmd.add_argument("--once", action="store_true", help="one pass, then exit")
    run_cmd.add_argument("--backfill", type=int, default=0, metavar="N",
                         help=f"on first run, also scan the last N messages (max {MAX_BACKFILL})")
    sub.add_parser("list", help="show quarantined messages")
    restore_cmd = sub.add_parser("restore", help="move a quarantined message back")
    restore_cmd.add_argument("incident_id")
    sub.add_parser("verify-audit", help="check the audit log's hash chain")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    try:
        if settings is None:
            dotenv = ROOT / ".env"
            settings = load_settings(dotenv_path=dotenv if dotenv.exists() else None)
        store = IncidentStore(reports_dir, quarantine_dir)
        if args.command == "verify-audit":
            ok, count, problem = store.audit.verify()
            print(f"audit log OK ({count} entries)" if ok else f"audit log FAILED: {problem}")
            return 0 if ok else 1
        if args.command == "list":
            for rec in store.quarantined():
                state = f"restored {rec['restored_at']}" if rec.get("restored_at") else "held"
                print(f"{rec['incident_id']}  score={rec.get('score')}  {state}  "
                      f"from={safe_text(rec.get('from', ''), 60)}  "
                      f"subject={safe_text(rec.get('subject', ''), 60)}")
            return 0
        _require_mailbox_settings(settings)
        poller = Poller(settings, store, connect or _connector(settings))
        if args.command == "restore":
            record = poller.restore(args.incident_id, actor=getpass.getuser())
            print(f"restored {record['incident_id']} to {record['source_folder']}")
            return 0
        if not 0 <= args.backfill <= MAX_BACKFILL:
            parser.error(f"--backfill must be between 0 and {MAX_BACKFILL}")
        log.info("mode=%s folder=%s threshold=%.2f", settings.mode,
                 settings.imap_quarantine_folder, settings.quarantine_threshold)
        return poller.run(once=args.once, backfill=args.backfill)
    except (ConfigError, ValueError, KeyError, MailboxError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
