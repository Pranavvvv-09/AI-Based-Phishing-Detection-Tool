"""Minimal, defensive IMAP client for your *own* mailbox.

What it does, and what it never does:

* **TLS only, certificates verified.** ``IMAP4_SSL`` on port 993 with
  ``ssl.create_default_context()`` (hostname + chain checked). No plaintext fallback.
* **Read without side effects.** Messages are fetched with ``BODY.PEEK[]`` so they are
  not marked as read, and only the first ``max_bytes + 1`` bytes are downloaded: an
  over-size message is seen as over-size by the parser and goes to review.
* **Move, never delete.** The only write is ``UID MOVE`` (RFC 6851). If a server lacks
  MOVE, COPY + delete is used only when UIDPLUS lets us expunge *that one* message;
  a plain EXPUNGE could remove messages the user deleted themselves, so without
  UIDPLUS we refuse to quarantine.
* **No injection.** Folder names are validated in ``config.py`` and Message-IDs here
  before they reach an IMAP command; UIDs are integers.
* **Never expunges anything else.** Sessions end with LOGOUT, never CLOSE (CLOSE
  permanently removes every message flagged \\Deleted, including the user's own).
* **No secrets in errors.** Login failures are re-raised without the server's text.
"""

from __future__ import annotations

import imaplib
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass

IMAP_PORT = 993
DEFAULT_TIMEOUT = 30  # seconds per network operation
_UID_IN_FETCH = re.compile(rb"\bUID (\d+)")
_COPYUID = re.compile(rb"^\s*(\d+)\s+([\d:,]+)\s+([\d:,]+)\s*$")
# Message-IDs go into SEARCH commands: printable, no quotes/backslashes, bounded.
_SAFE_MESSAGE_ID = re.compile(r"^<[\x21\x23-\x5b\x5d-\x7e]{1,250}>$")
_SAFE_FOLDER = re.compile(r"^[A-Za-z0-9_/-]{1,100}$")

# Older imaplib versions don't know UID MOVE; registering it is all that is needed.
imaplib.Commands.setdefault("MOVE", ("SELECTED",))


class MailboxError(RuntimeError):
    """A mailbox operation failed. Messages never contain credentials."""


class LoginError(MailboxError):
    """Authentication failed: retrying would risk locking the account."""


@dataclass(frozen=True)
class Selected:
    folder: str
    uidvalidity: int
    readonly: bool


def _folder(name: str) -> str:
    if not _SAFE_FOLDER.match(name):
        raise MailboxError("unsafe folder name")
    return name


class Mailbox:
    """Wraps an ``imaplib.IMAP4``-like object. Use :meth:`connect` in production."""

    def __init__(self, imap) -> None:
        self.imap = imap
        self.selected: Selected | None = None

    # ------------------------------------------------------------------ session

    @classmethod
    def connect(
        cls,
        host: str,
        user: str,
        password: str,
        timeout: float = DEFAULT_TIMEOUT,
        factory: Callable[..., object] | None = None,
    ) -> Mailbox:
        context = ssl.create_default_context()  # verifies certificate chain and hostname
        try:
            imap = (factory or imaplib.IMAP4_SSL)(
                host, IMAP_PORT, ssl_context=context, timeout=timeout
            )
        except (OSError, imaplib.IMAP4.error) as exc:
            raise MailboxError(f"cannot connect to {host}:{IMAP_PORT} ({type(exc).__name__})") \
                from None
        try:
            imap.login(user, password)
        except imaplib.IMAP4.error:
            _quiet_logout(imap)
            raise LoginError("IMAP login failed: check IMAP_USER and the app password") from None
        return cls(imap)

    def close(self) -> None:
        # LOGOUT only. IMAP CLOSE would permanently expunge every message flagged
        # \Deleted in the folder, including ones the user deleted themselves.
        _quiet_logout(self.imap)

    def __enter__(self) -> Mailbox:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def capabilities(self) -> set[str]:
        return {c.decode() if isinstance(c, bytes) else str(c)
                for c in getattr(self.imap, "capabilities", ())}

    def can_move(self) -> bool:
        caps = self.capabilities
        return "MOVE" in caps or "UIDPLUS" in caps

    # ------------------------------------------------------------------ folders

    def select(self, folder: str, readonly: bool) -> Selected:
        """SELECT (read-write) or EXAMINE (read-only) a folder; returns its UIDVALIDITY."""
        typ, _ = self.imap.select(_folder(folder), readonly=readonly)
        if typ != "OK":
            raise MailboxError(f"cannot open folder {folder}")
        _, data = self.imap.response("UIDVALIDITY")
        try:
            uidvalidity = int(data[-1])
        except (TypeError, ValueError, IndexError):
            raise MailboxError(f"server sent no UIDVALIDITY for {folder}") from None
        self.selected = Selected(folder, uidvalidity, readonly)
        return self.selected

    def ensure_folder(self, folder: str) -> None:
        """Create the quarantine folder if it doesn't exist (an existing one is fine)."""
        typ, data = self.imap.list('""', _folder(folder))
        if typ == "OK" and any(item for item in data if item):
            return
        typ, _ = self.imap.create(folder)
        if typ != "OK":
            raise MailboxError(f"cannot create folder {folder}")

    # ------------------------------------------------------------------ reading

    def _search(self, *criteria: str) -> list[int]:
        typ, data = self.imap.uid("SEARCH", None, *criteria)
        if typ != "OK":
            raise MailboxError("UID SEARCH failed")
        uids: list[int] = []
        for chunk in data:
            if chunk:
                uids += [int(x) for x in chunk.split() if x.isdigit()]
        return sorted(set(uids))

    def all_uids(self) -> list[int]:
        return self._search("ALL")

    def uids_after(self, last_uid: int) -> list[int]:
        # "UID n:*" always includes the highest UID even if it is below n (RFC 3501),
        # so filter again.
        return [uid for uid in self._search("UID", f"{last_uid + 1}:*") if uid > last_uid]

    def fetch(self, uid: int, max_bytes: int) -> bytes | None:
        """Up to ``max_bytes + 1`` raw bytes of a message, without setting \\Seen."""
        typ, data = self.imap.uid("FETCH", str(int(uid)), f"(UID BODY.PEEK[]<0.{max_bytes + 1}>)")
        if typ != "OK":
            raise MailboxError(f"UID FETCH {uid} failed")
        for item in data or ():
            if isinstance(item, tuple) and len(item) >= 2 and b"BODY[" in item[0]:
                match = _UID_IN_FETCH.search(item[0])
                if match and int(match.group(1)) != uid:
                    continue  # unsolicited FETCH for another message
                return bytes(item[1])
        return None  # message vanished (moved or deleted by another client)

    def find_message_id(self, message_id: str) -> list[int]:
        if not _SAFE_MESSAGE_ID.match(message_id):
            raise MailboxError("Message-ID unusable for search")
        return self._search("HEADER", "Message-ID", f'"{message_id}"')

    # ------------------------------------------------------------------ moving

    def move(self, uid: int, destination: str) -> tuple[int, int] | None:
        """Move one message out of the selected folder.

        Returns (destination UIDVALIDITY, new UID) when the server reports it (UIDPLUS).
        """
        if self.selected is None or self.selected.readonly:
            raise MailboxError("folder is not open read-write")
        destination = _folder(destination)
        caps = self.capabilities
        if "MOVE" in caps:
            typ, _ = self.imap.uid("MOVE", str(int(uid)), destination)
            if typ != "OK":
                raise MailboxError(f"UID MOVE {uid} failed")
        elif "UIDPLUS" in caps:
            typ, _ = self.imap.uid("COPY", str(int(uid)), destination)
            if typ != "OK":
                raise MailboxError(f"UID COPY {uid} failed")
            typ, _ = self.imap.uid("STORE", str(int(uid)), "+FLAGS.SILENT", r"(\Deleted)")
            if typ != "OK":
                raise MailboxError(f"UID STORE {uid} failed (message copied, original kept)")
            typ, _ = self.imap.uid("EXPUNGE", str(int(uid)))  # only this UID (RFC 4315)
            if typ != "OK":
                raise MailboxError(f"UID EXPUNGE {uid} failed (message copied, original kept)")
        else:
            raise MailboxError("server supports neither MOVE nor UIDPLUS: refusing to move")
        return self._copied_uid(uid)

    def _copied_uid(self, uid: int) -> tuple[int, int] | None:
        """Destination UID from the COPYUID response code (UIDPLUS), if the server sent it."""
        try:
            _, data = self.imap.response("COPYUID")
        except (imaplib.IMAP4.error, AttributeError):
            return None
        for item in reversed(data or []):
            match = _COPYUID.match(item if isinstance(item, bytes) else b"")
            if match and match.group(2) == str(uid).encode() and match.group(3).isdigit():
                return int(match.group(1)), int(match.group(3))
        return None


def _quiet_logout(imap) -> None:
    try:
        imap.logout()
    except (OSError, imaplib.IMAP4.error, AttributeError):
        pass
