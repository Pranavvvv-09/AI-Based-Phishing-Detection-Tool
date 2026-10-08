"""In-memory IMAP server speaking ``imaplib``'s Python API and response shapes.

Only what PhishGuard uses is implemented. It records every command and enforces the
rules the poller must respect: EXAMINE is read-only, FETCH without .PEEK sets \\Seen,
MOVE needs the MOVE capability, and nothing may CLOSE or expunge other messages.
"""

from __future__ import annotations

import imaplib
import re

_PARTIAL = re.compile(r"BODY(\.PEEK)?\[\]<0\.(\d+)>")


class FakeServer:
    def __init__(self, capabilities=("IMAP4REV1", "MOVE", "UIDPLUS"),
                 password="app-pass"):  # noqa: S107 - fake server, not a real credential
        self.capabilities = tuple(capabilities)
        self.password = password
        self.folders: dict[str, dict] = {}
        self.commands: list[tuple] = []
        self.logins = 0
        self.fail_connect = 0  # raise OSError on the next N connections
        self.create_folder("INBOX", uidvalidity=1000)

    def create_folder(self, name: str, uidvalidity: int = 2000) -> None:
        self.folders[name] = {"uidvalidity": uidvalidity, "next": 1, "msgs": {}}

    def deliver(self, raw: bytes, folder: str = "INBOX", flags=()) -> int:
        box = self.folders[folder]
        uid = box["next"]
        box["next"] += 1
        box["msgs"][uid] = {"raw": raw, "flags": set(flags)}
        return uid

    def messages(self, folder: str) -> dict[int, bytes]:
        return {uid: m["raw"] for uid, m in self.folders[folder]["msgs"].items()}

    def factory(self, host, port, ssl_context=None, timeout=None):
        assert port == 993 and ssl_context is not None  # TLS with verification, always
        assert ssl_context.verify_mode.name == "CERT_REQUIRED" and ssl_context.check_hostname
        if self.fail_connect:
            self.fail_connect -= 1
            raise OSError("network unreachable")
        return FakeIMAP(self)


class FakeIMAP:
    def __init__(self, server: FakeServer) -> None:
        self.server = server
        self.capabilities = server.capabilities
        self.state = "NONAUTH"
        self.untagged_responses: dict[str, list] = {}
        self.selected: str | None = None
        self.readonly = True

    def _log(self, *cmd) -> None:
        self.server.commands.append(cmd)

    def login(self, user, password):
        self._log("LOGIN", user)
        if password != self.server.password:
            raise imaplib.IMAP4.error(b"[AUTHENTICATIONFAILED] Invalid credentials (Failure)")
        self.server.logins += 1
        self.state = "AUTH"
        return "OK", [b"Logged in"]

    def logout(self):
        self._log("LOGOUT")
        self.state = "LOGOUT"
        return "BYE", [b"bye"]

    def close(self):  # pragma: no cover - PhishGuard must never call this
        self._log("CLOSE")
        raise AssertionError("CLOSE expunges \\Deleted messages: never allowed")

    def response(self, code):
        return code, self.untagged_responses.pop(code.upper(), [None])

    def select(self, mailbox="INBOX", readonly=False):
        self._log("EXAMINE" if readonly else "SELECT", mailbox)
        if mailbox not in self.server.folders:
            return "NO", [b"[NONEXISTENT] Unknown Mailbox"]
        box = self.server.folders[mailbox]
        self.selected, self.readonly, self.state = mailbox, readonly, "SELECTED"
        self.untagged_responses["UIDVALIDITY"] = [str(box["uidvalidity"]).encode()]
        return "OK", [str(len(box["msgs"])).encode()]

    def list(self, directory='""', pattern="*"):
        self._log("LIST", directory, pattern)
        if pattern in self.server.folders:
            return "OK", [f'(\\HasNoChildren) "/" "{pattern}"'.encode()]
        return "OK", [None]

    def create(self, mailbox):
        self._log("CREATE", mailbox)
        if mailbox in self.server.folders:
            return "NO", [b"[ALREADYEXISTS] Duplicate folder name"]
        self.server.create_folder(mailbox, uidvalidity=3000 + len(self.server.folders))
        return "OK", [b"Success"]

    # ----------------------------------------------------------------- UID commands

    def uid(self, command, *args):
        command = command.upper()
        self._log("UID", command, *args)
        assert self.state == "SELECTED"
        box = self.server.folders[self.selected]
        msgs = box["msgs"]
        if command == "SEARCH":
            return "OK", [" ".join(str(u) for u in self._search(msgs, args[1:])).encode()]
        if command == "FETCH":
            uid = int(args[0])
            match = _PARTIAL.search(args[1])
            if uid not in msgs:
                return "OK", [None]
            if not match.group(1):
                msgs[uid]["flags"].add("\\Seen")
            data = msgs[uid]["raw"][: int(match.group(2))]
            head = f"1 (UID {uid} BODY[]<0> {{{len(data)}}}".encode()
            return "OK", [(head, data), b")"]
        if self.readonly:
            return "NO", [b"[READ-ONLY] Mailbox is read-only"]
        uid = int(args[0])
        if command in ("MOVE", "COPY"):
            if command == "MOVE" and "MOVE" not in self.capabilities:
                raise imaplib.IMAP4.error("UID command error: BAD [b'Unknown command']")
            dest = args[1]
            if dest not in self.server.folders or uid not in msgs:
                return "NO", [b"[TRYCREATE] No such folder or message"]
            new_uid = self.server.deliver(msgs[uid]["raw"], dest, msgs[uid]["flags"])
            if command == "MOVE":
                del msgs[uid]
            if "UIDPLUS" in self.capabilities:
                validity = self.server.folders[dest]["uidvalidity"]
                self.untagged_responses.setdefault("COPYUID", []).append(
                    f"{validity} {uid} {new_uid}".encode())
            return "OK", [b"Done"]
        if command == "STORE":
            msgs[uid]["flags"].add("\\Deleted")
            return "OK", [None]
        if command == "EXPUNGE":
            assert "UIDPLUS" in self.capabilities
            if "\\Deleted" in msgs[uid]["flags"]:
                del msgs[uid]
            return "OK", [None]
        raise AssertionError(f"unexpected UID {command}")

    @staticmethod
    def _search(msgs, criteria):
        uids = sorted(msgs)
        if criteria == ("ALL",):
            return uids
        if criteria[0] == "UID":
            low = int(criteria[1].split(":")[0])
            found = [u for u in uids if u >= low]
            return found or uids[-1:]  # RFC 3501: n:* always includes the highest UID
        if criteria[:2] == ("HEADER", "Message-ID"):
            needle = criteria[2].strip('"').encode()
            return [u for u in uids if needle in msgs[u]["raw"]]
        raise AssertionError(f"unexpected SEARCH {criteria}")
