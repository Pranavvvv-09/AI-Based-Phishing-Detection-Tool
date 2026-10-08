"""The real ``imaplib`` parser against scripted server bytes (what Gmail sends).

The fake in ``imap_fake.py`` mimics imaplib's return values; this test checks those
shapes against imaplib itself: UIDVALIDITY codes, FETCH literals, COPYUID after MOVE.
"""

import imaplib
import socket
import threading

from phishguard.mailbox import Mailbox

MESSAGE = b"Subject: hi\r\nMessage-ID: <a@b.test>\r\n\r\nbody\r\n"
REPLIES = {
    b"LOGIN": b"{tag} OK [CAPABILITY IMAP4rev1 MOVE UIDPLUS] logged in\r\n",
    b"SELECT": (b"* 3 EXISTS\r\n* OK [UIDVALIDITY 777] UIDs valid\r\n"
                b"{tag} OK [READ-WRITE] done\r\n"),
    b"UID SEARCH": b"* SEARCH 4 7 8\r\n{tag} OK done\r\n",
    b"UID FETCH": (b"* 3 FETCH (UID 8 BODY[]<0> {%d}\r\n" % len(MESSAGE) + MESSAGE
                   + b")\r\n{tag} OK done\r\n"),
    b"UID MOVE": b"* OK [COPYUID 4242 8 15] moved\r\n* 3 EXPUNGE\r\n{tag} OK done\r\n",
    b"LOGOUT": b"* BYE\r\n{tag} OK bye\r\n",
}


def _serve(listener: socket.socket, seen: list[bytes]) -> None:
    conn, _ = listener.accept()
    with conn, conn.makefile("rb") as lines:
        conn.sendall(b"* OK [CAPABILITY IMAP4rev1 MOVE UIDPLUS] ready\r\n")
        for line in lines:
            tag, command = line.rstrip(b"\r\n").split(b" ", 1)
            seen.append(command)
            key = next((k for k in REPLIES if command.upper().startswith(k)), None)
            reply = REPLIES.get(key, b"{tag} BAD unexpected\r\n")
            conn.sendall(reply.replace(b"{tag}", tag))
            if key == b"LOGOUT":
                return


def test_real_imaplib_parses_what_the_mailbox_expects():
    listener = socket.create_server(("127.0.0.1", 0))
    seen: list[bytes] = []
    thread = threading.Thread(target=_serve, args=(listener, seen), daemon=True)
    thread.start()
    imap = imaplib.IMAP4("127.0.0.1", listener.getsockname()[1], timeout=5)
    imap.login("user", "pw")
    box = Mailbox(imap)
    assert box.select("INBOX", readonly=False).uidvalidity == 777
    assert box.uids_after(5) == [7, 8]
    assert box.fetch(8, 1000) == MESSAGE
    assert box.move(8, "Quarantine") == (4242, 15)
    box.close()
    thread.join(5)
    listener.close()
    assert b"UID FETCH 8 (UID BODY.PEEK[]<0.1001>)" in seen  # PEEK: never marks as read
    assert b"UID MOVE 8 Quarantine" in seen
    assert not any(c.upper().startswith((b"CLOSE", b"EXPUNGE", b"STORE")) for c in seen)
