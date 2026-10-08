import json

import pytest

from phishguard.incidents import AuditLog, IncidentStore, new_incident_id, valid_incident_id
from phishguard.mailbox import LoginError, Mailbox, MailboxError

from .imap_fake import FakeServer


def test_audit_chain_detects_edits_deletions_and_reordering(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    for n in range(4):
        log.append("scanned", uid=n)
    assert log.verify() == (True, 4, "")
    lines = log.path.read_text().splitlines()

    edited = [*lines]
    entry = json.loads(edited[1])
    entry["uid"] = 99
    edited[1] = json.dumps(entry)
    log.path.write_text("\n".join(edited) + "\n")
    assert log.verify()[2] == "line 2: contents were modified"

    log.path.write_text("\n".join([lines[0], lines[2], lines[3]]) + "\n")
    assert "chain broken" in log.verify()[2]

    log.path.write_text("\n".join([lines[1], lines[0]]) + "\n")
    assert not log.verify()[0]

    log.path.write_text("not json\n")
    assert log.verify()[2] == "line 1 is not a valid audit entry"


def test_incident_ids_are_strict_and_files_private(tmp_path):
    incident = new_incident_id()
    assert valid_incident_id(incident)
    for bad in ["../x", "20260101T000000Z-zzzzzzzz", "", incident + "/.."]:
        assert not valid_incident_id(bad)
    store = IncidentStore(tmp_path / "r", tmp_path / "q")
    store.save_quarantine(incident, {"content_sha256": "ab", "restored_at": "now"})
    path = store.quarantine_dir / f"{incident}.json"
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert store.restored_hashes() == {"ab"}
    with pytest.raises(ValueError):
        store.load_quarantine("../../etc/passwd")
    assert not list(store.quarantine_dir.glob(".tmp-*"))  # atomic writes leave no temp files


def test_corrupt_state_file_means_a_fresh_start(tmp_path):
    store = IncidentStore(tmp_path / "r", tmp_path / "q")
    store.reports_dir.mkdir(parents=True)
    store.state_path.write_text("{broken")
    assert store.load_state() == {}


def connect(server, password="app-pass"):  # noqa: S107 - fake server
    return Mailbox.connect("imap.example.test", "me", password, factory=server.factory)


def test_login_error_contains_no_secret_or_server_text():
    server = FakeServer()
    with pytest.raises(LoginError) as info:
        connect(server, password="wrong-secret-123")  # noqa: S106
    assert "wrong-secret-123" not in str(info.value)
    assert "AUTHENTICATIONFAILED" not in str(info.value)
    assert info.value.__cause__ is None and info.value.__suppress_context__


def test_fetch_ignores_unsolicited_responses_and_missing_messages():
    server = FakeServer()
    server.deliver(b"Subject: a\r\n\r\nx")
    box = connect(server)
    box.select("INBOX", readonly=True)
    assert box.fetch(1, 100) == b"Subject: a\r\n\r\nx"
    assert box.fetch(1, 5) == b"Subjec"  # max_bytes + 1: over-size is detectable
    assert box.fetch(42, 100) is None
    box.imap.uid = lambda *a: ("OK", [(b"1 (UID 7 BODY[]<0> {1}", b"z"), b")"])
    assert box.fetch(1, 100) is None


def test_unsafe_names_never_reach_imap_commands():
    box = connect(FakeServer())
    with pytest.raises(MailboxError):
        box.select('INBOX" DELETE "x', readonly=True)
    box.select("INBOX", readonly=False)
    with pytest.raises(MailboxError):
        box.find_message_id('<a"b@x> OR ALL')
    with pytest.raises(MailboxError):
        box.move(1, "Trash\r\nA1 DELETE INBOX")


def test_move_needs_a_read_write_folder():
    server = FakeServer()
    server.deliver(b"x")
    box = connect(server)
    box.select("INBOX", readonly=True)
    with pytest.raises(MailboxError, match="read-write"):
        box.move(1, "Junk")
