import json

import pytest

from phishguard.config import ConfigError, load_settings
from phishguard.incidents import IncidentStore
from phishguard.mailbox import Mailbox
from phishguard.poller import Poller, main, message_id_of
from phishguard.scorer import Reason, Verdict

from .imap_fake import FakeServer


class MarkerScorer:
    """PHISH -> quarantine, SUSPECT -> review, anything else -> deliver."""

    def scan_email_bytes(self, raw: bytes) -> Verdict:
        if b"PHISH" in raw:
            score, label, action = 0.97, "phishing", "quarantine"
        elif b"SUSPECT" in raw:
            score, label, action = 0.6, "suspicious", "review"
        else:
            score, label, action = 0.05, "legitimate", "deliver"
        return Verdict("email", score, label, action, True,
                       [Reason("text", "text_model", "stub", 0.0)], {},
                       {"from": "a@example.test", "subject": "s"})


def email(n: int, marker: str = "hello") -> bytes:
    return (f"From: a@example.test\r\nTo: me@example.test\r\nSubject: test {n}\r\n"
            f"Message-ID: <msg-{n}@example.test>\r\n\r\n{marker} body {n}\r\n").encode()


@pytest.fixture
def env(tmp_path):
    server = FakeServer()
    store = IncidentStore(tmp_path / "reports", tmp_path / "quarantine")

    def make(mode="quarantine", **extra):
        settings = load_settings({"MODE": mode, "IMAP_USER": "me@example.test",
                                  "IMAP_APP_PASSWORD": "app-pass", **extra})

        def connect():
            return Mailbox.connect(settings.imap_host, settings.imap_user,
                                   settings.imap_app_password, factory=server.factory)
        return Poller(settings, store, connect, scorer=MarkerScorer())

    return server, store, make


def test_first_run_starts_after_existing_mail_then_scans_new_mail(env):
    server, store, make = env
    server.deliver(email(1, "PHISH"))  # already in the inbox before PhishGuard started
    poller = make()
    assert poller.poll_once().scanned == 0
    server.deliver(email(2, "PHISH"))
    server.deliver(email(3))
    result = poller.poll_once()
    assert (result.scanned, result.quarantined) == (2, 1)
    assert set(server.messages("INBOX")) == {1, 3}
    assert list(server.messages("PhishGuard-Quarantine").values()) == [email(2, "PHISH")]
    assert poller.poll_once().scanned == 0  # nothing rescanned


def test_backfill_scans_the_last_n_existing_messages(env):
    server, _, make = env
    for n in range(1, 6):
        server.deliver(email(n, "PHISH" if n == 5 else "x"))
    result = make().poll_once(backfill=2)
    assert result.scanned == 2 and result.quarantined == 1


def test_monitor_mode_is_read_only(env):
    server, store, make = env
    poller = make(mode="monitor")
    poller.poll_once()
    server.deliver(email(1, "PHISH"))
    result = poller.poll_once()
    assert result.would_quarantine == 1 and result.quarantined == 0
    assert set(server.messages("INBOX")) == {1}
    assert "PhishGuard-Quarantine" not in server.folders  # not even created
    assert not [c for c in server.commands if c[0] in ("SELECT", "CREATE")
                or c[:2] in (("UID", "MOVE"), ("UID", "COPY"), ("UID", "STORE"))]
    reports = [p for p in store.reports_dir.glob("2*.json")]
    assert json.loads(reports[0].read_text())["action_taken"] == "would_quarantine"


def test_messages_are_never_marked_read_closed_or_expunged(env):
    server, _, make = env
    poller = make()
    poller.poll_once()
    server.deliver(b"Subject: user deleted this\r\n\r\nx", flags={"\\Deleted"})
    server.deliver(email(2, "PHISH"))
    server.deliver(email(3))
    poller.poll_once()
    assert all("\\Seen" not in m["flags"] for f in server.folders.values()
               for m in f["msgs"].values())
    assert 1 in server.messages("INBOX")  # the user's own \Deleted message survives
    assert not [c for c in server.commands if c[0] == "CLOSE" or c[:2] == ("UID", "EXPUNGE")]


def test_review_verdicts_are_reported_but_never_moved(env):
    server, store, make = env
    poller = make()
    poller.poll_once()
    server.deliver(email(1, "SUSPECT"))
    result = poller.poll_once()
    assert result.flagged_for_review == 1 and set(server.messages("INBOX")) == {1}
    report = json.loads(next(store.reports_dir.glob("2*.json")).read_text())
    assert report["action_taken"] == "flagged_for_review"
    assert "body" not in json.dumps(report)  # verdict and header facts only


def test_report_and_audit_contents(env):
    server, store, make = env
    poller = make()
    poller.poll_once()
    server.deliver(email(1, "PHISH"))
    poller.poll_once()
    report = json.loads(next(store.reports_dir.glob("2*.json")).read_text())
    assert report["message_id"] == "<msg-1@example.test>"
    assert report["mailbox"]["uid"] == 1 and report["verdict"]["action"] == "quarantine"
    assert "PHISH body" not in json.dumps(report)
    events = [json.loads(line)["event"] for line in store.audit.path.read_text().splitlines()]
    assert events == ["cursor_reset", "scanned"]
    assert store.audit.verify()[0]
    assert oct(store.audit.path.stat().st_mode & 0o777) == "0o600"


def test_restore_moves_back_and_is_never_requarantined(env):
    server, store, make = env
    poller = make()
    poller.poll_once()
    server.deliver(email(1, "PHISH"))
    poller.poll_once()
    (record,) = store.quarantined()
    assert record["quarantine_uid"] == 1
    folder = server.folders["PhishGuard-Quarantine"]
    assert record["quarantine_uidvalidity"] == folder["uidvalidity"]
    poller.restore(record["incident_id"], actor="tester")
    assert server.messages("PhishGuard-Quarantine") == {}
    assert list(server.messages("INBOX").values()) == [email(1, "PHISH")]
    result = poller.poll_once()  # the restored copy has a new UID in the inbox
    assert result.skipped == 1 and result.quarantined == 0
    assert set(server.messages("INBOX")) == {2}
    with pytest.raises(ValueError, match="already restored"):
        poller.restore(record["incident_id"])
    events = [json.loads(line)["event"] for line in store.audit.path.read_text().splitlines()]
    assert "restored" in events and "skipped_released" in events


def test_restore_finds_message_by_message_id_when_uid_is_stale(env):
    server, store, make = env
    poller = make()
    poller.poll_once()
    server.deliver(email(1, "PHISH"))
    poller.poll_once()
    (record,) = store.quarantined()
    record["quarantine_uid"] = 99  # e.g. the folder was renumbered
    store.save_quarantine(record["incident_id"], record)
    poller.restore(record["incident_id"])
    assert list(server.messages("INBOX").values()) == [email(1, "PHISH")]


def test_restore_refuses_a_different_message_with_the_same_message_id(env):
    server, store, make = env
    poller = make()
    poller.poll_once()
    server.deliver(email(1, "PHISH"))
    poller.poll_once()
    (record,) = store.quarantined()
    server.folders["PhishGuard-Quarantine"]["msgs"][1]["raw"] = email(1, "PHISH changed")
    with pytest.raises(Exception, match="not found"):
        poller.restore(record["incident_id"])


def test_restore_rejects_path_like_incident_ids(env):
    _, _, make = env
    with pytest.raises(ValueError):
        make().restore("../../etc/passwd")


def test_server_without_move_or_uidplus_is_refused(env):
    server, _, make = env
    server.capabilities = ("IMAP4REV1",)
    with pytest.raises(Exception, match="MOVE"):
        make().poll_once()


def test_copy_fallback_with_uidplus_expunges_only_that_message(env):
    server, _, make = env
    server.capabilities = ("IMAP4REV1", "UIDPLUS")
    poller = make()
    poller.poll_once()
    server.deliver(b"Subject: mine\r\n\r\nx", flags={"\\Deleted"})
    server.deliver(email(2, "PHISH"))
    poller.poll_once()
    assert set(server.messages("INBOX")) == {1}
    assert list(server.messages("PhishGuard-Quarantine").values()) == [email(2, "PHISH")]


def test_uidvalidity_change_resets_cursor_without_rescanning(env):
    server, store, make = env
    poller = make()
    server.deliver(email(1))
    poller.poll_once()
    server.folders["INBOX"]["uidvalidity"] = 5555
    server.deliver(email(2, "PHISH"))
    assert poller.poll_once().scanned == 0  # renumbered: start again at the newest
    assert store.load_state()["INBOX"]["uidvalidity"] == 5555


def test_wrong_password_stops_immediately(env):
    server, store, make = env
    server.password = "something-else"  # noqa: S105 - fake server
    assert make().run(once=False, sleep=lambda s: pytest.fail("must not retry")) == 2
    assert server.logins == 0
    assert "app-pass" not in store.audit.path.read_text()


def test_network_errors_back_off_exponentially(env):
    server, _, make = env
    server.fail_connect = 2
    delays = []

    def sleep(seconds):
        delays.append(seconds)
        if len(delays) == 3:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        make().run(sleep=sleep)
    assert delays == [120, 240, 60]  # 60*2, 60*4, then back to the normal interval


def test_quarantine_folder_must_not_be_the_inbox(env):
    _, _, make = env
    with pytest.raises(ConfigError):
        make(IMAP_QUARANTINE_FOLDER="INBOX")


def test_message_id_of_reads_headers_only():
    assert message_id_of(email(7)) == "<msg-7@example.test>"
    assert message_id_of(b"Subject: x\r\n\r\nMessage-ID: <body@evil.test>") == ""
    assert message_id_of(b"Message-ID: not-an-id\r\n\r\n") == ""


def test_real_scorer_quarantines_the_spoofed_fixture(env, tmp_path):
    from pathlib import Path

    from .test_scorer import scorer as stub_scorer

    server, store, make = env
    poller = make()
    poller._scorer = stub_scorer(p_email=0.5)
    poller.poll_once()
    fixture = (Path(__file__).parent / "fixtures" / "phish_spoofed_sender.eml").read_bytes()
    server.deliver(fixture)
    assert poller.poll_once().quarantined == 1


def test_cli_list_restore_and_verify(env, tmp_path, capsys):
    server, store, make = env
    poller = make()
    poller.poll_once()
    server.deliver(email(1, "PHISH"))
    poller.poll_once()
    kwargs = {"reports_dir": store.reports_dir, "quarantine_dir": store.quarantine_dir,
              "connect": poller.connect, "settings": poller.settings}
    assert main(["list"], **kwargs) == 0
    incident = store.quarantined()[0]["incident_id"]
    assert incident in capsys.readouterr().out
    assert main(["restore", incident], **kwargs) == 0
    assert main(["verify-audit"], **kwargs) == 0
    assert "audit log OK" in capsys.readouterr().out
    assert main(["restore", "nonsense"], **kwargs) == 2


def test_cli_refuses_to_run_without_mailbox_credentials(tmp_path, capsys):
    settings = load_settings({"MODE": "monitor"})
    assert main(["run", "--once"], reports_dir=tmp_path, quarantine_dir=tmp_path,
                settings=settings) == 2
    assert "IMAP_APP_PASSWORD" in capsys.readouterr().err
