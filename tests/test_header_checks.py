from pathlib import Path

from phishguard.header_checks import (
    WEIGHTS,
    authserv_id,
    check_headers,
    parse_auth_results,
)
from phishguard.parser import parse_email, parse_email_file

FIXTURES = Path(__file__).parent / "fixtures"


def report_for(name):
    return check_headers(parse_email_file(FIXTURES / name))


def test_legit_email_is_clean():
    r = report_for("legit_newsletter.eml")
    assert (r.spf, r.dkim, r.dmarc, r.auth_source) == ("pass", "pass", "pass", "trusted")
    assert r.findings == []
    assert r.risk == 0.0


def test_spoofed_paypal_flags_everything():
    r = report_for("phish_spoofed_sender.eml")
    assert (r.spf, r.dkim, r.dmarc) == ("softfail", "fail", "fail")
    assert {
        "dmarc_fail",
        "spf_softfail",
        "dkim_fail",
        "lookalike_sender_domain",
        "display_name_brand_spoof",
        "reply_to_mismatch",
        "return_path_mismatch",
    } <= r.codes
    assert r.risk == 1.0


def test_forged_pass_header_below_real_one_is_ignored():
    # Attacker added "dmarc=pass" claiming mx.google.com; Gmail's real header on top says fail.
    r = report_for("phish_forged_auth.eml")
    assert r.dmarc == "fail" and r.spf == "fail"
    assert "forged_auth_header" in r.codes
    assert "dmarc_fail" in r.codes


def test_pass_from_untrusted_server_is_not_credited():
    r = report_for("phish_untrusted_pass.eml")
    assert r.auth_source == "untrusted"
    assert (r.spf, r.dkim, r.dmarc) == ("unverified", "unverified", "unverified")
    assert "auth_unverified" in r.codes
    # The same header IS trusted if that server is the configured one.
    trusted = check_headers(
        parse_email_file(FIXTURES / "phish_untrusted_pass.eml"),
        trusted_authserv_id="relay.attacker.test",
    )
    assert trusted.dmarc == "pass"


def test_bec_from_freemail():
    r = report_for("phish_bec_freemail.eml")
    assert r.dmarc == "pass"  # gmail.com itself authenticates fine...
    assert {"freemail_impersonation", "display_name_other_email", "undisclosed_recipients"} <= (
        r.codes
    )  # ...but the display name lies about who is writing


def test_untrusted_failures_still_count():
    raw = (
        b"Authentication-Results: some.relay.test; dmarc=fail header.from=example.com\r\n"
        b"From: a@example.com\r\nTo: b@example.org\r\nMessage-ID: <1@x>\r\n\r\nhi"
    )
    r = check_headers(parse_email(raw))
    assert r.dmarc == "fail"
    assert "dmarc_fail" in r.codes


def test_missing_auth_and_from():
    r = check_headers(parse_email(b"Subject: hi\r\n\r\nbody"))
    assert {"auth_unverified", "missing_from", "missing_message_id"} <= r.codes


def test_bulk_recipients():
    to = ", ".join(f"u{i}@example.org" for i in range(12)).encode()
    r = check_headers(parse_email(b"From: a@example.com\r\nTo: " + to + b"\r\n\r\nhi"))
    assert "bulk_recipients" in r.codes


def test_freemail_reply_to_redirect():
    raw = (
        b"From: Billing <billing@example.com>\r\nReply-To: billing.dept@gmail.com\r\n"
        b"To: b@example.org\r\n\r\nhi"
    )
    r = check_headers(parse_email(raw))
    assert {"reply_to_mismatch", "reply_to_freemail"} <= r.codes


def test_official_brand_sender_not_flagged_for_brand_name():
    raw = (
        b"From: Amazon.in <order-update@amazon.in>\r\nReturn-Path: <bounce@amazonses.com>\r\n"
        b"To: b@example.org\r\nMessage-ID: <1@amazon.in>\r\n\r\nhi"
    )
    r = check_headers(parse_email(raw))
    assert not {"display_name_brand_spoof", "lookalike_sender_domain", "return_path_mismatch"} & (
        r.codes
    )


def test_auth_comment_text_cannot_inject_results():
    # "dmarc=pass" inside a (comment) must be ignored.
    value = "mx.google.com; spf=fail (sender claims dmarc=pass) smtp.mailfrom=x@y.test"
    assert parse_auth_results(value) == {"spf": "fail"}
    assert authserv_id("mx.google.com 1; spf=pass") == "mx.google.com"


def test_features_have_stable_columns():
    clean = report_for("legit_newsletter.eml").features()
    phish = report_for("phish_spoofed_sender.eml").features()
    assert clean.keys() == phish.keys()
    assert all(f"hdr_{code}" in clean for code in WEIGHTS)
    assert phish["hdr_dmarc_fail"] == 1.0 and clean["hdr_dmarc_fail"] == 0.0


def test_findings_are_deduplicated():
    raw = (
        b"From: a@example.com\r\nReply-To: x@other.test, y@other.test\r\n"
        b"To: b@example.org\r\n\r\nhi"
    )
    r = check_headers(parse_email(raw))
    assert [f.code for f in r.findings].count("reply_to_mismatch") == 1


def test_forwarded_mail_with_consistent_headers_not_forged():
    raw = (
        b"Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=a@example.com;"
        b" dkim=pass header.i=@example.com; dmarc=pass header.from=example.com\r\n"
        b"Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=a@example.com;"
        b" dmarc=pass header.from=example.com\r\n"
        b"From: a@example.com\r\nTo: b@example.org\r\nMessage-ID: <1@x>\r\n\r\nhi"
    )
    r = check_headers(parse_email(raw))
    assert "forged_auth_header" not in r.codes
    assert r.risk == 0.0


def test_regexes_fast_on_hostile_header_values():
    import time

    hostile = "a" * 900 + "@" + "b." * 40 + "!"
    raw = (
        f"Authentication-Results: mx.google.com; {'(' * 400}spf=pass{')' * 400}\r\n"
        f'From: "{hostile}" <x@example.com>\r\n\r\nhi'
    ).encode()
    start = time.perf_counter()
    check_headers(parse_email(raw))
    assert time.perf_counter() - start < 0.5
