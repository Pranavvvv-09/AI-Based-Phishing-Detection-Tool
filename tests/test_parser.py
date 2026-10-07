import base64
from pathlib import Path

import pytest

from phishguard.parser import (
    MAX_DEPTH,
    MAX_LINKS,
    MAX_PARTS,
    MAX_TEXT_CHARS,
    EmailParseError,
    EmailTooLargeError,
    parse_email,
    parse_email_file,
)

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str):
    return parse_email_file(FIXTURES / name)


# ---------- normal behaviour ----------


def test_legit_email_basic_fields():
    e = load("legit_newsletter.eml")
    assert e.subject == "Your weekly newsletter"
    assert e.from_display == "Example News"
    assert e.from_address == "news@example.com"
    assert e.to == ["student@example.org"]
    assert e.recipient_count == 1
    assert "dmarc=pass" in e.authentication_results[0]
    assert e.received_spf[0].startswith("pass")
    assert any(link.href == "https://www.example.com/news/42" for link in e.links)
    assert not e.truncated


def test_phish_headers_and_recipients():
    e = load("phish_spoofed_sender.eml")
    assert e.from_display == "PayPal Security"
    assert e.from_address == "service@paypal-secure.test"
    assert e.reply_to == ["recover-account@freemail.test"]
    assert e.return_path == "bounce@mailer.test"
    assert e.recipient_count == 3
    assert "dmarc=fail" in e.authentication_results[0]


def test_html_links_keep_display_text_and_href_separate():
    e = load("phish_spoofed_sender.eml")
    anchors = [link for link in e.links if link.source == "html"]
    assert anchors[0].href == "http://xn--pypal-4ve.test/verify"
    assert anchors[0].text == "https://www.paypal.com/security"  # the mismatch Day 4 will flag


def test_form_action_and_text_urls_extracted():
    e = load("phish_spoofed_sender.eml")
    sources = {(link.source, link.href) for link in e.links}
    assert ("form", "http://192.0.2.55/collect") in sources
    assert ("text", "http://192.0.2.55/paypal/login") in sources


def test_script_and_style_never_appear_in_text():
    e = load("phish_spoofed_sender.eml")
    assert "alert" not in e.html_text
    assert "color:red" not in e.html_text
    assert "unusual activity" in e.html_text


def test_attachments_metadata_only():
    e = load("phish_attachment.eml")
    names = {a.filename: a for a in e.attachments}
    assert names["salary.html"].content_type == "text/html"
    assert names["salary.html"].size > 0
    # Hostile filename is kept only as a label; it's never used as a path.
    assert "../../etc/passwd" in names
    assert "attached document" in e.text_body
    assert "Fake login page" not in e.body  # attachment content isn't treated as body


# ---------- hostile / malformed input ----------


def test_malformed_email_does_not_crash():
    e = load("malformed.eml")
    assert e.defects  # problems are recorded, not raised
    assert isinstance(e.body, str)


def test_unknown_charset_falls_back():
    raw = (
        b"From: a@example.com\r\nSubject: hi\r\n"
        b"Content-Type: text/plain; charset=x-made-up\r\n\r\nhello world\r\n"
    )
    e = parse_email(raw)
    assert "hello world" in e.text_body
    assert "unknown_charset" in e.defects


def test_size_limit_enforced_before_parsing():
    with pytest.raises(EmailTooLargeError):
        parse_email(b"A" * 2_000, max_bytes=1_000)


def test_file_size_checked_before_reading(tmp_path):
    big = tmp_path / "big.eml"
    big.write_bytes(b"From: a@example.com\r\n\r\n" + b"x" * 5_000)
    with pytest.raises(EmailTooLargeError):
        parse_email_file(big, max_bytes=1_000)


@pytest.mark.parametrize("raw", [b"", b"   \r\n  "])
def test_empty_input_rejected(raw):
    with pytest.raises(EmailParseError):
        parse_email(raw)


def test_non_bytes_rejected():
    with pytest.raises(TypeError):
        parse_email("From: a@example.com")  # type: ignore[arg-type]


def test_crlf_in_encoded_header_is_neutralised():
    evil = base64.b64encode(b"Hello\r\nX-Injected: yes").decode()
    raw = f"From: a@example.com\r\nSubject: =?utf-8?b?{evil}?=\r\n\r\nbody\r\n".encode()
    e = parse_email(raw)
    assert "\r" not in e.subject and "\n" not in e.subject
    assert e.subject == "Hello X-Injected: yes"


def test_too_many_parts_is_capped():
    parts = "".join(
        f"--b\r\nContent-Type: text/plain\r\n\r\npart {i}\r\n" for i in range(MAX_PARTS * 3)
    )
    raw = (
        "From: a@example.com\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" + parts + "--b--"
    ).encode()
    e = parse_email(raw)
    assert e.truncated
    assert "too_many_parts" in e.defects


def test_deep_nesting_is_capped_without_recursion_error():
    depth = 60
    head = "From: a@example.com\r\nContent-Type: multipart/mixed; boundary=b0\r\n\r\n"
    body = ""
    for i in range(1, depth):
        body += f"--b{i - 1}\r\nContent-Type: multipart/mixed; boundary=b{i}\r\n\r\n"
    body += f"--b{depth - 1}\r\nContent-Type: text/plain\r\n\r\ndeep\r\n"
    for i in reversed(range(depth)):
        body += f"--b{i}--\r\n"
    e = parse_email((head + body).encode())
    assert "nesting_too_deep" in e.defects
    assert depth > MAX_DEPTH


def test_text_budget_caps_huge_bodies():
    raw = b"From: a@example.com\r\nContent-Type: text/plain\r\n\r\n" + b"word " * 100_000
    e = parse_email(raw)
    assert len(e.body) <= MAX_TEXT_CHARS
    assert e.truncated


def test_link_count_is_capped():
    anchors = "".join(f'<a href="https://e{i}.example.com/">x</a>' for i in range(MAX_LINKS + 50))
    raw = (
        "From: a@example.com\r\nContent-Type: text/html\r\n\r\n<html>" + anchors + "</html>"
    ).encode()
    e = parse_email(raw)
    assert len(e.links) == MAX_LINKS
    assert e.truncated


def test_body_not_exposed_in_repr():
    e = load("phish_spoofed_sender.eml")
    text = repr(e)
    assert "unusual activity" not in text
    assert "192.0.2.55" not in text


def test_url_regex_is_fast_on_pathological_input():
    import time

    raw = b"From: a@example.com\r\n\r\n" + b"http://" + b"a" * 150_000
    start = time.perf_counter()
    parse_email(raw)
    assert time.perf_counter() - start < 1.0  # no catastrophic backtracking


# ---------- regressions from self-review ----------


def test_anchor_display_text_is_not_a_link():
    e = load("phish_spoofed_sender.eml")
    hrefs = [link.href for link in e.links]
    assert "https://www.paypal.com/security" not in hrefs  # it's only the visible text


def test_huge_recipient_list_rejected_fast():
    import time

    to = b", ".join(b"u%d@example.com" % i for i in range(100_000))
    raw = b"From: a@example.com\r\nTo: " + to + b"\r\n\r\nhi"
    start = time.perf_counter()
    with pytest.raises(EmailParseError):
        parse_email(raw)
    assert time.perf_counter() - start < 1.0


def test_many_long_address_headers_stay_fast():
    import time

    # Under the header-section cap, but each value is long: must be truncated pre-parse.
    to = b", ".join(b"u%d@example.com" % i for i in range(12_000))
    raw = b"From: a@example.com\r\nTo: " + to + b"\r\n\r\nhi"
    start = time.perf_counter()
    e = parse_email(raw)
    assert time.perf_counter() - start < 2.0
    assert 0 < e.recipient_count < 12_000  # truncated, not fully parsed


def test_mime_part_flood_rejected_fast():
    import time

    parts = "".join("--b\r\n\r\nx\r\n" for _ in range(50_000))
    raw = ("From: a@x.test\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" + parts).encode()
    start = time.perf_counter()
    with pytest.raises(EmailParseError):
        parse_email(raw)
    assert time.perf_counter() - start < 1.0


def test_encoded_display_name_and_folded_headers():
    name = base64.b64encode("PayPal Sécurité".encode()).decode()
    raw = (
        f"From: =?utf-8?b?{name}?= <a@example.com>\r\n"
        "To: one@example.com,\r\n two@example.com\r\n"
        "Subject: folded\r\n  subject line\r\n\r\nhi\r\n"
    ).encode()
    e = parse_email(raw)
    assert e.from_display == "PayPal Sécurité"
    assert e.to == ["one@example.com", "two@example.com"]
    assert e.subject == "folded  subject line"


def test_huge_html_is_bounded():
    import time

    raw = b"From: a@example.com\r\nContent-Type: text/html\r\n\r\n" + b"<div>" * 980_000
    start = time.perf_counter()
    e = parse_email(raw)
    assert time.perf_counter() - start < 1.5
    assert e.truncated


@pytest.mark.parametrize("charset", ["zlib", "base64", "rot13", "hex", "uu", "bogus-123"])
def test_non_text_charsets_never_crash(charset):
    raw = (
        f"From: a@example.com\r\nContent-Type: text/plain; charset={charset}\r\n\r\nhello"
    ).encode()
    e = parse_email(raw)
    assert "hello" in e.text_body
    assert "unknown_charset" in e.defects
