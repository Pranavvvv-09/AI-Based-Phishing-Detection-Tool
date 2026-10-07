import socket
import time
from pathlib import Path

import pytest

from phishguard.parser import Attachment, extract_urls, parse_email, parse_email_file
from phishguard.url_checks import WEIGHTS, check_attachment, check_links, check_url, check_urls

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)


def codes(url):
    return set(check_url(url).codes)


# ---------- single URLs ----------


@pytest.mark.parametrize(
    "url",
    [
        "https://www.example.com/news/42",
        "https://www.paypal.com/signin",  # official login page is fine
        "https://accounts.google.com/signin",
        "https://sbi.co.in/",
        "https://www.amazon.in/gp/your-account/order-history",
        "mailto:someone@example.com",
        "tel:+911234567890",
    ],
)
def test_clean_urls_have_no_findings(url):
    assert codes(url) == set()


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://paypal.com@evil.test/x", "url_at_symbol"),
        ("http://example.com\\@evil.test/", "url_obfuscated_host"),
        ("http://192.0.2.55/login", "url_ip_host"),
        ("http://[2001:db8::1]/login", "url_ip_host"),
        ("http://3232235777/", "url_obfuscated_ip"),  # decimal 192.168.1.1
        ("http://0x7f.1/", "url_obfuscated_ip"),  # hex
        ("http://0177.0.0.1/", "url_obfuscated_ip"),  # octal
        ("http://xn--pypal-4ve.test/", "url_punycode"),
        ("https://раураl.com/", "url_punycode"),  # raw Cyrillic IDN
        ("https://paypa1-verify.com/", "url_lookalike_domain"),
        ("https://paypal.com.account-check.test/", "url_brand_outside_domain"),
        ("https://evil.test/sbi/kyc/update", "url_brand_outside_domain"),
        ("https://bit.ly/3abc", "url_shortener"),
        ("https://x.netlify.app/", "url_free_hosting"),
        ("https://prize.xyz/", "url_risky_tld"),
        ("http://example.com/", "url_http_only"),
        ("https://a.b.c.d.e.example.com/", "url_many_subdomains"),
        ("https://example.com:8443/", "url_nonstandard_port"),
        ("https://example.com:99999/", "url_nonstandard_port"),
        ("https://example.com/account/verify", "url_credential_words"),
        ("https://example.com/" + "a" * 120, "url_long"),
        ("javascript:alert(1)", "url_dangerous_scheme"),
        ("data:text/html;base64,PGgxPg==", "url_dangerous_scheme"),
        ("http://[::1", "url_malformed"),
    ],
)
def test_risky_urls(url, expected):
    assert expected in codes(url)


def test_at_symbol_reveals_real_host():
    r = check_url("https://www.paypal.com@evil.test/login")
    assert r.host == "evil.test" and r.domain == "evil.test"


def test_scheme_less_www_url_not_called_http_only():
    assert "url_http_only" not in codes("www.example.com/page")


def test_shortener_is_only_a_weak_signal():
    assert WEIGHTS["url_shortener"] <= 0.1  # never an allowlist, never proof either


# ---------- whole emails ----------


def test_spoofed_email_link_findings():
    r = check_links(parse_email_file(FIXTURES / "phish_spoofed_sender.eml"))
    assert {
        "link_text_mismatch",
        "url_lookalike_domain",
        "url_punycode",
        "form_in_email",
        "url_ip_host",
    } <= r.codes
    assert "paypal.com" in r.findings["link_text_mismatch"]
    assert r.risk == 1.0


def test_legit_email_clean():
    r = check_links(parse_email_file(FIXTURES / "legit_newsletter.eml"))
    assert r.codes == set() and r.risk == 0.0
    assert r.urls[0].domain == "example.com"


def test_html_attachment_flagged():
    r = check_links(parse_email_file(FIXTURES / "phish_attachment.eml"))
    assert "att_html" in r.codes


def _html_email(body: str):
    return parse_email(
        ("From: a@example.com\r\nContent-Type: text/html\r\n\r\n" + body).encode()
    )


def test_link_text_brand_mismatch():
    r = check_links(_html_email('<a href="https://login-portal.test/">Sign in to PayPal</a>'))
    assert "link_text_brand_mismatch" in r.codes


def test_matching_link_text_ok():
    r = check_links(_html_email('<a href="https://www.example.com/a">www.example.com</a>'))
    assert "link_text_mismatch" not in r.codes


def test_esp_click_tracking_not_a_mismatch():
    r = check_links(
        _html_email('<a href="https://u123.ct.sendgrid.net/ls/click?x">www.example.com</a>')
    )
    assert "link_text_mismatch" not in r.codes


def test_plain_words_in_link_text_are_not_domains():
    r = check_links(_html_email('<a href="https://evil.test/">Step 1.2 click here.</a>'))
    assert "link_text_mismatch" not in r.codes


def test_features_stable_columns():
    a = check_links(parse_email_file(FIXTURES / "legit_newsletter.eml")).features()
    b = check_links(parse_email_file(FIXTURES / "phish_spoofed_sender.eml")).features()
    assert a.keys() == b.keys()
    assert b["lnk_link_text_mismatch"] == 1.0 and a["lnk_url_count"] == 1.0


def test_sms_style_text_urls():
    text = "SBI: your KYC expires today. Update now at sbi-kyc-update.in/verify or bit.ly/x1"
    urls = extract_urls(text) + ["http://sbi-kyc-update.in/verify"]
    r = check_urls(urls)
    assert {"url_lookalike_domain", "url_credential_words"} <= r.codes


# ---------- attachments ----------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("invoice.pdf.exe", {"att_executable", "att_double_extension"}),
        ("statement.pdf.html", {"att_html", "att_double_extension"}),
        ("lure.svg", {"att_html"}),
        ("report.docm", {"att_macro"}),
        ("inv\u202efdp.exe", {"att_rtlo_filename", "att_executable"}),
        ("files.zip", {"att_archive"}),
        ("photo.jpg", set()),
        ("report.pdf", set()),
        ("", set()),
    ],
)
def test_attachment_types(name, expected):
    assert set(check_attachment(Attachment(name, "application/octet-stream", 10))) == expected


# ---------- safety ----------


def test_checks_never_touch_network(no_network):
    for name in ("phish_spoofed_sender.eml", "legit_newsletter.eml", "phish_attachment.eml"):
        check_links(parse_email_file(FIXTURES / name))
    check_url("https://paypal.com@169.254.169.254/latest/meta-data")


def test_hostile_link_text_is_fast():
    text = ("a-" * 400 + ".") * 2
    start = time.perf_counter()
    check_links(_html_email(f'<a href="https://evil.test/">{text}</a>' * 50))
    assert time.perf_counter() - start < 1.0


def test_url_count_capped():
    links = "".join(f'<a href="https://e{i}.example.com/">x</a>' for i in range(250))
    r = check_links(_html_email(links))
    assert len(r.urls) == 100


def test_bidi_control_characters_flagged():
    assert "url_obfuscated_host" in codes("https://example.com/\u202egnp.exe")
    assert "url_obfuscated_host" in codes("https://exa\u200bmple.com/")
