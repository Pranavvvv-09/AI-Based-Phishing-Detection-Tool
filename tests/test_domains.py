import socket

import pytest

from phishguard import domains
from phishguard.domains import (
    brands_in_text,
    decode_punycode,
    domain_of,
    is_ip,
    lookalike_brand,
    official_brand,
    registered_domain,
)


@pytest.fixture
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)


def test_domain_lookup_never_touches_network(no_network, monkeypatch):
    import tldextract

    # A brand-new extractor configured exactly like the module's: must work offline.
    fresh = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, extra_suffixes=("bank.in",))
    monkeypatch.setattr(domains, "_EXTRACT", fresh)
    assert registered_domain("login.secure.paypal.co.uk") == "paypal.co.uk"
    assert lookalike_brand("paypa1-verify.com") == "paypal"


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("Mail.Example.COM.", "example.com"),
        ("a.b.sbi.co.in", "sbi.co.in"),
        ("netbanking.sbi.bank.in", "sbi.bank.in"),
        ("phish.paypal-secure.test", "paypal-secure.test"),
        ("192.0.2.5", "192.0.2.5"),
        ("example.com:8080", "example.com"),
        ("", ""),
    ],
)
def test_registered_domain(host, expected):
    assert registered_domain(host) == expected


def test_helpers():
    assert is_ip("192.0.2.1") and is_ip("[2001:db8::1]") and not is_ip("example.com")
    assert domain_of("User@Mail.PayPal.com") == "paypal.com"
    assert domain_of("not-an-address") == ""
    assert decode_punycode("xn--pypal-4ve") == "pаypal"  # Cyrillic 'а'
    assert decode_punycode("xn--invalid--") == "xn--invalid--"
    assert official_brand("www.paypal.com") == "paypal"


@pytest.mark.parametrize(
    ("domain", "brand"),
    [
        ("paypal-secure.test", "paypal"),  # brand + extra words
        ("paypalsecure.com", "paypal"),
        ("xn--pypal-4ve.com", "paypal"),  # homoglyph (Cyrillic a)
        ("paypa1.com", "paypal"),  # digit swap
        ("paypall.com", "paypal"),  # typo
        ("rnicrosoft.com", "microsoft"),  # rn -> m
        ("amaz0n.in", "amazon"),
        ("sbi-kyc-update.in", "sbi"),
        ("indiapost-delivery.top", "indiapost"),
    ],
)
def test_lookalikes_detected(domain, brand):
    assert lookalike_brand(domain) == brand


@pytest.mark.parametrize(
    "domain",
    ["paypal.com", "amazon.in", "example.com", "applebees.com", "scrabble.com",
     "gmail.com", "googleusercontent.com", "sbi.co.in", "192.0.2.1",
     # ordinary words one letter away from short brand names
     "apply.com", "paytv.com", "apples.com", "stream.com", "irctv.com", "fedel.com"],
)
def test_no_false_lookalikes(domain):
    assert lookalike_brand(domain) is None


def test_brands_in_text_whole_words():
    assert brands_in_text("PayPal Security Team") == ["paypal"]
    assert brands_in_text("India Post Delivery") == ["indiapost"]
    assert "sbi" in brands_in_text("State Bank of India")
    assert brands_in_text("Sbinder Newsletter") == []


@pytest.mark.parametrize(
    ("domain", "brand"),
    [
        ("app1e.com", "apple"),
        ("flipkart-sale.shop", "flipkart"),
        ("airte1.in", "airtel"),
        ("docusign-review.net", "docusign"),
        ("wellsfargo-alert.com", "wellsfargo"),
        ("kotak-kyc.in", "kotak"),
        ("uidai-aadhaar-update.in", "uidai"),
    ],
)
def test_expanded_brand_lookalikes(domain, brand):
    assert lookalike_brand(domain) == brand


def test_common_words_and_surnames_are_not_brand_claims():
    assert brands_in_text("Weekly Market Outlook") == []
    assert brands_in_text("Chase Miller") == []
    assert brands_in_text("Chase Bank Alerts") == ["chase"]
    assert "uidai" in brands_in_text("Aadhaar Update Team")


@pytest.fixture
def restore_brands():
    brands, phrases = dict(domains.BRANDS), dict(domains.BRAND_PHRASES)
    yield
    domains.BRANDS.clear()
    domains.BRANDS.update(brands)
    domains.BRAND_PHRASES.clear()
    domains.BRAND_PHRASES.update(phrases)


def test_load_extra_brands(tmp_path, restore_brands):
    from phishguard.domains import load_extra_brands

    path = tmp_path / "brands.json"
    path.write_text('{"acmecorp": ["acmecorp.com", "mail.acmecorp.in"]}')
    assert load_extra_brands(path) == 1
    assert official_brand("hr.acmecorp.com") == "acmecorp"
    assert lookalike_brand("acmecorp-payroll.com") == "acmecorp"
    assert brands_in_text("AcmeCorp HR") == ["acmecorp"]


@pytest.mark.parametrize(
    "content",
    [
        "[]",
        '{"Bad Name!": ["x.com"]}',
        '{"acme": "acme.com"}',
        '{"acme": []}',
        '{"acme": ["not a domain"]}',
        '{"acme": ["acme.com", 5]}',
        "not json",
    ],
)
def test_extra_brands_file_is_validated(tmp_path, restore_brands, content):
    from phishguard.domains import load_extra_brands

    path = tmp_path / "brands.json"
    path.write_text(content)
    with pytest.raises(ValueError):
        load_extra_brands(path)


def test_indian_consumer_brands_and_no_typo_matching_for_ordinary_words():
    from phishguard.domains import lookalike_brand, official_brand

    assert official_brand("swiggy.in") == "swiggy" and official_brand("zoma.to") == "zomato"
    assert lookalike_brand("swiggy-account-alerts.com") == "swiggy"
    assert lookalike_brand("zomato-refund.in") == "zomato"
    assert lookalike_brand("tomato.in") is None  # one edit from "zomato", but a real word
    assert lookalike_brand("mantra.com") is None  # one edit from "myntra"
