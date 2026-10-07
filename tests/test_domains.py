import importlib
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


def test_domain_lookup_never_touches_network(no_network):
    fresh = importlib.reload(domains)  # forces a brand-new TLDExtract
    assert fresh.registered_domain("login.secure.paypal.co.uk") == "paypal.co.uk"
    assert fresh.lookalike_brand("paypa1-verify.com") == "paypal"


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
     "gmail.com", "googleusercontent.com", "sbi.co.in", "192.0.2.1"],
)
def test_no_false_lookalikes(domain):
    assert lookalike_brand(domain) is None


def test_brands_in_text_whole_words():
    assert brands_in_text("PayPal Security Team") == ["paypal"]
    assert brands_in_text("India Post Delivery") == ["indiapost"]
    assert "sbi" in brands_in_text("State Bank of India")
    assert brands_in_text("Sbinder Newsletter") == []
