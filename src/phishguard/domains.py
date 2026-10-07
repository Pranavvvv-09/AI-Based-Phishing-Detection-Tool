"""Offline domain helpers shared by the header (Day 3) and URL (Day 4) checks.

No function in this module performs DNS lookups or network requests. ``tldextract``
downloads the Public Suffix List on first use by default; we disable that and use
its bundled snapshot so analysis stays fully offline.
"""

from __future__ import annotations

import ipaddress
import re

import tldextract

# suffix_list_urls=() + cache_dir=None -> bundled snapshot only, never the network.
# "bank.in" is RBI's bank-only zone (2025), newer than the bundled snapshot.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, extra_suffixes=("bank.in",))

# Official registered domains for brands commonly impersonated (global + India).
BRANDS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com", "paypal.me"}),
    "amazon": frozenset(
        {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonses.com", "amazonaws.com"}
    ),
    "microsoft": frozenset(
        {"microsoft.com", "outlook.com", "live.com", "office.com", "microsoftonline.com"}
    ),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "google": frozenset(
        {
            "google.com", "google.co.in", "gmail.com", "googlemail.com", "youtube.com",
            "googleusercontent.com", "gstatic.com", "googleapis.com",
        }
    ),
    "netflix": frozenset({"netflix.com"}),
    "facebook": frozenset({"facebook.com", "facebookmail.com", "meta.com"}),
    "instagram": frozenset({"instagram.com"}),
    "linkedin": frozenset({"linkedin.com"}),
    "whatsapp": frozenset({"whatsapp.com"}),
    "dhl": frozenset({"dhl.com"}),
    "fedex": frozenset({"fedex.com"}),
    "sbi": frozenset({"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"}),
    "hdfc": frozenset({"hdfcbank.com", "hdfc.bank.in"}),
    "icici": frozenset({"icicibank.com", "icici.bank.in"}),
    "axis": frozenset({"axisbank.com", "axis.bank.in"}),
    "paytm": frozenset({"paytm.com"}),
    "phonepe": frozenset({"phonepe.com"}),
    "indiapost": frozenset({"indiapost.gov.in"}),
    "irctc": frozenset({"irctc.co.in"}),
    "incometax": frozenset({"incometax.gov.in"}),
}

# Phrases in a display name that claim a brand (brand key -> phrases).
BRAND_PHRASES: dict[str, tuple[str, ...]] = {
    **{brand: (brand,) for brand in BRANDS},
    "indiapost": ("india post", "indiapost"),
    "incometax": ("income tax", "incometax"),
    "sbi": ("sbi", "state bank of india"),
    "hdfc": ("hdfc",),
    "icici": ("icici",),
    "axis": ("axis bank",),
}

FREEMAIL_DOMAINS = frozenset(
    {
        "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "outlook.com",
        "hotmail.com", "live.com", "aol.com", "icloud.com", "proton.me",
        "protonmail.com", "rediffmail.com", "zoho.com", "gmx.com", "mail.com",
    }
)

# Characters attackers swap in to imitate Latin letters (digits, Cyrillic, Greek...).
_CONFUSABLES = str.maketrans(
    {
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "ӏ": "l", "ο": "o", "ν": "v", "α": "a",
    }
)
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def normalise_host(host: str) -> str:
    """Lower-case, strip whitespace, brackets, port and trailing dot."""
    host = host.strip().lower().strip("[]")
    if host.count(":") == 1:  # host:port (IPv6 has several colons)
        host = host.split(":", 1)[0]
    return host.rstrip(".")


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(normalise_host(host))
    except ValueError:
        return False
    return True


def registered_domain(host: str) -> str:
    """``mail.paypal.co.uk`` -> ``paypal.co.uk``. IPs are returned unchanged.

    Unknown suffixes (e.g. ``.test``) fall back to the last two labels.
    """
    host = normalise_host(host)
    if not host or is_ip(host):
        return host
    ext = _EXTRACT(host)
    if ext.suffix and ext.domain:
        return f"{ext.domain}.{ext.suffix}"
    labels = [label for label in host.split(".") if label]
    return ".".join(labels[-2:])


def domain_of(address: str) -> str:
    """Registered domain of an email address (``""`` if there is no ``@``)."""
    _, at, host = address.rpartition("@")
    return registered_domain(host) if at else ""


def decode_punycode(label: str) -> str:
    """Decode an IDN label such as ``xn--pypal-4ve`` (returns input on failure)."""
    if not label.startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return label


def skeleton(text: str) -> str:
    """Map look-alike characters to Latin letters: ``pаypa1`` -> ``paypal``."""
    text = text.lower().translate(_CONFUSABLES)
    return text.replace("rn", "m").replace("vv", "w")


def _distance_at_most_one(a: str, b: str) -> bool:
    """True if ``a`` and ``b`` differ by at most one insert, delete or substitution."""
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = j = edits = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        edits += 1
        if edits > 1:
            return False
        if len(a) == len(b):
            i += 1
        j += 1
    return edits + (len(b) - j) + (len(a) - i) <= 1


def official_brand(domain: str) -> str | None:
    """Brand whose official domain this is, if any."""
    domain = registered_domain(domain)
    for brand, domains in BRANDS.items():
        if domain in domains:
            return brand
    return None


def lookalike_brand(domain: str) -> str | None:
    """Brand that ``domain`` imitates without being an official domain of it.

    Catches homoglyphs (``pаypal``), typos (``paypall``, ``paypa1``) and brand names
    inside other domains (``paypal-secure.test``, ``sbi-kyc-update.in``).
    """
    domain = registered_domain(domain)
    if not domain or is_ip(domain) or official_brand(domain):
        return None
    label = domain.split(".")[0]
    shape = skeleton(decode_punycode(label))
    tokens = [t for t in _TOKEN_SPLIT.split(shape) if t]
    for brand in BRANDS:
        if shape == brand or brand in tokens:
            return brand
        # Substring match only for longer names: "paypalsecure" yes, "applebees" no.
        if len(brand) >= 6 and brand in shape:
            return brand
        if len(brand) >= 5 and _distance_at_most_one(shape, brand):
            return brand
    return None


def brands_in_text(text: str) -> list[str]:
    """Brands named in free text such as a display name (whole words only)."""
    words = " ".join(t for t in _TOKEN_SPLIT.split(text.lower()) if t)
    padded = f" {words} "
    return [
        brand
        for brand, phrases in BRAND_PHRASES.items()
        if any(f" {phrase} " in padded for phrase in phrases)
    ]
