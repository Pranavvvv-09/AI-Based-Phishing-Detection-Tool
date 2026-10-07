"""Offline domain helpers shared by the header (Day 3) and URL (Day 4) checks.

No function in this module performs DNS lookups or network requests. ``tldextract``
downloads the Public Suffix List on first use by default; we disable that and use
its bundled snapshot so analysis stays fully offline.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

import tldextract

# suffix_list_urls=() + cache_dir=None -> bundled snapshot only, never the network.
# "bank.in" is RBI's bank-only zone (2025), newer than the bundled snapshot.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, extra_suffixes=("bank.in",))

# Official registered domains for brands commonly impersonated (global + India).
# Extend at runtime with ``load_extra_brands`` (config: EXTRA_BRANDS_FILE).
BRANDS: dict[str, frozenset[str]] = {
    # --- global tech, payments, social ---
    "paypal": frozenset({"paypal.com", "paypal.me"}),
    "amazon": frozenset(
        {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonses.com", "amazonaws.com"}
    ),
    "microsoft": frozenset(
        {
            "microsoft.com", "outlook.com", "live.com", "office.com", "office365.com",
            "microsoftonline.com", "sharepoint.com", "onedrive.com", "msn.com",
        }
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
    "twitter": frozenset({"twitter.com", "x.com"}),
    "adobe": frozenset({"adobe.com"}),
    "dropbox": frozenset({"dropbox.com", "dropboxmail.com"}),
    "docusign": frozenset({"docusign.com", "docusign.net"}),
    "zoom": frozenset({"zoom.us", "zoom.com"}),
    "spotify": frozenset({"spotify.com"}),
    "coinbase": frozenset({"coinbase.com"}),
    "binance": frozenset({"binance.com"}),
    "metamask": frozenset({"metamask.io"}),
    "chase": frozenset({"chase.com"}),
    "wellsfargo": frozenset({"wellsfargo.com"}),
    "bankofamerica": frozenset({"bankofamerica.com", "bofa.com"}),
    "usaa": frozenset({"usaa.com"}),
    # --- couriers ---
    "dhl": frozenset({"dhl.com"}),
    "fedex": frozenset({"fedex.com"}),
    "ups": frozenset({"ups.com"}),
    "usps": frozenset({"usps.com"}),
    "bluedart": frozenset({"bluedart.com"}),
    "delhivery": frozenset({"delhivery.com"}),
    "indiapost": frozenset({"indiapost.gov.in"}),
    # --- Indian banks, payments, government (common scam targets) ---
    "sbi": frozenset({"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"}),
    "hdfc": frozenset({"hdfcbank.com", "hdfc.bank.in"}),
    "icici": frozenset({"icicibank.com", "icici.bank.in"}),
    "axis": frozenset({"axisbank.com", "axis.bank.in"}),
    "kotak": frozenset({"kotak.com"}),
    "pnb": frozenset({"pnbindia.in"}),
    "bankofbaroda": frozenset({"bankofbaroda.in"}),
    "canarabank": frozenset({"canarabank.com"}),
    "yesbank": frozenset({"yesbank.in"}),
    "paytm": frozenset({"paytm.com"}),
    "phonepe": frozenset({"phonepe.com"}),
    "npci": frozenset({"npci.org.in"}),
    "flipkart": frozenset({"flipkart.com"}),
    "airtel": frozenset({"airtel.in", "airtel.com"}),
    "jio": frozenset({"jio.com"}),
    "irctc": frozenset({"irctc.co.in"}),
    "incometax": frozenset({"incometax.gov.in"}),
    "uidai": frozenset({"uidai.gov.in"}),
    "epfo": frozenset({"epfindia.gov.in"}),
    "rbi": frozenset({"rbi.org.in"}),
    "lic": frozenset({"licindia.in"}),
}

# Phrases in a display name or link text that claim a brand (brand key -> phrases).
BRAND_PHRASES: dict[str, tuple[str, ...]] = {
    **{brand: (brand,) for brand in BRANDS},
    # Not "outlook" or plain "chase": ordinary words / surnames ("Market Outlook", "Chase Lee").
    "microsoft": ("microsoft", "office 365", "microsoft 365", "onedrive", "sharepoint"),
    "chase": ("chase bank", "jpmorgan chase"),
    "google": ("google", "gmail", "google drive", "google pay"),
    "apple": ("apple", "icloud", "apple id"),
    "facebook": ("facebook", "meta"),
    "wellsfargo": ("wells fargo", "wellsfargo"),
    "bankofamerica": ("bank of america", "bankofamerica"),
    "indiapost": ("india post", "indiapost", "speed post"),
    "incometax": ("income tax", "incometax", "income tax department"),
    "sbi": ("sbi", "state bank of india"),
    "axis": ("axis bank",),
    "kotak": ("kotak", "kotak mahindra"),
    "pnb": ("pnb", "punjab national bank"),
    "bankofbaroda": ("bank of baroda", "bankofbaroda"),
    "canarabank": ("canara bank", "canarabank"),
    "yesbank": ("yes bank", "yesbank"),
    "npci": ("npci", "bhim upi"),
    "uidai": ("uidai", "aadhaar"),
    "epfo": ("epfo", "provident fund"),
    "rbi": ("rbi", "reserve bank of india"),
    "lic": ("lic", "life insurance corporation"),
    "twitter": ("twitter",),
}

# Short names that are also ordinary words: only matched as whole tokens, never fuzzily.
_MIN_FUZZY_LEN = 6

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
        # Substring and one-edit typos only for longer names: "paypalsecure"/"paypall"
        # yes, but "applebees"/"apply" (apple) and "paytv" (paytm) are real words.
        if len(brand) >= _MIN_FUZZY_LEN and (brand in shape or _distance_at_most_one(shape, brand)):
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


_BRAND_KEY = re.compile(r"^[a-z0-9]{2,40}$")
_HOSTNAME = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
MAX_EXTRA_BRANDS = 500


def load_extra_brands(path: Path) -> int:
    """Add organisation-specific brands from a JSON file ``{"brand": ["domain", ...]}``.

    The file is untrusted input: size, keys and domains are validated, and nothing
    is executed. Returns the number of brands added or extended.
    """
    path = Path(path)
    if path.stat().st_size > 256 * 1024:
        raise ValueError("extra brands file too large")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or len(data) > MAX_EXTRA_BRANDS:
        raise ValueError("extra brands file must be an object of brand -> domain list")
    added = 0
    for brand, domains in data.items():
        if not isinstance(brand, str) or not _BRAND_KEY.match(brand):
            raise ValueError(f"invalid brand name: {brand!r}")
        if not isinstance(domains, list) or not 1 <= len(domains) <= 50:
            raise ValueError(f"brand {brand!r} needs a list of 1-50 domains")
        clean = {registered_domain(d) for d in domains if isinstance(d, str)}
        if not all(_HOSTNAME.match(d) for d in clean) or len(clean) != len(domains):
            raise ValueError(f"brand {brand!r} has invalid domains")
        BRANDS[brand] = BRANDS.get(brand, frozenset()) | frozenset(clean)
        BRAND_PHRASES.setdefault(brand, (brand,))
        added += 1
    return added
