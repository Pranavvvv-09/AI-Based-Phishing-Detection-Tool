"""Link and attachment checks. Purely lexical: no URL is ever fetched or resolved.

Why never fetch?
  * Visiting a phishing link can trigger drive-by downloads or exploit the scanner.
  * The request tells the attacker "this address is live and someone opened it".
  * Fetching attacker-chosen URLs from a server is SSRF: a link to
    ``http://169.254.169.254/`` or ``http://localhost:8080/admin`` would make *our*
    machine attack internal services.
So everything here works on the URL string alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import SplitResult, unquote, urlsplit

from .domains import (
    BRANDS,
    brands_in_text,
    decode_punycode,
    is_ip,
    lookalike_brand,
    normalise_host,
    official_brand,
    registered_domain,
)
from .parser import Attachment, Link, ParsedEmail

MAX_URLS_CHECKED = 100

SHORTENERS = frozenset(
    {
        "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly",
        "rb.gy", "shorturl.at", "tiny.cc", "buff.ly", "rebrand.ly", "s.id", "t.ly", "v.gd",
        "shorte.st", "bl.ink", "short.io",
    }
)
# Free site builders / tunnels often used to host throwaway credential pages.
FREE_HOSTING = frozenset(
    {
        "000webhostapp.com", "weebly.com", "wixsite.com", "firebaseapp.com", "web.app",
        "github.io", "pages.dev", "netlify.app", "vercel.app", "glitch.me", "blogspot.com",
        "ngrok-free.app", "ngrok.io", "trycloudflare.com", "workers.dev", "r2.dev", "ipfs.io",
        "square.site", "godaddysites.com", "webflow.io", "framer.app", "duckdns.org",
    }
)
# TLDs with a high share of abuse in public phishing reports (cheap or free to register).
RISKY_TLDS = frozenset(
    {
        "zip", "mov", "top", "xyz", "click", "link", "cfd", "sbs", "rest", "icu", "buzz",
        "quest", "cam", "monster", "gq", "tk", "ml", "cf", "ga", "work", "support", "live",
    }
)
# Email service providers' click-tracking redirectors: legitimate newsletters show
# "www.brand.com" but link via these, so a text/target mismatch is expected there.
ESP_TRACKING = frozenset(
    {
        "sendgrid.net", "list-manage.com", "mailchimp.com", "mcusercontent.com",
        "mandrillapp.com", "awstrack.me", "mailgun.org", "hubspotlinks.com", "hs-sites.com",
        "exacttarget.com", "rs6.net", "cmail19.com", "cmail20.com", "klclick.com",
        "sparkpostmail.com", "mlsend.com", "brevo.com", "sendibt3.com",
    }
)
DANGEROUS_SCHEMES = frozenset({"javascript", "data", "vbscript", "file"})
IGNORED_SCHEMES = frozenset({"mailto", "tel", "sms", "cid", "about"})
CREDENTIAL_WORDS = frozenset(
    {
        "login", "signin", "sign-in", "logon", "verify", "verification", "secure", "account",
        "update", "password", "passwd", "kyc", "banking", "wallet", "unlock", "suspended",
        "confirm", "billing", "invoice", "otp", "auth",
    }
)

EXECUTABLE_EXT = frozenset(
    {
        "exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "ps1", "msi", "jar", "hta",
        "lnk", "wsf", "cpl", "com", "dll", "iso", "img", "vhd", "vhdx", "apk", "reg", "msc",
    }
)
HTML_EXT = frozenset({"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"})
MACRO_EXT = frozenset({"docm", "xlsm", "pptm", "xlam", "dotm", "xltm", "ppam"})
ARCHIVE_EXT = frozenset({"zip", "rar", "7z", "gz", "tar", "ace", "cab", "arj", "xz", "bz2"})
DOCUMENT_EXT = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "png"})

WEIGHTS = {
    # per-URL
    "url_dangerous_scheme": 0.40,
    "url_ip_host": 0.30,
    "url_obfuscated_ip": 0.40,
    "url_at_symbol": 0.35,
    "url_obfuscated_host": 0.25,
    "url_punycode": 0.30,
    "url_lookalike_domain": 0.40,
    "url_brand_outside_domain": 0.30,
    "url_shortener": 0.10,
    "url_free_hosting": 0.15,
    "url_risky_tld": 0.10,
    "url_http_only": 0.05,
    "url_many_subdomains": 0.10,
    "url_nonstandard_port": 0.10,
    "url_credential_words": 0.10,
    "url_long": 0.05,
    "url_malformed": 0.10,
    # email-level link checks
    "link_text_mismatch": 0.45,
    "link_text_brand_mismatch": 0.25,
    "form_in_email": 0.35,
    # attachments
    "att_executable": 0.50,
    "att_html": 0.35,
    "att_macro": 0.35,
    "att_double_extension": 0.30,
    "att_rtlo_filename": 0.40,
    "att_archive": 0.15,
}

_NUMERIC_LABEL = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)$", re.IGNORECASE)
_DOMAIN_IN_TEXT = re.compile(
    r"(?:https?://)?((?:[a-z0-9-]{1,63}\.){1,10}[a-z]{2,24})(?![a-z0-9-])", re.IGNORECASE
)
_PATH_TOKENS = re.compile(r"[^a-z0-9-]+")
_RTLO = "\u202e"  # escaped on purpose: raw bidi chars in source are "Trojan Source"
# Bidirectional/invisible controls that make text *display* differently than it reads.
_BIDI_CONTROLS = re.compile("[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


@dataclass(frozen=True)
class UrlResult:
    url: str
    host: str
    domain: str  # registered domain
    codes: tuple[str, ...]


@dataclass
class LinkReport:
    urls: list[UrlResult] = field(default_factory=list)
    findings: dict[str, str] = field(default_factory=dict)  # code -> example detail

    @property
    def codes(self) -> set[str]:
        return set(self.findings)

    @property
    def risk(self) -> float:
        return round(min(1.0, sum(WEIGHTS[c] for c in self.findings)), 3)

    def add(self, code: str, detail: str) -> None:
        self.findings.setdefault(code, detail)

    def features(self) -> dict[str, float]:
        feats = {f"lnk_{code}": 0.0 for code in WEIGHTS}
        for code in self.findings:
            feats[f"lnk_{code}"] = 1.0
        feats["lnk_url_count"] = float(len(self.urls))
        feats["lnk_domain_count"] = float(len({u.domain for u in self.urls if u.domain}))
        feats["lnk_risk"] = self.risk
        return feats


def _split(url: str) -> tuple[SplitResult | None, bool]:
    """Parse a URL; returns (parts, scheme_was_added) for scheme-less ``www.`` URLs."""
    url = url.strip()
    added = url.lower().startswith("www.")
    if added:
        url = "http://" + url
    try:
        return urlsplit(url), added
    except ValueError:  # e.g. malformed IPv6 literal
        return None, added


def _is_obfuscated_ip(host: str) -> bool:
    """Hosts browsers treat as IPs but that don't look like one: 3232235777, 0x7f.1, 0177.0.0.1."""
    labels = host.split(".")
    if not 1 <= len(labels) <= 4 or not all(_NUMERIC_LABEL.match(lb) for lb in labels):
        return False
    return not is_ip(host) or any(
        lb.lower().startswith("0x") or (len(lb) > 1 and lb.startswith("0")) for lb in labels
    )


def check_url(url: str) -> UrlResult:
    """Lexical risk checks for one URL. Never performs network access."""
    codes: list[str] = []
    parts, scheme_added = _split(url)
    if parts is None:
        return UrlResult(url=url, host="", domain="", codes=("url_malformed",))

    scheme = parts.scheme.lower()
    if scheme in DANGEROUS_SCHEMES:
        return UrlResult(url=url, host="", domain="", codes=("url_dangerous_scheme",))
    if scheme not in ("http", "https"):
        return UrlResult(url=url, host="", domain="", codes=())

    netloc = parts.netloc
    if _BIDI_CONTROLS.search(url):
        codes.append("url_obfuscated_host")
    if "@" in netloc:
        codes.append("url_at_symbol")  # https://paypal.com@evil.test -> host is evil.test
    if "\\" in netloc or "%" in netloc:
        codes.append("url_obfuscated_host")

    host = normalise_host(unquote(parts.hostname or ""))
    if not host:
        return UrlResult(url=url, host="", domain="", codes=(*codes, "url_malformed"))

    if _is_obfuscated_ip(host):
        codes.append("url_obfuscated_ip")
    elif is_ip(host):
        codes.append("url_ip_host")

    looks_like_ip = is_ip(host) or _is_obfuscated_ip(host)
    domain = host if looks_like_ip else registered_domain(host)
    if not looks_like_ip:
        ascii_host = host
        if not host.isascii():  # raw Unicode IDN, e.g. Cyrillic letters
            try:
                ascii_host = host.encode("idna").decode("ascii")
            except UnicodeError:
                codes.append("url_malformed")
        if any(label.startswith("xn--") for label in ascii_host.split(".")):
            codes.append("url_punycode")
        if lookalike_brand(domain):
            codes.append("url_lookalike_domain")
        else:
            # Brand named in a subdomain or path of a non-brand site:
            # paypal.com.account-check.test, evil.test/paypal/login
            subdomain = host[: -len(domain)] if host.endswith(domain) else host
            for brand in brands_in_text(f"{subdomain} {unquote(parts.path)}"):
                if domain not in BRANDS[brand]:
                    codes.append("url_brand_outside_domain")
                    break
        if domain in SHORTENERS:
            codes.append("url_shortener")
        if domain in FREE_HOSTING:
            codes.append("url_free_hosting")
        if host.rsplit(".", 1)[-1] in RISKY_TLDS:
            codes.append("url_risky_tld")
        if host.count(".") - domain.count(".") >= 4:
            codes.append("url_many_subdomains")

    if scheme == "http" and not scheme_added:
        codes.append("url_http_only")
    try:
        port = parts.port
    except ValueError:
        port = -1
    if port not in (None, 80, 443):
        codes.append("url_nonstandard_port")
    words = set(_PATH_TOKENS.split(unquote(f"{parts.path} {parts.query}").lower()))
    if words & CREDENTIAL_WORDS and not official_brand(domain):
        codes.append("url_credential_words")
    if len(url) > 100:
        codes.append("url_long")

    return UrlResult(url=url, host=host, domain=domain, codes=tuple(dict.fromkeys(codes)))


def _shown_domain(text: str) -> str:
    """Registered domain a link's visible text claims to go to ('' if it shows none)."""
    match = _DOMAIN_IN_TEXT.search(text)
    return registered_domain(decode_punycode(match.group(1))) if match else ""


def _check_link_text(link: Link, result: UrlResult, report: LinkReport) -> None:
    if link.source != "html" or not result.domain:
        return
    shown = _shown_domain(link.text)
    if shown and shown != result.domain and result.domain not in ESP_TRACKING:
        report.add(
            "link_text_mismatch",
            f"Link text shows {shown} but actually goes to {result.domain}",
        )
        return
    for brand in brands_in_text(link.text):
        if result.domain not in BRANDS[brand]:
            report.add(
                "link_text_brand_mismatch",
                f"Link text mentions {brand} but goes to {result.domain}",
            )
            return


def check_attachment(attachment: Attachment) -> list[str]:
    name = attachment.filename.lower().strip().rstrip(".")
    codes = []
    if _RTLO in name:
        codes.append("att_rtlo_filename")  # "invoice\u202efdp.exe" displays as "invoiceexe.pdf"
        name = name.replace(_RTLO, "")
    parts = name.rsplit(".", 2)
    ext = parts[-1] if len(parts) > 1 else ""
    if ext in EXECUTABLE_EXT:
        codes.append("att_executable")
    elif ext in HTML_EXT or (not ext and attachment.content_type in ("text/html", "image/svg+xml")):
        codes.append("att_html")
    elif ext in MACRO_EXT:
        codes.append("att_macro")
    elif ext in ARCHIVE_EXT:
        codes.append("att_archive")
    if len(parts) == 3 and parts[1] in DOCUMENT_EXT and ext not in DOCUMENT_EXT:
        codes.append("att_double_extension")  # invoice.pdf.exe / statement.pdf.html
    return codes


def _detail(code: str, where: str) -> str:
    return f"{code.removeprefix('url_').replace('_', ' ').capitalize()}: {where}"


def check_urls(urls: list[str]) -> LinkReport:
    """Check bare URLs (e.g. extracted from an SMS)."""
    report = LinkReport()
    for url in urls[:MAX_URLS_CHECKED]:
        result = check_url(url)
        report.urls.append(result)
        for code in result.codes:
            report.add(code, _detail(code, result.host or url[:80]))
    return report


def check_links(email: ParsedEmail) -> LinkReport:
    """Check every link and attachment in a parsed email."""
    report = LinkReport()
    for link in email.links[:MAX_URLS_CHECKED]:
        result = check_url(link.href)
        report.urls.append(result)
        for code in result.codes:
            report.add(code, _detail(code, result.host or link.href[:80]))
        _check_link_text(link, result, report)
        if link.source == "form":
            target = result.host or link.href[:80]
            report.add("form_in_email", f"Email contains a form that submits to {target}")
    for attachment in email.attachments:
        for code in check_attachment(attachment):
            report.add(code, f"Risky attachment: {attachment.filename or attachment.content_type}")
    return report
