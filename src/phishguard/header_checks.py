"""Header-based phishing checks: authentication results, spoofing and Reply-To tricks.

Trust model for SPF/DKIM/DMARC
------------------------------
We never do DNS lookups (that would break the no-network rule and let attackers
trigger lookups to domains they control). Instead we read the
``Authentication-Results`` header that the *receiving* mail server already wrote.

Anyone can put a fake ``Authentication-Results: mx.google.com; dmarc=pass`` header in
an email they send. Gmail adds its own header *on top* of whatever the sender
included, so:

* Only the **top-most** header is considered, and only if its authserv-id matches
  ``TRUSTED_AUTHSERV_ID`` (e.g. ``mx.google.com``).
* **Fail** results are counted even from an untrusted header, because attackers
  never forge failures. **Pass** results from an untrusted header are ignored.
* A *second* header claiming to come from the trusted server is evidence of forgery.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .domains import (
    BRANDS,
    FREEMAIL_DOMAINS,
    brands_in_text,
    domain_of,
    lookalike_brand,
    official_brand,
)
from .parser import ParsedEmail

DEFAULT_TRUSTED_AUTHSERV_ID = "mx.google.com"
BULK_RECIPIENTS = 10

_COMMENT = re.compile(r"\([^()]*\)")
_RESULT = re.compile(r"(?<![\w.-])(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_EMAIL_IN_TEXT = re.compile(r"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}")
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")

# Display-name words that claim authority; suspicious when sent from a free mailbox.
ROLE_PHRASES = (
    "ceo", "cfo", "md", "director", "managing director", "hr", "human resources",
    "payroll", "accounts", "finance", "it support", "it department", "helpdesk",
    "help desk", "admin", "administrator", "security", "support", "customer care",
    "bank", "principal", "dean", "registrar", "tax", "police", "court",
)

WEIGHTS = {
    "dmarc_fail": 0.35,
    "spf_fail": 0.20,
    "spf_softfail": 0.10,
    "dkim_fail": 0.15,
    "forged_auth_header": 0.30,
    "auth_unverified": 0.05,
    "reply_to_mismatch": 0.25,
    "reply_to_freemail": 0.10,
    "return_path_mismatch": 0.05,
    "display_name_brand_spoof": 0.35,
    "display_name_other_email": 0.30,
    "freemail_impersonation": 0.25,
    "lookalike_sender_domain": 0.40,
    "punycode_sender_domain": 0.20,
    "bulk_recipients": 0.05,
    "undisclosed_recipients": 0.05,
    "missing_from": 0.20,
    "missing_message_id": 0.05,
}


@dataclass(frozen=True)
class Finding:
    code: str
    weight: float
    detail: str


@dataclass
class HeaderReport:
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    auth_source: str = "missing"  # "trusted" | "untrusted" | "missing"
    findings: list[Finding] = field(default_factory=list)

    @property
    def risk(self) -> float:
        """Rule-based risk in [0, 1] (sum of finding weights, capped)."""
        return round(min(1.0, sum(f.weight for f in self.findings)), 3)

    @property
    def codes(self) -> set[str]:
        return {f.code for f in self.findings}

    def features(self) -> dict[str, float]:
        """Numeric features for the ML model / scorer (one column per check)."""
        feats = {f"hdr_{code}": 0.0 for code in WEIGHTS}
        for finding in self.findings:
            feats[f"hdr_{finding.code}"] = 1.0
        feats["hdr_auth_trusted"] = 1.0 if self.auth_source == "trusted" else 0.0
        feats["hdr_risk"] = self.risk
        return feats

    def add(self, code: str, detail: str) -> None:
        if code not in self.codes:
            self.findings.append(Finding(code, WEIGHTS[code], detail))


def authserv_id(header_value: str) -> str:
    """First token of an Authentication-Results header (the server that wrote it)."""
    return header_value.split(";", 1)[0].strip().split(" ", 1)[0].lower()


def parse_auth_results(header_value: str) -> dict[str, str]:
    """Extract spf/dkim/dmarc results. Comments like ``(...)`` are ignored."""
    text = _COMMENT.sub(" ", _COMMENT.sub(" ", header_value))
    found: dict[str, list[str]] = {}
    for method, result in _RESULT.findall(text):
        found.setdefault(method.lower(), []).append(result.lower())
    summary = {}
    for method, results in found.items():
        # Several DKIM signatures are common: one valid signature is enough.
        if "pass" in results:
            summary[method] = "pass"
        elif "fail" in results:
            summary[method] = "fail"
        else:
            summary[method] = results[0]
    return summary


def _words(text: str) -> str:
    return " " + " ".join(t for t in _TOKEN_SPLIT.split(text.lower()) if t) + " "


def _check_authentication(email: ParsedEmail, report: HeaderReport, trusted_id: str) -> None:
    headers = email.authentication_results
    if not headers:
        report.add("auth_unverified", "No Authentication-Results header (origin unverifiable)")
        return

    top = headers[0]
    trusted = authserv_id(top) == trusted_id
    report.auth_source = "trusted" if trusted else "untrusted"
    results = parse_auth_results(top)
    if "spf" not in results and email.received_spf:
        spf_word = email.received_spf[0].split(" ", 1)[0].lower()
        if spf_word.isalpha():
            results["spf"] = spf_word

    for method in ("spf", "dkim", "dmarc"):
        value = results.get(method, "none")
        if value == "pass" and not trusted:
            value = "unverified"  # a pass claim we can't trust
        setattr(report, method, value)

    if not trusted:
        report.add("auth_unverified", f"Top Authentication-Results not from {trusted_id}")
    # Forwarded mail can legitimately carry an older header from the same provider, so
    # only flag the forgery signature: a lower header *claiming a pass* the top one denies.
    for lower in headers[1:]:
        if authserv_id(lower) != trusted_id:
            continue
        claimed = parse_auth_results(lower)
        if any(claimed.get(m) == "pass" and results.get(m) != "pass" for m in claimed):
            report.add(
                "forged_auth_header",
                f"A lower header falsely claims {trusted_id} passed this message",
            )
            break

    if report.dmarc == "fail":
        report.add("dmarc_fail", "DMARC failed: the From domain did not authorise this sender")
    if report.spf in ("fail", "permerror"):
        report.add("spf_fail", "SPF failed: sending server not allowed for this domain")
    elif report.spf == "softfail":
        report.add("spf_softfail", "SPF soft-failed: sending server probably not authorised")
    if report.dkim in ("fail", "permerror"):
        report.add("dkim_fail", "DKIM signature invalid: message may have been altered")


def _check_sender(email: ParsedEmail, report: HeaderReport) -> None:
    from_domain = domain_of(email.from_address)
    if not from_domain:
        report.add("missing_from", "No valid From address")
        return

    host = email.from_address.rpartition("@")[2]
    if any(label.startswith("xn--") for label in host.split(".")):
        report.add("punycode_sender_domain", f"Sender domain uses punycode: {host}")
    imitated = lookalike_brand(from_domain)
    if imitated:
        report.add(
            "lookalike_sender_domain",
            f"Sender domain {from_domain} imitates {imitated} but is not an official domain",
        )

    display = email.from_display
    for brand in brands_in_text(display):
        if from_domain not in BRANDS[brand]:
            report.add(
                "display_name_brand_spoof",
                f"Display name claims '{brand}' but the address is @{from_domain}",
            )
            break

    for embedded in _EMAIL_IN_TEXT.findall(display):
        if domain_of(embedded.lower()) != from_domain:
            report.add(
                "display_name_other_email",
                f"Display name shows a different address ({embedded}) than the real sender",
            )
            break

    if from_domain in FREEMAIL_DOMAINS:
        words = _words(display)
        if any(f" {phrase} " in words for phrase in ROLE_PHRASES):
            report.add(
                "freemail_impersonation",
                f"Display name claims an official role but is sent from free mail (@{from_domain})",
            )

    for reply in email.reply_to:
        reply_domain = domain_of(reply)
        if reply_domain and reply_domain != from_domain:
            report.add(
                "reply_to_mismatch",
                f"Replies go to @{reply_domain}, not the sender's domain @{from_domain}",
            )
            if reply_domain in FREEMAIL_DOMAINS and from_domain not in FREEMAIL_DOMAINS:
                report.add(
                    "reply_to_freemail", f"Replies are redirected to free mail @{reply_domain}"
                )
            break

    return_domain = domain_of(email.return_path)
    # Weak signal: newsletters and big brands legitimately bounce via their mailing
    # provider's domain, so official brand senders are skipped entirely.
    if return_domain and return_domain != from_domain and not official_brand(from_domain):
        report.add(
            "return_path_mismatch",
            f"Bounce address @{return_domain} differs from sender @{from_domain}",
        )


def _check_recipients(email: ParsedEmail, report: HeaderReport) -> None:
    if email.recipient_count >= BULK_RECIPIENTS:
        report.add("bulk_recipients", f"Sent to {email.recipient_count} visible recipients")
    elif email.recipient_count == 0:
        report.add("undisclosed_recipients", "No visible recipients (hidden BCC mass mailing)")
    if not email.message_id:
        report.add("missing_message_id", "Message-ID header missing")


def check_headers(
    email: ParsedEmail, trusted_authserv_id: str = DEFAULT_TRUSTED_AUTHSERV_ID
) -> HeaderReport:
    """Run all header checks on a parsed email."""
    report = HeaderReport()
    _check_authentication(email, report, trusted_authserv_id.lower())
    _check_sender(email, report)
    _check_recipients(email, report)
    return report
