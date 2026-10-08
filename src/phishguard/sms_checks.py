"""SMS-specific evidence: who sent it, where its links go, and how it asks to be answered.

Emails carry SPF/DKIM/DMARC; SMS carries almost nothing verifiable. What it does carry:

* **The sender** as the phone shows it. Banks, couriers and government services text
  from short codes or alphanumeric sender IDs (in India: DLT headers such as
  ``VM-HDFCBK-S``), never from a personal 10-digit mobile number or an email address
  (iMessage/RCS lets anyone text "from" an email address). So a brand-claiming message
  from such a sender is a strong sign of impersonation.
  An alphanumeric sender ID earns **no** credit: outside India it can be spoofed, and
  spoofed IDs land in the same thread as the real bank's messages.
* **Links vs. the brand named.** "SBI: update KYC at kyc-update.in" names a brand but
  links elsewhere. A message whose every link stays on the named brand's own domains
  earns a small credit: an attacker can't make the real domain serve their page.
* **A way to answer.** Smishing needs the victim to act on *something* in the message:
  a link, a number to call, an address, a reply. A message with none of these
  (a debit alert, a delivery update) earns a small credit. It is capped so that
  confident scam wording still wins, because some scams (OTP theft: "our officer will
  call you") set up the contact later.

Everything here is lexical: nothing is looked up, dialled or fetched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .domains import BRANDS, brands_in_text
from .url_checks import LinkReport

WEIGHTS = {
    "sender_phone_claims_brand": 0.35,
    "sender_email_address": 0.25,
    "sms_brand_link_mismatch": 0.30,
}
NO_CONTACT_CREDIT = 1.0
ALIGNED_SMS_LINKS_CREDIT = 1.0
MAX_SENDER_CHARS = 100

_EMAIL_ADDRESS = re.compile(r"^[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}$")
_EMAIL_IN_TEXT = re.compile(r"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}")
_PHONE_PUNCT = re.compile(r"[\s().-]")
_LONG_NUMBER = re.compile(r"^\+?\d{8,15}$")
_SHORT_CODE = re.compile(r"^\d{3,7}$")
_ALNUM_SENDER = re.compile(r"^(?=.*[A-Za-z])[A-Za-z0-9 _-]{2,20}$")
# A callable number: 8-15 digits, optionally with +country code and spaces/dashes,
# introduced by a word that asks you to use it ("call our officer 98450 22371",
# "SMS BLOCK 4417 to 9215676766"), or written with a leading + (explicitly a phone
# number), or shaped like an Indian mobile number (10 digits starting 6-9).
# Reference numbers ("UPI Ref 6280...", "PNR 4521...") have no such word.
# Bounded quantifiers keep matching linear.
_NUMBER_BODY = r"\+?\d[\d -]{6,18}\d"
_CONTACT_NUMBER = re.compile(
    r"\b(?:call|calls|calling|contact|whatsapp|dial|helpline|executive|officer|agent|"
    r"phone|mobile|number)\b[^\d+\n]{0,25}(" + _NUMBER_BODY + r")"
    r"|\bto\s{1,2}(" + _NUMBER_BODY + r")"
    r"|(?<![\w+])(\+\d[\d -]{6,18}\d)"
    r"|(?<![\w+])((?:91[ -]?)?[6-9]\d{4}[ -]?\d{5})(?![\w])",
    re.IGNORECASE,
)
# "Text WIN to 87121", "reply YES", "reply with your SIM number". Opt-outs ("SMS STOP to
# 1909") and appointment replies ("Reply C to cancel") are how genuine senders talk too,
# but they are also answers: we count every reply/short-code request as a channel.
_REPLY_REQUEST = re.compile(
    r"\b(?:reply|respond|text|txt|sms|send)\b[^.\n]{0,30}\bto\s+\d{3,7}\b"
    r"|\breply\b(?:\s+(?:with|back|yes|no|y|n))?",
    re.IGNORECASE,
)
_MASK = re.compile(r"[Xx*]")


@dataclass(frozen=True)
class SmsFinding:
    code: str
    weight: float
    detail: str


@dataclass
class SmsReport:
    sender_kind: str = "none"  # none | phone | email | short_code | alphanumeric | other
    brands: list[str] = field(default_factory=list)
    contact_channels: list[str] = field(default_factory=list)
    findings: list[SmsFinding] = field(default_factory=list)
    aligned_links: bool = False

    @property
    def codes(self) -> set[str]:
        return {f.code for f in self.findings}

    @property
    def risk(self) -> float:
        return round(min(1.0, sum(f.weight for f in self.findings)), 3)

    def add(self, code: str, detail: str) -> None:
        if code not in self.codes:
            self.findings.append(SmsFinding(code, WEIGHTS[code], detail))


def classify_sender(sender: str) -> str:
    """How the phone shows the sender: phone number, email, short code or sender ID."""
    sender = sender.strip()[:MAX_SENDER_CHARS]
    if not sender:
        return "none"
    if _EMAIL_ADDRESS.match(sender):
        return "email"
    compact = _PHONE_PUNCT.sub("", sender)
    if _LONG_NUMBER.match(compact):
        return "phone"
    if _SHORT_CODE.match(compact):
        return "short_code"
    if _ALNUM_SENDER.match(sender):
        return "alphanumeric"
    return "other"


def contact_channels(text: str, links: LinkReport) -> list[str]:
    """Ways the message asks to be answered: links, numbers to call, addresses, replies."""
    channels: list[str] = []
    if links.urls:
        channels.append("link")
    for match in _CONTACT_NUMBER.finditer(text):
        number = next(group for group in match.groups() if group)
        if not _MASK.search(number) and len(re.sub(r"\D", "", number)) >= 8:
            channels.append("phone_number")
            break
    if _EMAIL_IN_TEXT.search(text):
        channels.append("email_address")
    if _REPLY_REQUEST.search(text):
        channels.append("reply")
    return channels


def check_sms(text: str, sender: str, links: LinkReport) -> SmsReport:
    """Sender, link-vs-brand and contact-channel evidence for one SMS."""
    report = SmsReport(sender_kind=classify_sender(sender), brands=brands_in_text(text))
    report.contact_channels = contact_channels(text, links)
    brand_names = ", ".join(report.brands)

    if report.brands and report.sender_kind == "phone":
        report.add("sender_phone_claims_brand",
                   f"Message names {brand_names} but was sent from a personal phone number")
    if report.sender_kind == "email":
        report.add("sender_email_address",
                   "Sent from an email address (iMessage/RCS), not a phone or business ID")

    if report.brands and links.urls:
        official = frozenset().union(*(BRANDS[b] for b in report.brands))
        domains = {u.domain for u in links.urls if u.domain}
        outside = sorted(d for d in domains if d not in official)
        if outside:
            report.add("sms_brand_link_mismatch",
                       f"Message names {brand_names} but links to {', '.join(outside[:3])}")
        elif domains and not links.codes:
            report.aligned_links = True
    return report
