"""Combine text model, header rules, link rules and trust signals into one verdict.

Evidence fusion in log-odds
---------------------------
Every layer contributes *log-odds* (logit) evidence, and the total is mapped back to
a probability with the sigmoid function::

    logit = clip(logit(text_probability), -4, +4)       # what the wording says
          + 4 x header_risk                              # SPF/DKIM/DMARC, spoofing
          + 4 x link_risk                                # lookalike links, risky files
          - trust_credit                                 # verified official sender
    score = 1 / (1 + e^-logit)

* A rule weight of 1.0 (the cap of a layer) is worth +4 log-odds, enough to turn a
  50/50 message into 98% phishing. One DMARC failure (weight 0.35) is +1.4.
* The text model is clipped to [-4, +4] because TF-IDF + logistic regression is
  over-confident: without the clip, wording alone could veto hard technical
  evidence (a DMARC failure, a lookalike domain, a credential form).
* Trust credits reward only what an attacker cannot fake: DMARC "pass" written by
  *your* mail provider for an *official* brand domain, with no spoofing signs.
  They are capped so that wording can still push a verified sender to "review",
  because scammers abuse real platforms too (fake invoices sent by paypal.com).

Every contribution is returned as a ``Reason`` with its signed weight, so a verdict
can always answer "why?". All parameters are fixed constants chosen before
evaluation, never tuned on test data.

Fail-safe: messages that exceed parse limits, can't be parsed, or hit an internal
error get ``action="review"``, never "deliver".
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Protocol

from .config import Settings, load_settings
from .domains import (
    BRANDS,
    FREEMAIL_DOMAINS,
    domain_of,
    is_ip,
    load_extra_brands,
    official_brand,
)
from .header_checks import HeaderReport, check_headers
from .parser import (
    EmailLimitError,
    EmailParseError,
    ParsedEmail,
    clean_header,
    extract_urls,
    parse_email,
)
from .text_model import MODELS_DIR, ROOT, email_text, load_text_model
from .url_checks import ESP_TRACKING, LinkReport, check_links, check_url
from .url_checks import WEIGHTS as LINK_WEIGHTS

RULE_SCALE = 4.0  # a layer at its maximum risk (1.0) adds +4 log-odds
TEXT_CLIP = 4.0  # text model log-odds limited to [-4, +4]
VERIFIED_SENDER_CREDIT = 2.0
ALIGNED_LINKS_CREDIT = 1.0
REVIEW_THRESHOLD = 0.5
MIN_TEXT_TOKENS = 3
MAX_SMS_CHARS = 5_000
MAX_BARE_DOMAINS = 20
TOP_TERMS = 5

# Invisible/bidirectional characters make attacker-chosen text *display* differently
# than it reads (e.g. a reversed domain). Removed from everything a verdict shows.
_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
MAX_DETAIL_CHARS = 300

# Parser defects meaning part of the message was never analysed (MIME floods/nesting
# are a classic way to hide a payload past scanner limits): never auto-deliver.
_PARTIAL_ANALYSIS = frozenset({"too_many_parts", "nesting_too_deep"})

# Header findings that rule out the "verified sender" trust credit.
_DISQUALIFY_TRUST = frozenset(
    {
        "forged_auth_header", "dmarc_fail", "spf_fail", "dkim_fail",
        "display_name_brand_spoof", "display_name_other_email", "freemail_impersonation",
        "lookalike_sender_domain", "punycode_sender_domain", "reply_to_mismatch",
        "reply_to_freemail",
    }
)
# Bare domains in SMS, e.g. "Update KYC: sbi-kyc-update.in/verify". Bounded quantifiers
# keep matching linear; candidates are validated against the public-suffix list.
_BARE_DOMAIN = re.compile(
    r"(?<![\w@./:-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,4}[a-z]{2,24})"
    r"(/[^\s<>\"']{0,200})?(?![\w-])",
    re.IGNORECASE,
)


class TextScorer(Protocol):
    """What the scorer needs from a text model (``TextModel`` implements it)."""

    def predict_proba(self, text: str) -> float: ...
    def token_count(self, text: str) -> int: ...
    def top_terms(self, text: str, k: int = 5) -> list[tuple[str, float]]: ...


def safe_text(value: object, limit: int = MAX_DETAIL_CHARS) -> str:
    """Display-safe text: no control or invisible/bidi characters, bounded length."""
    return clean_header(_INVISIBLE.sub("", str(value)), limit)


@dataclass(frozen=True)
class Reason:
    source: str  # "text" | "header" | "link" | "trust" | "system"
    code: str
    detail: str
    weight: float  # signed log-odds contribution: + towards phishing, - towards legitimate

    @property
    def strength(self) -> str:
        size = abs(self.weight)
        return "strong" if size >= 2 else "medium" if size >= 1 else "weak"


@dataclass
class Verdict:
    kind: str  # "email" | "sms" | "text"
    score: float | None  # probability of phishing, None when not analysed
    label: str  # "phishing" | "suspicious" | "legitimate" | "unknown"
    action: str  # "quarantine" | "review" | "deliver"
    analysed: bool
    reasons: list[Reason] = field(default_factory=list)
    components: dict[str, float] = field(default_factory=dict)
    summary: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """JSON-safe dict. Every string that may come from the message is sanitised."""
        data = asdict(self)
        data["score"] = None if self.score is None else round(self.score, 4)
        data["reasons"] = [
            {**asdict(r), "detail": safe_text(r.detail), "weight": round(r.weight, 3),
             "strength": r.strength}
            for r in self.reasons
        ]
        data["summary"] = _sanitise(self.summary)
        return data


def _sanitise(value: object) -> object:
    if isinstance(value, str):
        return safe_text(value)
    if isinstance(value, dict):
        return {k: _sanitise(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitise(v) for v in value]
    return value


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def _logit(p: float) -> float:
    p = min(max(p, 1e-9), 1 - 1e-9)
    return math.log(p / (1 - p))


def extract_bare_domains(text: str) -> list[str]:
    """Domains written without http:// or www. (common in smishing), validated offline."""
    from .domains import _EXTRACT  # offline public-suffix snapshot

    found: list[str] = []
    for match in _BARE_DOMAIN.finditer(text[: MAX_SMS_CHARS * 2]):
        host = match.group(1).lower()
        if host.startswith("www.") or is_ip(host):
            continue  # www. URLs are handled by extract_urls
        ext = _EXTRACT(host)
        if not ext.suffix or not ext.domain or len(ext.domain) < 2:
            continue  # "file.txt", "e.g." and friends are not domains
        candidate = host + (match.group(2) or "")
        if candidate not in found:
            found.append(candidate)
        if len(found) >= MAX_BARE_DOMAINS:
            break
    return found


def check_text_links(text: str) -> LinkReport:
    """Link checks for free text (SMS, pasted messages): full URLs plus bare domains."""
    report = LinkReport()
    targets = [(url, False) for url in extract_urls(text)]
    targets += [(bare, True) for bare in extract_bare_domains(text)]
    for target, bare in targets:
        result = check_url(("http://" if bare else "") + target)
        if bare:
            # The writer typed no scheme, so "http only" would be a false finding.
            result = replace(result, url=target,
                             codes=tuple(c for c in result.codes if c != "url_http_only"))
        report.urls.append(result)
        for code in result.codes:
            label = code.removeprefix("url_").replace("_", " ").capitalize()
            report.add(code, f"{label}: {result.host or target[:80]}")
    return report


def _layer_reasons(source: str, items: list[tuple[str, float, str]]) -> list[Reason]:
    """Turn (code, risk weight, detail) findings into log-odds reasons.

    A layer contributes at most RULE_SCALE in total; if its weights add up to more
    than 1.0, every finding is scaled down proportionally.
    """
    total = sum(weight for _, weight, _ in items)
    scale = RULE_SCALE / max(total, 1.0)
    return [Reason(source, code, detail, weight * scale) for code, weight, detail in items]


def _text_reason(model: TextScorer, text: str) -> tuple[Reason, float]:
    probability = model.predict_proba(text)
    weight = max(-TEXT_CLIP, min(TEXT_CLIP, _logit(probability)))
    if model.token_count(text) < MIN_TEXT_TOKENS:
        detail = "Too little readable text to judge the wording"
    elif probability >= 0.5:
        words = ", ".join(f"'{term}'" for term, _ in model.top_terms(text, TOP_TERMS))
        detail = f"Wording resembles phishing ({probability:.0%})"
        detail += f"; strongest words: {words}" if words else ""
    else:
        detail = f"Wording resembles legitimate messages ({1 - probability:.0%} legitimate)"
    return Reason("text", "text_model", detail, weight), probability


def _trust_reasons(email: ParsedEmail, header: HeaderReport, links: LinkReport) -> list[Reason]:
    if header.auth_source != "trusted" or header.dmarc != "pass":
        return []
    if header.codes & _DISQUALIFY_TRUST:
        return []
    sender = domain_of(email.from_address)
    # Free-mail domains (gmail.com, outlook.com, ...) are "official" brand domains, but
    # anyone can register an address there and DMARC passes for every user: no credit.
    if not sender or sender in FREEMAIL_DOMAINS:
        return []
    brand = official_brand(sender)
    if brand is None:
        return []
    reasons = [
        Reason(
            "trust", "verified_sender",
            f"Verified sender: {sender} passed DMARC at your mail provider and is an "
            f"official {brand} domain",
            -VERIFIED_SENDER_CREDIT,
        )
    ]
    link_domains = {u.domain for u in links.urls if u.domain}
    allowed = BRANDS[brand] | ESP_TRACKING  # the brand's own mailing-provider links
    if not links.codes and all(d in allowed for d in link_domains):
        detail = (f"All links stay on official {brand} domains" if link_domains
                  else "No links to click")
        reasons.append(Reason("trust", "aligned_links", detail, -ALIGNED_LINKS_CREDIT))
    return reasons


class Scorer:
    """Loads the hash-verified models once; scores emails, SMS and pasted text."""

    def __init__(
        self,
        settings: Settings | None = None,
        models_dir: Path = MODELS_DIR,
        models: dict[str, TextScorer] | None = None,
    ) -> None:
        self.settings = settings or load_settings()
        if self.settings.extra_brands_file:
            # Invalid organisation brand files stop the scorer at start-up (fail closed).
            load_extra_brands(Path(self.settings.extra_brands_file))
        if models is None:
            models = {k: load_text_model(f"{k}_model", models_dir) for k in ("email", "sms")}
        self.models = models

    # ------------------------------------------------------------------ public API

    def scan_email_bytes(self, raw: bytes) -> Verdict:
        try:
            email = parse_email(raw, max_bytes=self.settings.max_email_bytes)
        except EmailLimitError as exc:
            return self._unanalysed("email", "limit_exceeded",
                                    f"Message exceeds a safety limit ({exc}); needs manual review")
        except EmailParseError:
            return self._unanalysed("email", "unparseable",
                                    "Message could not be parsed as an email; needs manual review")
        return self.scan_email(email)

    def scan_email(self, email: ParsedEmail) -> Verdict:
        try:
            return self._score_email(email)
        except Exception as exc:  # noqa: BLE001 - fail safe: an error must never mean "deliver"
            return self._unanalysed("email", "internal_error",
                                    f"Analysis failed ({type(exc).__name__}); needs manual review")

    def scan_sms(self, text: str) -> Verdict:
        return self.scan_text(text, kind="sms")

    def scan_text(self, text: str, kind: str = "text") -> Verdict:
        """Score free text: ``kind="sms"`` uses the SMS model, otherwise the email model."""
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        truncated = len(text) > MAX_SMS_CHARS
        text = text[:MAX_SMS_CHARS].replace("\x00", " ")
        try:
            return self._score_text(text, kind, truncated)
        except Exception as exc:  # noqa: BLE001
            return self._unanalysed(kind, "internal_error",
                                    f"Analysis failed ({type(exc).__name__}); needs manual review")

    # ------------------------------------------------------------------ internals

    def _score_email(self, email: ParsedEmail) -> Verdict:
        header = check_headers(email, self.settings.trusted_authserv_id)
        links = check_links(email)
        text_reason, probability = _text_reason(self.models["email"], email_text(email))
        header_reasons = _layer_reasons(
            "header", [(f.code, f.weight, f.detail) for f in header.findings]
        )
        link_reasons = _layer_reasons(
            "link", [(code, LINK_WEIGHTS[code], detail) for code, detail in links.findings.items()]
        )
        trust = _trust_reasons(email, header, links)
        summary = {
            "from": email.from_address,
            "from_display": email.from_display,
            "subject": clean_header(email.subject, 200),
            "recipients": email.recipient_count,
            "links": len(email.links),
            "attachments": len(email.attachments),
            "auth": {"spf": header.spf, "dkim": header.dkim, "dmarc": header.dmarc,
                     "source": header.auth_source},
            "truncated": email.truncated,
        }
        verdict = self._verdict("email", probability, text_reason, header.risk, links.risk,
                                [*header_reasons, *link_reasons, *trust], summary)
        partial = sorted(_PARTIAL_ANALYSIS & set(email.defects))
        if partial and verdict.action == "deliver":
            verdict.label, verdict.action = "suspicious", "review"
            verdict.reasons.append(Reason(
                "system", "partial_analysis",
                f"Part of the message was not analysed ({', '.join(partial)}); needs review",
                0.0,
            ))
        return verdict

    def _score_text(self, text: str, kind: str, truncated: bool) -> Verdict:
        model = self.models["sms" if kind == "sms" else "email"]
        links = check_text_links(text)
        text_reason, probability = _text_reason(model, text)
        link_reasons = _layer_reasons(
            "link", [(code, LINK_WEIGHTS[code], detail) for code, detail in links.findings.items()]
        )
        summary = {"characters": len(text), "links": len(links.urls), "truncated": truncated,
                   "link_domains": sorted({u.domain for u in links.urls if u.domain})[:10]}
        return self._verdict(kind, probability, text_reason, 0.0, links.risk, link_reasons, summary)

    def _verdict(
        self,
        kind: str,
        probability: float,
        text_reason: Reason,
        header_risk: float,
        link_risk: float,
        rule_reasons: list[Reason],
        summary: dict,
    ) -> Verdict:
        reasons = [text_reason, *rule_reasons]
        logit = sum(r.weight for r in reasons)
        score = _sigmoid(logit)
        if score >= self.settings.quarantine_threshold:
            label, action = "phishing", "quarantine"
        elif score >= REVIEW_THRESHOLD:
            label, action = "suspicious", "review"
        else:
            label, action = "legitimate", "deliver"
        reasons.sort(key=lambda r: -abs(r.weight))
        components = {
            "text_probability": round(probability, 4),
            "text_logit": round(text_reason.weight, 3),
            "header_risk": round(header_risk, 3),
            "link_risk": round(link_risk, 3),
            "trust_credit": round(-sum(r.weight for r in reasons if r.source == "trust"), 3),
            "total_logit": round(logit, 3),
        }
        return Verdict(kind, score, label, action, True, reasons, components, summary)

    @staticmethod
    def _unanalysed(kind: str, code: str, detail: str) -> Verdict:
        return Verdict(kind, None, "unknown", "review", False,
                       [Reason("system", code, detail, 0.0)])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m phishguard.scorer",
                                     description="Score an email file or an SMS text.")
    sub = parser.add_subparsers(dest="command", required=True)
    email_cmd = sub.add_parser("email", help="score a .eml file")
    email_cmd.add_argument("path", type=Path)
    sms_cmd = sub.add_parser("sms", help="score an SMS text")
    sms_cmd.add_argument("text")
    args = parser.parse_args(argv)

    dotenv = ROOT / ".env"
    settings = load_settings(dotenv_path=dotenv if dotenv.exists() else None)
    scorer = Scorer(settings)
    if args.command == "email":
        size_limit = settings.max_email_bytes
        if not args.path.is_file():
            print(f"error: {args.path} is not a file", file=sys.stderr)
            return 2
        with args.path.open("rb") as handle:
            raw = handle.read(size_limit + 1)  # bounded read; over-size -> review verdict
        verdict = scorer.scan_email_bytes(raw)
    else:
        verdict = scorer.scan_sms(args.text)
    print(json.dumps(verdict.to_dict(), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
