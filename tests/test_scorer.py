import json
import math
import time
from pathlib import Path

import pytest

from phishguard.config import load_settings
from phishguard.scorer import (
    RULE_SCALE,
    TEXT_CLIP,
    BlendedText,
    Scorer,
    check_text_links,
    extract_bare_domains,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
REAL_MODELS = all((ROOT / "models" / f"{k}_model.joblib").exists() for k in ("email", "sms"))


class StubModel:
    """Deterministic stand-in for TextModel: fixed probability, no model files needed."""

    def __init__(self, probability: float, fail: bool = False) -> None:
        self.probability = probability
        self.fail = fail

    def predict_proba(self, text: str) -> float:
        if self.fail:
            raise RuntimeError("boom")
        return self.probability

    def token_count(self, text: str) -> int:
        return len(text.split())

    def top_terms(self, text: str, k: int = 5) -> list[tuple[str, float]]:
        return [("verify", 1.0)]


def scorer(p_email=0.5, p_sms=0.5, fail=False, **env) -> Scorer:
    settings = load_settings({"QUARANTINE_THRESHOLD": "0.8", **env})
    models = {"email": StubModel(p_email, fail), "sms": StubModel(p_sms, fail)}
    return Scorer(settings, models=models)


def logit(p):
    return math.log(p / (1 - p))


def sigmoid(x):
    return 1 / (1 + math.exp(-x))


def raw_email(headers: str, body: str = "Hello, see the attached notes for this week.") -> bytes:
    return (headers.strip() + "\r\nMessage-ID: <1@example.com>\r\n\r\n" + body).encode()


# ---------------------------------------------------------------- fusion maths


def test_text_only_score_equals_model_probability():
    v = scorer(p_sms=0.9, p_email=0.9).scan_sms("hello there my friend how are you")
    assert v.score == pytest.approx(0.9)
    assert v.label == "phishing" and v.action == "quarantine"
    v = scorer(p_email=0.9).scan_text("hello there my friend how are you", kind="email")
    assert v.score == pytest.approx(0.9)


def test_sms_wording_averages_sms_and_email_models_in_log_odds():
    v = scorer(p_sms=0.9, p_email=0.1).scan_sms("hello there my friend how are you")
    assert v.score == pytest.approx(0.5)  # logits +2.197 and -2.197 cancel out
    assert v.components["sms_model_probability"] == 0.9
    assert v.components["email_model_probability"] == 0.1
    v = scorer(p_sms=0.95, p_email=0.6).scan_sms("hello there my friend how are you")
    assert v.score == pytest.approx(sigmoid((logit(0.95) + logit(0.6)) / 2))
    assert "sms_model_probability" not in scorer().scan_text("a b c d", kind="email").components


def test_blended_explanation_halves_each_models_word_weights():
    class Terms(StubModel):
        def __init__(self, terms):
            super().__init__(0.5)
            self.terms = terms

        def top_terms(self, text, k=5):
            return self.terms[:k]

    blend = BlendedText(Terms([("kyc", 2.0), ("account", 1.0)]),
                        Terms([("account", 3.0), ("verify", 0.5)]))
    assert blend.top_terms("x", 2) == [("account", 2.0), ("kyc", 1.0)]
    assert blend.predict_proba("x") == pytest.approx(0.5)


def test_text_evidence_is_clipped():
    v = scorer(p_sms=0.999999, p_email=0.999999).scan_sms("some ordinary words here")
    assert v.score == pytest.approx(sigmoid(TEXT_CLIP))
    v = scorer(p_sms=1e-9, p_email=1e-9).scan_sms("some ordinary words here")
    assert v.score == pytest.approx(sigmoid(-TEXT_CLIP))


def test_thresholds_map_to_actions():
    assert scorer(p_sms=0.79, p_email=0.79).scan_sms("a b c d").action == "review"
    assert scorer(p_sms=0.49, p_email=0.49).scan_sms("a b c d").action == "deliver"
    assert scorer(p_sms=0.81, p_email=0.81).scan_sms("a b c d").action == "quarantine"


def test_rule_layer_is_capped_at_rule_scale():
    # Spoofed fixture: header and link risk are both 1.0, so each adds exactly RULE_SCALE.
    v = scorer(p_email=0.5).scan_email_bytes((FIXTURES / "phish_spoofed_sender.eml").read_bytes())
    header = sum(r.weight for r in v.reasons if r.source == "header")
    link = sum(r.weight for r in v.reasons if r.source == "link")
    assert header == pytest.approx(RULE_SCALE) and link == pytest.approx(RULE_SCALE)
    assert v.score == pytest.approx(sigmoid(2 * RULE_SCALE))


def test_hard_technical_evidence_beats_innocent_wording():
    v = scorer(p_email=0.001).scan_email_bytes(
        (FIXTURES / "phish_spoofed_sender.eml").read_bytes()
    )
    assert v.action == "quarantine"  # text clipped at -4, rules add +8


def test_adding_a_finding_never_lowers_the_score():
    base = scorer(p_sms=0.3).scan_sms("please read the message below carefully")
    risky = scorer(p_sms=0.3).scan_sms("please read the message below http://192.0.2.7/x")
    assert risky.score > base.score


def test_reasons_sorted_and_explained():
    v = scorer(p_email=0.9).scan_email_bytes((FIXTURES / "phish_spoofed_sender.eml").read_bytes())
    weights = [abs(r.weight) for r in v.reasons]
    assert weights == sorted(weights, reverse=True)
    assert {"text", "header", "link"} <= {r.source for r in v.reasons}
    assert sum(r.weight for r in v.reasons) == pytest.approx(v.components["total_logit"], abs=1e-3)
    data = v.to_dict()
    keys = {"source", "code", "detail", "weight", "strength"}
    assert all(keys <= set(r) for r in data["reasons"])


def test_verdict_never_contains_the_body():
    body = "UNIQUE-BODY-MARKER-1234 please verify your account"
    v = scorer().scan_email_bytes(raw_email("From: a@example.com\r\nTo: b@example.org", body))
    assert "UNIQUE-BODY-MARKER" not in json.dumps(v.to_dict())


# ---------------------------------------------------------------- trust credits

PAYPAL_DMARC_OK = (
    "Authentication-Results: mx.google.com; dkim=pass header.i=@paypal.com;"
    " spf=pass smtp.mailfrom=service@paypal.com; dmarc=pass header.from=paypal.com\r\n"
    "From: PayPal <service@paypal.com>\r\nTo: b@example.org\r\nSubject: Your receipt"
)


def test_verified_official_sender_gets_trust_credit():
    body = '<a href="https://www.paypal.com/activity">View activity</a>'
    raw = raw_email(PAYPAL_DMARC_OK + "\r\nContent-Type: text/html", body)
    v = scorer(p_email=0.99).scan_email_bytes(raw)
    codes = {r.code for r in v.reasons if r.source == "trust"}
    assert codes == {"verified_sender", "aligned_links"}
    assert v.components["trust_credit"] == pytest.approx(3.0)
    # Wording can still push a verified sender to review (fake invoices from paypal.com).
    assert v.action == "review"


def test_no_trust_when_header_not_from_your_provider():
    raw = raw_email(PAYPAL_DMARC_OK.replace("mx.google.com", "relay.attacker.test"))
    v = scorer(p_email=0.99).scan_email_bytes(raw)
    assert not [r for r in v.reasons if r.source == "trust"]
    assert v.action == "quarantine"


def test_no_trust_for_non_brand_or_spoofing_signs():
    gmail = PAYPAL_DMARC_OK.replace("paypal.com", "gmail.com").replace("PayPal <", "Friend <")
    assert not [r for r in scorer().scan_email_bytes(raw_email(gmail)).reasons
                if r.source == "trust"]
    redirected = PAYPAL_DMARC_OK + "\r\nReply-To: refunds@gmail.com"
    assert not [r for r in scorer().scan_email_bytes(raw_email(redirected)).reasons
                if r.source == "trust"]


@pytest.mark.parametrize("freemail", ["gmail.com", "outlook.com", "icloud.com", "yahoo.com"])
def test_freemail_senders_never_get_trust_even_with_dmarc_pass(freemail):
    # Gmail passes DMARC for every user, including scammers: no "verified sender" credit.
    raw = raw_email(PAYPAL_DMARC_OK.replace("paypal.com", freemail).replace("PayPal <", "Boss <"))
    v = scorer(p_email=0.9).scan_email_bytes(raw)
    assert not [r for r in v.reasons if r.source == "trust"]


def test_off_brand_link_removes_aligned_links_credit():
    body = '<a href="https://evil.example.net/login">View activity</a>'
    raw = raw_email(PAYPAL_DMARC_OK + "\r\nContent-Type: text/html", body)
    codes = {r.code for r in scorer().scan_email_bytes(raw).reasons if r.source == "trust"}
    assert codes == {"verified_sender"}


def test_extra_brands_file_is_used_and_validated(tmp_path):
    good = tmp_path / "brands.json"
    good.write_text('{"acmecorp": ["acmecorp.com"]}')
    s = scorer(EXTRA_BRANDS_FILE=str(good))
    acme = PAYPAL_DMARC_OK.replace("paypal.com", "acmecorp.com").replace("PayPal", "Acme HR")
    raw = raw_email(acme)
    assert {r.code for r in s.scan_email_bytes(raw).reasons} >= {"verified_sender"}
    bad = tmp_path / "bad.json"
    bad.write_text('{"acme": "not-a-list"}')
    with pytest.raises(ValueError):
        scorer(EXTRA_BRANDS_FILE=str(bad))  # fail closed at start-up


# ---------------------------------------------------------------- fail-safe


def test_oversized_email_goes_to_review():
    raw = b"From: a@example.com\r\n\r\n" + b"x" * 5000
    v = scorer(MAX_EMAIL_BYTES="2048").scan_email_bytes(raw)
    assert (v.action, v.label, v.analysed, v.score) == ("review", "unknown", False, None)
    assert v.reasons[0].code == "limit_exceeded"


def test_unparseable_and_mime_floods_go_to_review():
    assert scorer().scan_email_bytes(b"   ").action == "review"
    flood = ("From: a@x.test\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n"
             + "--b\r\n\r\nx\r\n" * 3000).encode()
    assert scorer().scan_email_bytes(flood).action == "review"


def test_partially_analysed_email_is_never_delivered():
    parts = "".join(f"--b\r\nContent-Type: text/plain\r\n\r\npart {i}\r\n" for i in range(150))
    raw = ("From: a@example.com\r\nTo: b@example.org\r\nMessage-ID: <1@x>\r\n"
           "Content-Type: multipart/mixed; boundary=b\r\n\r\n" + parts + "--b--").encode()
    v = scorer(p_email=0.01).scan_email_bytes(raw)
    assert v.action == "review"
    assert "partial_analysis" in {r.code for r in v.reasons}


def test_internal_error_never_means_deliver():
    v = scorer(fail=True).scan_email_bytes((FIXTURES / "legit_newsletter.eml").read_bytes())
    assert (v.action, v.analysed) == ("review", False)
    assert "RuntimeError" in v.reasons[0].detail and "boom" not in v.reasons[0].detail
    assert scorer(fail=True).scan_sms("hello").action == "review"


def test_sms_input_validation():
    with pytest.raises(TypeError):
        scorer().scan_sms(b"bytes")  # type: ignore[arg-type]
    v = scorer().scan_sms("word " * 5000)
    assert v.summary["truncated"] is True and v.summary["characters"] == 5000


# ---------------------------------------------------------------- SMS links


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Update KYC at sbi-kyc-update.in/verify now", ["sbi-kyc-update.in/verify"]),
        ("Track: indiapost-track.top/abc123", ["indiapost-track.top/abc123"]),
        ("Login paypa1.com today", ["paypa1.com"]),
        ("see e.g. the file report.txt or mail a@b.com", []),
        ("pi is 3.14 and v2.0 is out", []),
        ("visit https://example.com/x or www.example.org", []),  # handled by extract_urls
    ],
)
def test_extract_bare_domains(text, expected):
    assert extract_bare_domains(text) == expected


def test_bare_domain_findings_without_false_http_only():
    report = check_text_links("Your parcel is held. Pay at indiapost-track.top/fee")
    assert "url_lookalike_domain" in report.codes and "url_risky_tld" in report.codes
    assert "url_http_only" not in report.codes


def test_bare_domain_extraction_is_fast_and_bounded():
    start = time.perf_counter()
    found = extract_bare_domains(("a" * 60 + ".") * 2000 + " " + "x.com " * 100)
    assert time.perf_counter() - start < 1.0
    assert len(found) <= 20


# ---------------------------------------------------------------- real models (skipped in CI)


@pytest.mark.skipif(not REAL_MODELS, reason="run scripts/bootstrap.py first")
@pytest.mark.parametrize(
    ("fixture", "action"),
    [
        ("legit_newsletter.eml", "deliver"),
        ("phish_spoofed_sender.eml", "quarantine"),
        ("phish_forged_auth.eml", "quarantine"),
        ("phish_bec_freemail.eml", "quarantine"),
        ("phish_attachment.eml", "quarantine"),
    ],
)
def test_real_models_on_fixtures(fixture, action):
    s = Scorer(load_settings({}))
    assert s.scan_email_bytes((FIXTURES / fixture).read_bytes()).action == action


@pytest.mark.skipif(not REAL_MODELS, reason="run scripts/bootstrap.py first")
def test_real_sms_model_and_cli(capsys):
    from phishguard.scorer import main

    s = Scorer(load_settings({}))
    smish = s.scan_sms("Your SBI account is blocked. Update KYC now at sbi-kyc-update.in/verify")
    chat = s.scan_sms("ok see you at lunch tomorrow, bring the notes pls")
    assert smish.action == "quarantine" and chat.action == "deliver"
    assert main(["email", str(FIXTURES / "phish_spoofed_sender.eml")]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["action"] == "quarantine" and out["reasons"]


def test_m365_tenant_never_gets_trust():
    tenant = PAYPAL_DMARC_OK.replace("paypal.com", "contoso.onmicrosoft.com")
    tenant = tenant.replace("PayPal <", "Contoso <")
    v = scorer(p_email=0.9).scan_email_bytes(raw_email(tenant))
    assert not [r for r in v.reasons if r.source == "trust"]


def test_verdict_output_strips_invisible_and_bidi_characters():
    raw = raw_email(
        "From: \"Pay\u202eLaP\u200b\" <a@example.com>"
        "\r\nTo: b@example.org\r\nSubject: hi\u2066there",
        "<a href='https://exa\u200bmple.com/x'>www.paypal.com</a>",
    )
    data = scorer().scan_email_bytes(raw).to_dict()
    dumped = json.dumps(data, ensure_ascii=False)
    for ch in ("\u202e", "\u200b", "\u2066"):
        assert ch not in dumped
    assert all(len(r["detail"]) <= 300 for r in data["reasons"])
