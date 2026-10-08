import pytest

from phishguard.scorer import check_text_links, extract_bare_domains
from phishguard.sms_checks import check_sms, classify_sender, contact_channels
from phishguard.url_checks import LinkReport

from .test_scorer import scorer


def sms_report(text: str, sender: str = ""):
    return check_sms(text, sender, check_text_links(text))


@pytest.mark.parametrize(
    ("sender", "kind"),
    [
        ("VM-HDFCBK-S", "alphanumeric"), ("AMAZON", "alphanumeric"),
        ("+91 98450 22371", "phone"), ("9845022371", "phone"), ("+1 (415) 555-0148", "phone"),
        ("57575", "short_code"), ("scam.team@icloud.com", "email"), ("", "none"),
        ("  ", "none"), ("<script>", "other"),
    ],
)
def test_classify_sender(sender, kind):
    assert classify_sender(sender) == kind


@pytest.mark.parametrize(
    "text",
    [
        "Call our officer 98450 22371 immediately",
        "SMS BLOCK 4417 to 919951860002",
        "To claim contact Rana 7416430812 on WhatsApp",
        "Reach us at +44 7700 900461",
        "Reply YES to confirm",
        "Text WIN to 87121 now",
        "Write to refunds@example.org",
        "Update at example.in/kyc",
    ],
)
def test_contact_channels_are_found(text):
    assert contact_channels(text, check_text_links(text))


@pytest.mark.parametrize(
    "text",
    [
        "Rs 560 debited from A/c X9921. UPI Ref No 628011457731. Bal Rs 18,904",
        "PNR:4521788901, TRN:12627, coach B4 32. Happy journey",
        "Not you? Call 1800-XXX-XXXX",  # masked numbers can't be called
        "Your parcel AWB 77215544 will arrive on 09-Oct. No action needed.",
    ],
)
def test_reference_and_masked_numbers_are_not_channels(text):
    assert contact_channels(text, LinkReport()) == []


def test_brand_claim_from_personal_number_or_email_is_flagged():
    text = "SBI: your account is blocked, our officer will call you"
    assert "sender_phone_claims_brand" in sms_report(text, "+91 98301 44728").codes
    assert "sender_phone_claims_brand" not in sms_report(text, "AD-SBIINB-S").codes
    assert "sender_phone_claims_brand" not in sms_report("see you at 8", "+91 98301 44728").codes
    assert "sender_email_address" in sms_report("Parcel on hold", "x@icloud.com").codes


def test_alphanumeric_sender_ids_earn_no_credit():
    # Spoofable outside India: a sender ID must never lower the score.
    a = scorer(p_sms=0.7, p_email=0.7).scan_sms("Your KYC is pending, reply now", "VM-SBIINB-S")
    b = scorer(p_sms=0.7, p_email=0.7).scan_sms("Your KYC is pending, reply now")
    assert a.score == pytest.approx(b.score)


def test_link_outside_named_brand_is_flagged_and_official_link_is_credited():
    bad = sms_report("ICICI: verify your account at https://bit.ly/3rvChg9")
    assert "sms_brand_link_mismatch" in bad.codes and not bad.aligned_links
    good = sms_report("Amazon: delivered. Track: https://amzn.in/d/5hR2kPq")
    assert not good.findings and good.aligned_links
    lookalike = sms_report("SBI: redeem points at sbi-yono-points.xyz")
    assert "sms_brand_link_mismatch" in lookalike.codes


def test_no_contact_credit_only_without_any_channel_or_finding():
    quiet = scorer(p_sms=0.7, p_email=0.7).scan_sms("Rs 500 credited to your account today")
    assert "sms_no_contact_channel" in {r.code for r in quiet.reasons}
    assert quiet.components["trust_credit"] == pytest.approx(1.0)
    call = scorer(p_sms=0.7, p_email=0.7).scan_sms("Account blocked, call 98301 44728 now")
    assert "sms_no_contact_channel" not in {r.code for r in call.reasons}
    # A risk finding (brand from a personal number) also cancels the credit.
    risky = scorer(p_sms=0.7, p_email=0.7).scan_sms("SBI account update done", "+91 98301 44728")
    assert "sms_no_contact_channel" not in {r.code for r in risky.reasons}


def test_credits_are_capped_so_confident_scam_wording_still_wins():
    v = scorer(p_sms=0.999, p_email=0.999).scan_sms("send the otp you received to our agent")
    assert v.action == "quarantine"


def test_sender_layer_is_capped_and_reported():
    v = scorer(p_sms=0.5, p_email=0.5).scan_sms("SBI KYC pending", "+91 98301 44728")
    sender = [r for r in v.reasons if r.source == "sender"]
    assert sender and sum(r.weight for r in sender) <= 4.0
    assert v.components["sender_risk"] == pytest.approx(0.35)
    assert v.summary["sender_kind"] == "phone"


def test_sender_must_be_a_string():
    with pytest.raises(TypeError):
        scorer().scan_sms("hello", sender=None)


def test_untrusted_sender_never_reaches_the_verdict_unsanitised():
    v = scorer().scan_sms("hello please reply", "\u202eevil\x00")
    assert "\u202e" not in str(v.to_dict()) and "\x00" not in str(v.to_dict())


def test_single_letter_short_link_domains_are_links():
    assert extract_bare_domains("Join t.me/stockking_vip, or a.co/d/abc.") == [
        "t.me/stockking_vip", "a.co/d/abc"]
    assert extract_bare_domains("e.g. this, and file.txt") == []


def test_sms_only_components_stay_out_of_email_text():
    assert "sender_risk" not in scorer().scan_text("hello there", kind="email").components
