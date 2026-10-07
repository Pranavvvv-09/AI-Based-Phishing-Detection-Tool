# ruff: noqa: E501  (long template strings are data; wrapping them hurts readability)
"""Generate synthetic transactional SMS: training data for SMS experiment variants V1/V2.

Why: every legitimate SMS in the public corpora (UCI 2011, Mendeley 2022) is personal
chat, so the model learned "formal = scam" and flags genuine bank alerts, OTPs and
delivery updates. Real transactional SMS are personal data and no public corpus exists.

How the shortcut is avoided: every legitimate template has smishing counterparts in
the *same* formats (bank alerts, OTPs, deliveries, bills, ...). Format and formality
are therefore useless to the model; only *what the message asks for* separates the
classes: legitimate messages inform ("never share your OTP", "no action needed"),
smishing asks you to act (share an OTP, pay a fee, click to verify, approve a request).

Safety: phone numbers are masked, links use the reserved .test TLD, names are generic.
Artifacts avoided: links are full https:// URLs, which the SMS normaliser removes (links
are judged by the link rules, and ".test" or the fake domain words must not become
smishing words). Masked numbers (XX1234, 98XXXXXX10) are dropped by the V1/V2 normaliser
like any other number, so the masking used for safety can't become a feature either.
These rows are TRAINING data only. They were written after the evaluation sets were
frozen, and tests enforce that they don't reuse their wording (word overlap below 0.4,
no shared run of 5+ words with any evaluation message).

Status: the pre-registered experiment (scripts/sms_experiment.py) did not select the
template-trained variants; the shipped scorer blends the SMS and email models (V3).
The file is kept so the experiment can be reproduced and extended.

Run:  python scripts/generate_sms_templates.py   (writes data/curated/sms_templates.csv)
"""

from __future__ import annotations

import csv
import random
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "curated" / "sms_templates.csv"
VARIANTS = 8
SEED = 2026

BANKS = ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "Kotak Bank", "PNB", "Bank of Baroda",
         "Canara Bank", "Union Bank", "IDFC FIRST Bank", "IndusInd Bank", "Yes Bank"]
MERCHANTS = ["Amazon", "Flipkart", "Swiggy", "Zomato", "BigBasket", "Myntra", "DMart",
             "Apollo Pharmacy", "BookMyShow", "Reliance Digital", "Nykaa", "Croma"]
COURIERS = ["Delhivery", "Blue Dart", "DTDC", "Ekart", "XpressBees", "Shadowfax", "Ecom Express"]
TELCOS = ["Jio", "Airtel", "Vi", "BSNL"]
BOARDS = ["BESCOM", "MSEDCL", "TNEB", "Tata Power", "Adani Electricity", "CESC"]
APPS = ["Netflix", "Hotstar", "Spotify", "YouTube Premium", "Zee5", "SonyLIV"]
PEOPLE = ["Anil", "Divya", "Imran", "Kavya", "Manoj", "Neha", "Pooja", "Rohit", "Sana", "Vikram"]
CITIES = ["Pune", "Chennai", "Jaipur", "Lucknow", "Kochi", "Indore", "Nagpur", "Surat"]
FAKE = ["kyc-verify", "secure-update", "account-help", "refund-desk", "reward-claim",
        "parcel-fee", "bill-desk", "support-team"]

# {b} bank, {m} merchant, {c} courier, {t} telco, {e} electricity board, {s} app,
# {p} person, {city} city, {a} amount, {d} date, {acc} masked account, {otp} code,
# {link} fake .test link, {ph} masked phone number, {h} hours.
LEGIT = {
    "bank_debit": [
        "{b}: Rs {a} has been debited from your account {acc} on {d} towards {m}. Current balance shown in the app.",
        "IMPS of Rs {a} to {p} done from {b} account {acc} on {d}. Not initiated by you? Ring the helpline listed on your passbook.",
        "Cheque no. {a} for Rs {a} presented on your {b} account {acc} has been cleared on {d}.",
        "Auto-debit of Rs {a} for your {s} subscription was processed from {b} account {acc}. Manage mandates in your banking app.",
    ],
    "bank_credit": [
        "{b}: NEFT inward of Rs {a} from {p} reflected in a/c {acc} on {d}. Available balance can be checked in the app.",
        "Payroll transfer received: {b} has added Rs {a} to account {acc}. Pay slip details are with your employer.",
        "Cashback of Rs {a} from {m} has been credited to your {b} card {acc}. No action is required.",
        "Your fixed deposit of Rs {a} with {b} has matured and the amount is credited to account {acc}.",
    ],
    "card": [
        "{m} purchase of Rs {a} approved on {b} card {acc}. Questions about this charge? Use the help section of the {b} app.",
        "{b} card {acc}: your bill payment of Rs {a} has been posted. The updated limit is visible in the app.",
        "{b} card e-statement generated: outstanding Rs {a}, least payable Rs {a}, pay by {d}.",
        "International usage is disabled on your {b} card {acc}. You can enable it anytime from the app settings.",
    ],
    "upi": [
        "You paid Rs {a} to {m} using UPI from your {b} account {acc}. Transaction ID {a}.",
        "Money received! {p} sent you Rs {a} via UPI. It is now in your {b} account {acc}.",
        "Your UPI autopay for {s} of Rs {a} will be debited on {d}. Pause or cancel it in your UPI app.",
    ],
    "otp": [
        "{otp} is your {b} net banking OTP. Keep it private. {b} will never call you for it.",
        "Use OTP {otp} to complete your payment of Rs {a} at {m}. Valid for 10 minutes. Do not share this OTP.",
        "{otp} is your login code for {m}. If you did not request it, simply ignore this message.",
        "Your {t} SIM change OTP is {otp}. If you have not requested a SIM change, visit a store with your ID.",
    ],
    "delivery": [
        "{c}: your shipment from {m} has been dispatched and will reach {city} by {d}. No action needed.",
        "Your {m} order has been delivered at {h}:00 hrs. Thank you for shopping with us.",
        "{c}: we tried to deliver your parcel today but could not reach you. We will try again tomorrow.",
        "Your {m} package is out for delivery today. Keep the delivery OTP ready for the agent.",
    ],
    "order": [
        "Your {m} order is confirmed. You will receive an update when it ships.",
        "Your refund of Rs {a} for the returned item from {m} has been initiated. It reaches your account in 5-7 days.",
        "You cancelled your {m} order. Any amount paid will be refunded to the original payment method.",
    ],
    "bill": [
        "{e}: the statement for your connection is available. Amount payable Rs {a} by {d}. Online and counter payments are both accepted.",
        "{e}: we have credited Rs {a} against your electricity account. Your next meter reading is scheduled around {d}.",
        "{t} postpaid: Rs {a} outstanding for this month, payable by {d}. Already settled? Please disregard this message.",
    ],
    "telecom": [
        "{t}: Rs {a} top-up applied to your number. Unlimited calls and data now run until {d}.",
        "{t}: high-speed quota for today is over. Browsing continues at a lower speed until the quota resets tomorrow.",
        "{t}: your plan expires on {d}. Recharge from the official app to continue services.",
    ],
    "travel": [
        "Your bus ticket from {city} to {city} on {d} is confirmed. Seat {a}. Show this SMS while boarding.",
        "E-ticket issued for your {city} flight on {d}. Baggage allowance is 15 kg plus 7 kg cabin. Have a pleasant trip.",
        "Your cab driver {p} has arrived at the pickup point. Please share the ride OTP {otp} only inside the cab.",
    ],
    "appointment": [
        "Dr. {p}'s clinic has booked you for {d} at {h}:30. Please arrive 10 minutes early.",
        "Your lab test report is ready. You can collect it from the centre or view it in the app.",
        "Your vaccination slot at the {city} health centre on {d} is confirmed. Carry an ID card.",
    ],
    "account_notice": [
        "Net banking password update completed for your {b} login on {d}. Report anything unexpected using the helpline printed on your debit card.",
        "{m}: sign-in from a Chrome browser in {city} just now. Recognise it? Then nothing more is needed.",
        "{b} security tip: our staff will not request your PIN, OTP or card details by call, SMS or email. Stay alert.",
    ],
    "hinglish": [
        "Aapke {b} khate {acc} mein Rs {a} jama kiye gaye hain. Dhanyavaad.",
        "Aapka {m} order kal tak deliver ho jayega. Koi action ki zarurat nahi hai.",
        "{t}: aapka recharge safal raha. Plan {d} tak valid hai.",
    ],
}
SMISHING = {
    "bank_debit": [
        "{b} fraud desk: a Rs {a} transfer to an unknown payee is being processed. Stop the payment through {link} within {h} hours.",
        "Unusual activity on your {b} account {acc}. Verify your identity within {h} hours at {link} or the account will be frozen.",
        "{b} ALERT: Rs {a} left account {acc} just now. Our reversal officer at {ph} can undo it once you read out the code we texted.",
        "Your {s} auto-debit of Rs {a} failed. Update your card details at {link} to avoid account suspension.",
    ],
    "bank_credit": [
        "{b} rewards: a festive bonus of Rs {a} awaits you. Authorise the incoming UPI mandate with your PIN to collect it.",
        "Congratulations! Cashback of Rs {a} from {m} is pending. Claim it today at {link} before it expires.",
        "Payroll credit of Rs {a} for this month cannot be posted until your PAN is linked again. Do it at {link} today.",
        "Your fixed deposit interest of Rs {a} is blocked. Pay a release fee of Rs {a} at {link} to receive it.",
    ],
    "card": [
        "{b} cards division: missing PAN details have put card {acc} on hold. Submit them at {link} to resume spending.",
        "{b}: {a} loyalty coins are about to lapse. Convert them to cash by typing your card number and CVV at {link}.",
        "Pre-approved upgrade: your {b} card qualifies for a Platinum variant. A bank officer will call from {ph}; tell them the verification code to confirm.",
        "{b}: overseas charge of Rs {a} pending on your card. Text back the 16 digits and CVV so the fraud team can decline it.",
    ],
    "upi": [
        "{p} from the {city} PG: my payment app shows Rs {a} went to your UPI ID wrongly. Kindly accept the refund request with your PIN, my rent is due.",
        "NPCI compliance: unverified UPI handles are closed tonight. Approve the Re 1 request in your app with your PIN to stay active.",
        "{m} returns desk: your Rs {a} payback is ready. Open the QR image we shared and type your PIN to accept the money.",
    ],
    "otp": [
        "{b} helpdesk calling about your locked mobile banking. To unlock it during this call, read out the six digit code that just arrived.",
        "{m} seller desk: your purchase is on a security hold. Type the 6-digit code from your SMS inbox into our chat so we can dispatch it.",
        "{t} network team: a number port request needs your consent. Forward the code you just got to {ph} to cancel it.",
        "Your loan of Rs {a} is approved. Share the OTP with our agent on {ph} to receive the amount today.",
    ],
    "delivery": [
        "{c}: house number missing on consignment for {city}. Courier will return it to the sender unless a Rs {a} correction charge is paid at {link}.",
        "Import clearance for your {m} order from abroad needs a Rs {a} tax payment. Settle it at {link} before the package goes back.",
        "{c}: the courier could not find your door, so the item sits in our godown. A Rs {a} holding fee at {link} gets it out within {h} hours.",
        "Missed delivery for your {m} parcel today. Get our rescheduling app from {link} and pick a new slot.",
    ],
    "order": [
        "{m}: we could not charge your card, so your purchase is on hold. Provide the card number again at {link} within {h} hours.",
        "{m} security: someone tried to buy a gift voucher of Rs {a} with your saved card. Dial {ph} to stop the purchase.",
        "{m} returns: to push your Rs {a} refund manually, our technician needs remote access. Install QuickSupport and read out the 9-digit ID.",
    ],
    "bill": [
        "{e} final notice: a meter reading mismatch was found on your connection. Speak to the billing officer on {ph} before evening to keep supply on.",
        "Your {e} bill payment failed. Pay Rs {a} immediately at {link} to avoid disconnection today.",
        "{t}: your number will be deactivated due to an unpaid bill of Rs {a}. Pay now at {link}.",
    ],
    "telecom": [
        "{t}: your number is selected for a free 5G upgrade. Log in at {link} with your details to activate.",
        "{t}: identity documents for your connection need re-verification. Send a selfie holding your Aadhaar card to {ph} on WhatsApp.",
        "Department of Telecom: complaints are registered against your {t} connection. Outgoing calls stop in {h} hours unless you contact {ph}.",
    ],
    "travel": [
        "Rail booking update: a cancelled journey left Rs {a} unclaimed in your name. Provide your account number and IFSC at {link} today.",
        "Your number was picked for a 3-night stay in {city} at no cost. Reserve it by transferring Rs {a} as a security deposit.",
        "Airline notice: your {city} booking was rescheduled. Read out your card number to our desk on {ph} to process compensation.",
    ],
    "appointment": [
        "Your health insurance bonus of Rs {a} is approved. Pay the processing fee at {link} to receive it.",
        "Ayushman card camp in {city}: free treatment cover up to Rs {a}. Enrolment needs your ATM PIN and Aadhaar number, fill them at {link}.",
        "Your vaccination certificate is on hold. Verify your Aadhaar and OTP at {link} to download it.",
    ],
    "account_notice": [
        "{b} alert: online banking access stops at 6 PM because your mobile number is not verified. Re-confirm it at {link}.",
        "Your {m} account is locked after unusual sign-in attempts. Confirm your password at {link}.",
        "{b} compliance cell: re-KYC is pending, so debit transactions are paused. Upload a selfie and PAN copy through the WhatsApp number {ph} to lift the hold.",
    ],
    "hinglish": [
        "Aapka {b} khata aaj band ho jayega. Turant KYC update karein: {link}",
        "Aapka parcel ruka hua hai. Rs {a} fees bharein warna parcel wapas chala jayega: {link}",
        "Badhai ho! Aapne Rs {a} jeete hain. Claim karne ke liye {ph} par call karein.",
    ],
}


def _fill(template: str, rng: random.Random) -> str:
    return template.format(
        b=rng.choice(BANKS), m=rng.choice(MERCHANTS), c=rng.choice(COURIERS), t=rng.choice(TELCOS),
        e=rng.choice(BOARDS), s=rng.choice(APPS), p=rng.choice(PEOPLE), city=rng.choice(CITIES),
        a=f"{rng.randint(10, 99999):,}", d=f"{rng.randint(1, 28):02d}-{rng.randint(1, 12):02d}-26",
        acc=f"XX{rng.randint(1000, 9999)}", otp=f"{rng.randint(100000, 999999)}",
        link=f"https://{rng.choice(FAKE)}-{rng.randint(1, 99)}.test/{rng.choice('abcdefgh')}",
        ph=f"9{rng.randint(1, 9)}XXXXXX{rng.randint(10, 99)}", h=rng.randint(1, 12),
    )


def generate() -> list[tuple[int, int, str, str, str]]:
    # A seeded PRNG on purpose: the data must be reproducible (this is not security code).
    rng = random.Random(SEED)  # noqa: S311  # nosec B311
    rows, seen = [], set()
    for label, groups in ((0, LEGIT), (1, SMISHING)):
        for category, templates in groups.items():
            for t_index, template in enumerate(templates):
                for _ in range(VARIANTS):
                    text = _fill(template, rng)
                    if text not in seen:
                        seen.add(text)
                        rows.append((label, category, f"{category}-{label}-{t_index}", text))
    return [(i, *row) for i, row in enumerate(rows, 1)]


def main() -> int:
    rows = generate()
    with OUT.open("w", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["id", "label", "category", "template_id", "text"])
        writer.writerows(rows)
    legit = sum(1 for r in rows if r[1] == 0)
    print(f"wrote {OUT.name}: {legit} legitimate, {len(rows) - legit} smishing rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
