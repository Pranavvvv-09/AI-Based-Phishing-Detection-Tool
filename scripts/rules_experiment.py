"""Pre-registered experiment for the Day 6 rule fixes (reproducible).

Two problems, one experiment each, both decided on validation data only:

1. Modern legitimate email is flagged because the text model learned "your account"
   wording as phishing (all its legitimate training mail is from 2000-2008).
2. Genuine transactional SMS are flagged because the SMS model learned "formal = scam",
   and SMS had no sender or link-vs-brand evidence at all.

Evaluation data, frozen in a commit before any of these fixes existed:
* data/curated/email_eval_v2.csv: 60 modern emails with sender, DMARC result, Reply-To.
* data/curated/sms_eval_v2.csv: 120 SMS with the sender and realistic links.
Phone-number placeholders are filled in deterministically at load time.

Email variants (fixed before training; all use the corrected brand list):
  E0  the shipped email model
  E1  email model retrained with person pronouns as stop words (you, your, yours,
      yourself, we, us, our, ours): modern notices are written "to you", old corpora
      mostly person to person
  E2  E1 plus "account" and "accounts"
Guard (text model alone): honeypot-future English recall >= 0.85 and in-distribution
legitimate FPR <= 1%, both at 0.5.
Rule: highest full-scorer F1 at 0.5 on the email validation third; ties -> fewer
validation false positives at the quarantine threshold, then at 0.5; then the simpler
variant (E0, E1, E2).

SMS variants (fixed before evaluation; all use the email model chosen above):
  S0  the Day 6 scorer: SMS+email wording and URL checks
  S1  S0 + sender evidence and brand-vs-link mismatch (risk only)
  S2  S1 + the two capped credits (no contact channel; links on the brand's domains)
Guard: on the public SMS test split through the full scorer, FPR <= 1% and recall >= 0.90.
Rule: highest full-scorer F1 at 0.5 on the pooled SMS validation data (the sms_eval_v2
validation third + the validation half of sms_transactional_eval.csv, which was used
to choose the blend but never as a test); ties -> fewer validation false positives at
the quarantine threshold, then at 0.5; then the simpler variant (S0, S1, S2).

Only after both choices are fixed are the test thirds, the old frozen test half and the
independent bank SMS scored.

Run:  python scripts/rules_experiment.py   (needs the datasets and both models; ~6 min)
Writes models/rules_experiment.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from phishguard import scorer as sc  # noqa: E402
from phishguard import text_model as tm  # noqa: E402
from phishguard.config import load_settings  # noqa: E402
from phishguard.sms_checks import SmsReport  # noqa: E402

CURATED_DIR = ROOT / "data" / "curated"
OUT = ROOT / "models" / "rules_experiment.json"
PRONOUNS = ["you", "your", "yours", "yourself", "we", "us", "our", "ours"]
EMAIL_SIMPLICITY = ["E0", "E1", "E2"]
SMS_SIMPLICITY = ["S0", "S1", "S2"]
EMAIL_GUARD = {"min_honeypot_recall": 0.85, "max_legit_fpr": 0.01}
SMS_GUARD = {"max_fpr": 0.01, "min_recall": 0.90}


# ----------------------------------------------------------------------------- data


def fill_placeholders(value: str, row_id: str, sender: bool = False) -> str:
    """Deterministic phone numbers of the right shape (never published in the CSV)."""
    n = int(row_id)
    mobile = f"9{(n * 7919) % 10**9:09d}"
    if sender:
        mobile = f"+91 {mobile[:5]} {mobile[5:]}"
    return value.replace("{MOBILE}", mobile).replace("{TOLLFREE}", f"1800 425 {n % 10000:04d}")


def load_sms_eval() -> pd.DataFrame:
    df = pd.read_csv(CURATED_DIR / "sms_eval_v2.csv", dtype=str, keep_default_na=False)
    df["text"] = [fill_placeholders(t, i) for t, i in zip(df["text"], df["id"], strict=True)]
    df["sender"] = [fill_placeholders(s, i, sender=True)
                    for s, i in zip(df["sender"], df["id"], strict=True)]
    return df.astype({"label": int})


def email_bytes(row) -> bytes:
    """The email as Gmail would deliver it: its own Authentication-Results on top."""
    domain = row["from_address"].rsplit("@", 1)[1]
    result = "pass" if row["dmarc"] == "pass" else "fail"
    lines = [
        f"Authentication-Results: mx.google.com; dkim={result} header.i=@{domain};"
        f" spf={result} smtp.mailfrom={row['from_address']}; dmarc={result}"
        f" header.from={domain}",
        f"From: \"{row['from_display']}\" <{row['from_address']}>",
        "To: user@example.org",
        f"Subject: {row['subject']}",
        f"Message-ID: <{row['id']}@{domain}>",
        "Date: Thu, 08 Oct 2026 10:00:00 +0530",
    ]
    if row["reply_to"]:
        lines.append(f"Reply-To: {row['reply_to']}")
    lines += ["MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8", "", row["body"]]
    return "\r\n".join(lines).encode()


def load_email_eval() -> pd.DataFrame:
    df = pd.read_csv(CURATED_DIR / "email_eval_v2.csv", dtype=str, keep_default_na=False)
    return df.astype({"label": int})


# --------------------------------------------------------------------------- metrics


def rates(labels, scores, threshold: float) -> dict:
    y, p = np.asarray(labels), np.asarray(scores, dtype=float)
    legit, phish = p[y == 0], p[y == 1]
    out: dict = {"n_legit": int(len(legit)), "n_phish": int(len(phish))}
    if len(legit):
        out.update(FP_05=int((legit >= 0.5).sum()), FP_q=int((legit >= threshold).sum()),
                   FPR_05=round(float((legit >= 0.5).mean()), 4),
                   FPR_q=round(float((legit >= threshold).mean()), 4))
    if len(phish):
        out.update(recall_05=round(float((phish >= 0.5).mean()), 4),
                   recall_q=round(float((phish >= threshold).mean()), 4))
    if len(legit) and len(phish):
        out["F1_05"] = round(float(f1_score(y, (p >= 0.5).astype(int), zero_division=0)), 4)
    return out


def score_of(verdict) -> float:
    return 1.0 if verdict.score is None else verdict.score  # unanalysed -> review


def choose(results: dict, eligible: list[str], order: list[str]) -> str:
    return min(eligible, key=lambda v: (-results[v]["validation"]["F1_05"],
                                        results[v]["validation"]["FP_q"],
                                        results[v]["validation"]["FP_05"], order.index(v)))


# --------------------------------------------------------------------- email models


def train_email_variant(stop_words: list[str]) -> tm.TextModel:
    """Same data and split as ``tm.train_email_model``; only the stop words differ."""
    corpus = tm.load_email_corpus()
    curated = tm.load_curated()
    pot = corpus[corpus["source"] == tm.HONEYPOT]
    rest = corpus[corpus["source"] != tm.HONEYPOT]
    train, _ = train_test_split(rest, test_size=0.2, stratify=rest["label"],
                                random_state=tm.SEED)
    cutoff = pot["sample_no"].quantile(tm.HONEYPOT_TRAIN_FRACTION)
    train = pd.concat([train, pot[pot["sample_no"] <= cutoff]], ignore_index=True)
    pipeline = tm._fit(train, curated[curated["split"] == "train"],
                       stop_words=[*tm.CORPUS_ARTIFACTS, *stop_words])
    return tm.TextModel(pipeline, "email")


def email_guard(model: tm.TextModel) -> dict:
    corpus = tm.load_email_corpus()
    pot = corpus[corpus["source"] == tm.HONEYPOT]
    rest = corpus[corpus["source"] != tm.HONEYPOT]
    _, test = train_test_split(rest, test_size=0.2, stratify=rest["label"],
                               random_state=tm.SEED)
    cutoff = pot["sample_no"].quantile(tm.HONEYPOT_TRAIN_FRACTION)
    future = pot[pot["sample_no"] > cutoff]
    legit = test[test["label"] == 0]
    # Texts are already normalised; normalising again is a no-op for these strings.
    p_future = model.pipeline.predict_proba(future["text"])[:, 1]
    p_legit = model.pipeline.predict_proba(legit["text"])[:, 1]
    return {"honeypot_future_recall": round(float((p_future >= 0.5).mean()), 4),
            "legit_test_fpr": round(float((p_legit >= 0.5).mean()), 4)}


# ------------------------------------------------------------------------ SMS variants


class SmsVariant:
    """Run the real scorer with parts of the SMS evidence switched off (S0/S1)."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __enter__(self):
        self._check, self._trust = sc.check_sms, sc._sms_trust_reasons
        if self.name == "S0":
            def no_sms_rules(text, sender, links):
                return SmsReport(contact_channels=["(disabled)"])
            sc.check_sms = no_sms_rules
        if self.name in ("S0", "S1"):
            sc._sms_trust_reasons = lambda sms: []
        return self

    def __exit__(self, *exc):
        sc.check_sms, sc._sms_trust_reasons = self._check, self._trust


def main() -> int:
    settings = load_settings({})
    q = settings.quarantine_threshold
    sms_model = tm.load_text_model("sms_model")
    email_models = {"E0": tm.load_text_model("email_model")}
    print("training E1 and E2 (about 2 minutes each)...")
    email_models["E1"] = train_email_variant(PRONOUNS)
    email_models["E2"] = train_email_variant([*PRONOUNS, "account", "accounts"])

    emails = load_email_eval()
    email_val = emails[emails["split"] == "validation"]
    email_test = emails[emails["split"] == "test"]
    report: dict = {"email": {"guard": EMAIL_GUARD, "variants": {}},
                    "sms": {"guard": SMS_GUARD, "variants": {}}}

    def email_scores(scorer: sc.Scorer, rows: pd.DataFrame) -> list[float]:
        return [score_of(scorer.scan_email_bytes(email_bytes(r))) for _, r in rows.iterrows()]

    scorers = {name: sc.Scorer(settings, models={"email": model, "sms": sms_model})
               for name, model in email_models.items()}
    email_results = report["email"]["variants"]
    for name, model in email_models.items():
        email_results[name] = {
            "guard": email_guard(model),
            "validation": rates(email_val["label"], email_scores(scorers[name], email_val), q),
        }
    email_eligible = [v for v in EMAIL_SIMPLICITY
                      if email_results[v]["guard"]["honeypot_future_recall"]
                      >= EMAIL_GUARD["min_honeypot_recall"]
                      and email_results[v]["guard"]["legit_test_fpr"]
                      <= EMAIL_GUARD["max_legit_fpr"]]
    email_choice = choose(email_results, email_eligible, EMAIL_SIMPLICITY)
    report["email"].update(eligible=email_eligible, choice=email_choice)
    scorer = scorers[email_choice]

    # ---------------- SMS, on top of the chosen email model
    sms = load_sms_eval()
    old = pd.read_csv(CURATED_DIR / "sms_transactional_eval.csv", dtype={"text": str})
    old = old.assign(sender="")
    pooled_val = pd.concat([sms[sms["split"] == "validation"], old[old["split"] == "validation"]],
                           ignore_index=True)
    corpus = tm.load_sms_corpus()
    _, public_test = train_test_split(corpus, test_size=0.2, stratify=corpus["label"],
                                      random_state=tm.SEED)
    raw = _raw_sms()
    public_texts = [raw.get(k[:2000], k) for k in public_test["text"]]

    def sms_scores(rows_text, rows_sender) -> list[float]:
        return [score_of(scorer.scan_sms(t, sender=s))
                for t, s in zip(rows_text, rows_sender, strict=True)]

    sms_results = report["sms"]["variants"]
    for name in SMS_SIMPLICITY:
        with SmsVariant(name):
            sms_results[name] = {
                "validation": rates(pooled_val["label"],
                                    sms_scores(pooled_val["text"], pooled_val["sender"]), q),
                "public_test_split": rates(public_test["label"],
                                           sms_scores(public_texts, [""] * len(public_texts)), q),
            }
    sms_eligible = [v for v in SMS_SIMPLICITY
                    if sms_results[v]["public_test_split"]["FPR_05"] <= SMS_GUARD["max_fpr"]
                    and sms_results[v]["public_test_split"]["recall_05"]
                    >= SMS_GUARD["min_recall"]]
    sms_choice = choose(sms_results, sms_eligible, SMS_SIMPLICITY)
    report["sms"].update(eligible=sms_eligible, choice=sms_choice)

    # ---------------- only now: test data
    for name in EMAIL_SIMPLICITY:
        email_results[name]["test"] = rates(email_test["label"],
                                            email_scores(scorers[name], email_test), q)
    independent = pd.read_csv(CURATED_DIR / "sms_independent_bank.csv", dtype={"text": str})
    sms_test = sms[sms["split"] == "test"]
    old_test = old[old["split"] == "test"]
    for name in SMS_SIMPLICITY:
        with SmsVariant(name):
            scores = sms_scores(sms_test["text"], sms_test["sender"])
            sms_results[name]["test"] = rates(sms_test["label"], scores, q)
            wrong = (np.asarray(scores) >= 0.5).astype(int) != sms_test["label"].to_numpy()
            sms_results[name]["test_errors_by_category"] = (
                sms_test.loc[wrong, "category"].value_counts().sort_index().to_dict())
            sms_results[name]["old_frozen_test"] = rates(
                old_test["label"], sms_scores(old_test["text"], old_test["sender"]), q)
            sms_results[name]["independent_bank"] = rates(
                independent["label"], sms_scores(independent["text"], [""] * len(independent)),
                q)

    OUT.write_text(json.dumps(report, indent=1) + "\n")
    for kind, order in (("email", EMAIL_SIMPLICITY), ("sms", SMS_SIMPLICITY)):
        print(f"\n{kind}: eligible {report[kind]['eligible']} | choice {report[kind]['choice']}")
        for name in order:
            r = report[kind]["variants"][name]
            print(f"  {name} val F1 {r['validation']['F1_05']:.3f} "
                  f"val FP {r['validation']['FP_05']}/{r['validation']['n_legit']} | "
                  f"test FPR {r['test']['FPR_05']:.3f} (q {r['test']['FPR_q']:.3f}) "
                  f"recall {r['test']['recall_05']:.3f} (q {r['test']['recall_q']:.3f})")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


def _raw_sms() -> dict[str, str]:
    """Training-time dedup key -> raw SMS text (as in scripts/evaluate_scorer.py)."""
    import csv
    import html

    mapping: dict[str, str] = {}
    mendeley = pd.read_csv(tm.RAW_DIR / tm.SMS_MENDELEY, dtype=str, keep_default_na=False)
    uci = pd.read_csv(tm.RAW_DIR / tm.SMS_UCI, sep="\t", header=None, names=["label", "text"],
                      dtype=str, keep_default_na=False, quoting=csv.QUOTE_NONE)
    for text in [*mendeley["TEXT"], *uci["text"]]:
        clean = html.unescape(tm._UCI_PLACEHOLDER.sub(" ", text))
        mapping.setdefault(tm.normalize_sms(clean)[:2000], clean)
    return mapping


if __name__ == "__main__":
    raise SystemExit(main())
