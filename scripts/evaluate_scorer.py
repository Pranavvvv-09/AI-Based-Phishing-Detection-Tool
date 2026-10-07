"""Evaluate the complete scorer (text model + header rules + link rules + trust).

The text-model metrics in models/manifest.json judge wording only. This script runs
messages through the full ``Scorer`` exactly as the app will, on data never used for
training, and compares each result with the text model alone.

Test sets (all held out from training):
* Honeypot future (English): the same 2026 honeypot emails the text model is tested on,
  as real .eml files, so headers, links and attachments count too.
* Honeypot future (all languages): every newest-30% honeypot email, including German,
  Portuguese, image-only, ... - what a real inbox would receive.
* Legitimate test split: held-out legitimate emails from Enron, SpamAssassin, CEAS_08,
  Ling. The CSVs contain no headers, so these run in content mode (text + links).
* Modern hand-written test half, scored as email text and as SMS.
* SMS test split (Mendeley + UCI) through the full SMS scorer (text + links).
* Frozen SMS sets (data/curated/sms_transactional_eval.csv, validation and test halves,
  and sms_independent_bank.csv): committed before the SMS false-positive fix and never
  used for training. The validation half chose the fix; the test half is only reported.

"Flagged" = review or quarantine (score >= 0.5); "quarantined" = score >= threshold.
Unanalysed (fail-safe) verdicts count as flagged, because they go to review.

Run:  python scripts/evaluate_scorer.py      (needs the datasets and both models; ~5 min)
Writes models/scorer_metrics.json.
"""

from __future__ import annotations

import csv
import html
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from phishguard import scorer as sc  # noqa: E402
from phishguard import text_model as tm  # noqa: E402
from phishguard.config import load_settings  # noqa: E402

OUT = ROOT / "models" / "scorer_metrics.json"


def _summarise(verdicts: list, positive: bool, threshold: float) -> dict:
    n = len(verdicts)
    flagged = sum(v.action in ("review", "quarantine") for v in verdicts)
    quarantined = sum(v.action == "quarantine" for v in verdicts)
    text_p = [v.components.get("text_probability") for v in verdicts if v.analysed]
    text_flag = sum(p >= 0.5 for p in text_p)
    text_quar = sum(p >= threshold for p in text_p)
    key = "recall" if positive else "false_positive_rate"
    rnd = lambda x: round(x / n, 4) if n else 0.0  # noqa: E731
    return {
        "n": n,
        "unanalysed_review": sum(not v.analysed for v in verdicts),
        f"scorer_{key}_flagged": rnd(flagged),
        f"scorer_{key}_quarantined": rnd(quarantined),
        f"text_only_{key}_flagged": rnd(text_flag),
        f"text_only_{key}_quarantined": rnd(text_quar),
    }


def _raw_email_texts(sources: list[str]) -> dict[str, str]:
    """Map the training-time dedup key back to the raw subject + body text."""
    csv.field_size_limit(10**8)
    mapping: dict[str, str] = {}
    for name in sources:
        df = pd.read_csv(tm.RAW_DIR / name, dtype=str, keep_default_na=False, on_bad_lines="skip")
        for raw in df["subject"] + "\n" + df["body"]:
            mapping.setdefault(tm.normalize_text(raw)[:2000], raw)
    return mapping


def _raw_sms_texts() -> dict[str, str]:
    mapping: dict[str, str] = {}
    mendeley = pd.read_csv(tm.RAW_DIR / tm.SMS_MENDELEY, dtype=str, keep_default_na=False)
    uci = pd.read_csv(tm.RAW_DIR / tm.SMS_UCI, sep="\t", header=None, names=["label", "text"],
                      dtype=str, keep_default_na=False, quoting=csv.QUOTE_NONE)
    for raw in [*mendeley["TEXT"], *uci["text"]]:
        clean = html.unescape(tm._UCI_PLACEHOLDER.sub(" ", raw))
        mapping.setdefault(tm.normalize_sms(clean)[:2000], clean)
    return mapping


def main() -> int:
    started = time.time()
    settings = load_settings({})  # defaults: threshold 0.8, trusted id mx.google.com
    threshold = settings.quarantine_threshold
    scorer = sc.Scorer(settings)
    results: dict = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "parameters": {
            "rule_scale": sc.RULE_SCALE, "text_clip": sc.TEXT_CLIP,
            "verified_sender_credit": sc.VERIFIED_SENDER_CREDIT,
            "aligned_links_credit": sc.ALIGNED_LINKS_CREDIT,
            "review_threshold": sc.REVIEW_THRESHOLD, "quarantine_threshold": threshold,
        },
    }

    # ---------------- email corpus and the exact training split
    corpus = tm.load_email_corpus()
    pot = corpus[corpus["source"] == tm.HONEYPOT]
    rest = corpus[corpus["source"] != tm.HONEYPOT]
    cutoff = pot["sample_no"].quantile(tm.HONEYPOT_TRAIN_FRACTION)
    _, test = train_test_split(rest, test_size=0.2, stratify=rest["label"], random_state=tm.SEED)

    email_dir = tm.RAW_DIR / tm.HONEYPOT / "email"
    english_ids = set(pot.loc[pot["sample_no"] > cutoff, "sample_no"].astype(int))
    future_files = []
    for path in email_dir.glob("sample-*.eml"):
        number = path.stem.removeprefix("sample-")
        if number.isdigit() and int(number) > cutoff:
            future_files.append((int(number), path))
    future_files.sort()
    english, everything = [], []
    for number, path in future_files:
        with path.open("rb") as handle:
            verdict = scorer.scan_email_bytes(handle.read(settings.max_email_bytes + 1))
        everything.append(verdict)
        if number in english_ids:
            english.append(verdict)
    results["honeypot_future_english"] = _summarise(english, True, threshold)
    results["honeypot_future_all_languages"] = _summarise(everything, True, threshold)

    # ---------------- legitimate held-out emails (content mode: no headers in the CSVs)
    legit = test[test["label"] == 0]
    raw_map = _raw_email_texts(sorted(set(legit["source"])))
    per_source = {}
    all_legit = []
    for source, group in legit.groupby("source"):
        verdicts = [scorer.scan_text(raw_map.get(key[:2000], key), kind="email")
                    for key in group["text"]]
        per_source[source] = _summarise(verdicts, False, threshold)
        all_legit += verdicts
    results["legit_test_content_mode"] = {"all": _summarise(all_legit, False, threshold),
                                          **per_source}

    # ---------------- modern hand-written test half
    curated = pd.read_csv(tm.CURATED, dtype={"text": str})
    modern = curated[curated["split"] == "test"]
    for kind in ("email", "sms"):
        verdicts = {lab: [scorer.scan_text(t, kind=kind)
                          for t in modern.loc[modern["label"] == lab, "text"]] for lab in (0, 1)}
        results[f"modern_test_as_{kind}"] = {
            "phishing": _summarise(verdicts[1], True, threshold),
            "legitimate": _summarise(verdicts[0], False, threshold),
        }

    # ---------------- SMS test split through the full SMS scorer
    sms = tm.load_sms_corpus()
    _, sms_test = train_test_split(sms, test_size=0.2, stratify=sms["label"],
                                   random_state=tm.SEED)
    sms_raw = _raw_sms_texts()
    sms_verdicts = {lab: [scorer.scan_sms(sms_raw.get(k[:2000], k))
                          for k in sms_test.loc[sms_test["label"] == lab, "text"]]
                    for lab in (0, 1)}
    results["sms_test_full_scorer"] = {
        "smishing": _summarise(sms_verdicts[1], True, threshold),
        "legitimate": _summarise(sms_verdicts[0], False, threshold),
    }

    # ---------------- frozen SMS evaluation sets (never trained on)
    frozen = pd.read_csv(ROOT / "data" / "curated" / "sms_transactional_eval.csv",
                         dtype={"text": str})
    for split in ("validation", "test"):
        part = frozen[frozen["split"] == split]
        verdicts = {lab: [scorer.scan_sms(t) for t in part.loc[part["label"] == lab, "text"]]
                    for lab in (0, 1)}
        results[f"sms_frozen_{split}"] = {
            "smishing": _summarise(verdicts[1], True, threshold),
            "legitimate": _summarise(verdicts[0], False, threshold),
        }
    independent = pd.read_csv(ROOT / "data" / "curated" / "sms_independent_bank.csv",
                              dtype={"text": str})
    results["sms_independent_bank"] = {
        "legitimate": _summarise([scorer.scan_sms(t) for t in independent["text"]], False,
                                 threshold),
    }

    # ---------------- fixtures
    fixtures = {}
    for path in sorted((ROOT / "tests" / "fixtures").glob("*.eml")):
        verdict = scorer.scan_email_bytes(path.read_bytes())
        fixtures[path.name] = {"action": verdict.action,
                               "score": None if verdict.score is None else round(verdict.score, 3)}
    results["fixtures"] = fixtures
    results["runtime_seconds"] = round(time.time() - started)

    OUT.write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
