"""Pre-registered experiment that chose how SMS wording is scored (reproducible).

Problem: every legitimate message in the public SMS corpora is a personal chat, so the
SMS model learned "formal = scam" and flagged genuine bank, UPI, OTP and delivery alerts.

Evaluation sets, frozen in a commit *before* any fix was built:
* data/curated/sms_transactional_eval.csv: 72 hand-written SMS (36 legitimate, 36
  smishing in the same formats). Validation half (24) chooses; test half (48) reports.
* data/curated/sms_independent_bank.csv: 12 real-format bank SMS written by independent
  developers (see THIRD_PARTY_NOTICES.md). Evaluation only.

Variants (fixed before training):
  V0  the SMS model as trained by ``python -m phishguard.text_model train-sms``
  V1  SMS model retrained with data/curated/sms_templates.csv added to the training split
      (weight 1.0) and a normaliser that also drops masked numbers ("XX1234")
  V2  V1 averaged with the email model in log-odds
  V3  V0 averaged with the email model in log-odds
Guard: on the public SMS test split, FPR <= 1% and recall >= 0.90 at 0.5.
Rule: highest validation F1 at 0.5 (smishing = positive); ties -> fewer validation false
positives at 0.8; then the simpler variant (V0, V1, V3, V2). The test half and the
independent set are scored only after the choice is fixed. Scores are text-model
probabilities (the frozen sets use .test domains, which the link rules ignore).

History: run 1 chose V1. An overlap audit then found synthetic templates paraphrasing
evaluation messages (up to 8 shared consecutive words), which flattered V1. They were
rewritten using overlap measures only (tests now enforce the limits) and the experiment
re-run unchanged: run 2, this script, chose V3. The test half was looked at in both runs.

Run:  python scripts/sms_experiment.py   (needs the datasets and the email model; ~10 s)
Writes models/sms_experiment.json.
"""

from __future__ import annotations

import csv
import html
import json
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from phishguard import text_model as tm  # noqa: E402

CURATED_DIR = ROOT / "data" / "curated"
OUT = ROOT / "models" / "sms_experiment.json"
TEMPLATE_WEIGHT = 1.0
GUARD_MAX_FPR, GUARD_MIN_RECALL = 0.01, 0.90
SIMPLICITY = ["V0", "V1", "V3", "V2"]
_MASKED_NUMBER = re.compile(r"(?<![A-Za-z])(?=[Xx*-]*\d)[\dXx*][\dXx*-]*(?![A-Za-z])")


def normalize_sms_masked(text: str) -> str:
    """V1/V2 normaliser: ``tm.normalize_sms`` that also drops masked numbers."""
    text = text[: tm.MAX_TEXT_CHARS * 2]
    text = tm._URL.sub(" ", text)
    text = tm._EMAIL.sub(" ", text)
    text = _MASKED_NUMBER.sub(" ", text)
    text = tm._NUMBER.sub(" ", text)
    return tm._SPACE.sub(" ", text).strip().lower()[: tm.MAX_TEXT_CHARS]


def load_corpus(normalize) -> pd.DataFrame:
    """Same rows as ``tm.load_sms_corpus`` (checked below), plus the cleaned raw text."""
    mendeley = pd.read_csv(tm.RAW_DIR / tm.SMS_MENDELEY, dtype=str, keep_default_na=False)
    uci = pd.read_csv(tm.RAW_DIR / tm.SMS_UCI, sep="\t", header=None, names=["label", "text"],
                      dtype=str, keep_default_na=False, quoting=csv.QUOTE_NONE)

    def frame(texts: pd.Series, labels: pd.Series, source: str) -> pd.DataFrame:
        clean = texts.map(lambda t: html.unescape(tm._UCI_PLACEHOLDER.sub(" ", t)))
        return pd.DataFrame({"raw": clean, "text": clean.map(normalize), "label": labels,
                             "source": source})

    corpus = pd.concat(
        [frame(mendeley["TEXT"], mendeley["LABEL"].str.strip().str.lower()
               .map({"ham": 0, "smishing": 1}), tm.SMS_MENDELEY),
         frame(uci["text"], uci["label"].str.strip().map({"ham": 0}), tm.SMS_UCI)],
        ignore_index=True,
    )
    corpus = corpus[corpus["text"].str.len() >= 2]
    corpus = corpus.loc[~corpus["text"].str.slice(0, 2000).duplicated()]
    return corpus.dropna(subset=["label"]).astype({"label": int}).reset_index(drop=True)


def curated(normalize) -> pd.DataFrame:
    df = pd.read_csv(tm.CURATED, dtype={"text": str})
    return df.assign(raw=df["text"], text=df["text"].map(normalize), source="curated")


def fit(train: pd.DataFrame, curated_train: pd.DataFrame, templates: pd.DataFrame | None):
    frames, weights = [train], [np.ones(len(train))]
    if templates is not None:
        frames.append(templates)
        weights.append(np.full(len(templates), TEMPLATE_WEIGHT))
    frames.append(curated_train)
    weights.append(np.full(len(curated_train), tm.SMS_CURATED_WEIGHT))
    frame = pd.concat(frames, ignore_index=True)
    return tm.build_pipeline(tm.SMS_STOP_WORDS).fit(
        frame["text"], frame["label"], clf__sample_weight=np.concatenate(weights))


def _logit(p: np.ndarray) -> np.ndarray:
    p = np.clip(p, 1e-9, 1 - 1e-9)
    return np.log(p / (1 - p))


def rates(labels, scores) -> dict:
    y, p = np.asarray(labels), np.asarray(scores)
    legit, smish = p[y == 0], p[y == 1]
    out: dict = {"n_legit": int(len(legit)), "n_smish": int(len(smish))}
    if len(legit):
        out.update(FP_05=int((legit >= 0.5).sum()), FP_08=int((legit >= 0.8).sum()),
                   FPR_05=round(float((legit >= 0.5).mean()), 4),
                   FPR_08=round(float((legit >= 0.8).mean()), 4))
    if len(smish):
        out.update(recall_05=round(float((smish >= 0.5).mean()), 4),
                   recall_08=round(float((smish >= 0.8).mean()), 4))
    if len(legit) and len(smish):
        out["F1_05"] = round(float(f1_score(y, (p >= 0.5).astype(int), zero_division=0)), 4)
    return out


def main() -> int:
    corpus_v0 = load_corpus(tm.normalize_sms)
    shipped = tm.load_sms_corpus()
    if corpus_v0["text"].tolist() != shipped["text"].tolist():
        raise SystemExit("corpus mirror differs from tm.load_sms_corpus - update this script")
    corpus_v1 = load_corpus(normalize_sms_masked)
    cur_v0, cur_v1 = curated(tm.normalize_sms), curated(normalize_sms_masked)
    templates = pd.read_csv(CURATED_DIR / "sms_templates.csv", dtype={"text": str})
    templates = templates.assign(text=templates["text"].map(normalize_sms_masked))
    frozen = pd.read_csv(CURATED_DIR / "sms_transactional_eval.csv", dtype={"text": str})
    independent = pd.read_csv(CURATED_DIR / "sms_independent_bank.csv", dtype={"text": str})

    def split(corpus: pd.DataFrame):
        return train_test_split(corpus, test_size=0.2, stratify=corpus["label"],
                                random_state=tm.SEED)

    train_v0, test_v0 = split(corpus_v0)
    train_v1, test_v1 = split(corpus_v1)
    v0 = fit(train_v0, cur_v0[cur_v0["split"] == "train"], None)
    v1 = fit(train_v1, cur_v1[cur_v1["split"] == "train"], templates)
    email = tm.load_text_model("email_model")  # hash-verified

    def p_v0(raw: list[str]) -> np.ndarray:
        return v0.predict_proba([tm.normalize_sms(t) for t in raw])[:, 1]

    def p_v1(raw: list[str]) -> np.ndarray:
        return v1.predict_proba([normalize_sms_masked(t) for t in raw])[:, 1]

    def p_email(raw: list[str]) -> np.ndarray:
        return np.array([email.predict_proba(t) for t in raw])

    def blend(a: np.ndarray, b: np.ndarray) -> np.ndarray:
        return 1 / (1 + np.exp(-(_logit(a) + _logit(b)) / 2))

    variants = {
        "V0": (p_v0, test_v0, cur_v0),
        "V1": (p_v1, test_v1, cur_v1),
        "V2": (lambda raw: blend(p_v1(raw), p_email(raw)), test_v1, cur_v1),
        "V3": (lambda raw: blend(p_v0(raw), p_email(raw)), test_v0, cur_v0),
    }
    validation = frozen[frozen["split"] == "validation"]
    results: dict = {}
    for name, (prob, test, cur) in variants.items():
        modern = cur[cur["split"] == "test"]
        results[name] = {
            "validation": rates(validation["label"], prob(validation["text"].tolist())),
            "in_distribution": rates(test["label"], prob(test["raw"].tolist())),
            "modern_test": rates(modern["label"], prob(modern["raw"].tolist())),
        }

    eligible = [v for v in SIMPLICITY
                if results[v]["in_distribution"]["FPR_05"] <= GUARD_MAX_FPR
                and results[v]["in_distribution"]["recall_05"] >= GUARD_MIN_RECALL]
    choice = min(eligible, key=lambda v: (-results[v]["validation"]["F1_05"],
                                          results[v]["validation"]["FP_08"], SIMPLICITY.index(v)))

    # Only now: the test half and the independent set.
    test_half = frozen[frozen["split"] == "test"]
    for name, (prob, _, _) in variants.items():
        scores = prob(test_half["text"].tolist())
        results[name]["test"] = rates(test_half["label"], scores)
        results[name]["independent"] = rates(independent["label"],
                                             prob(independent["text"].tolist()))
        wrong = (scores >= 0.5).astype(int) != test_half["label"].to_numpy()
        results[name]["test_errors_by_category"] = (
            test_half.loc[wrong, "category"].value_counts().sort_index().to_dict())

    report = {"guard": {"max_fpr": GUARD_MAX_FPR, "min_recall": GUARD_MIN_RECALL},
              "eligible": eligible, "choice": choice, "variants": results}
    OUT.write_text(json.dumps(report, indent=1) + "\n")
    print(f"{'':3} {'val F1':>6} {'val FP':>6} {'test FPR':>8} {'test rec':>8} "
          f"{'indep FP':>8} {'mod FPR':>7} {'pub rec':>7}")
    for name in ("V0", "V1", "V2", "V3"):
        r = results[name]
        print(f"{name:3} {r['validation']['F1_05']:6.3f} {r['validation']['FP_05']:6d} "
              f"{r['test']['FPR_05']:8.3f} {r['test']['recall_05']:8.3f} "
              f"{r['independent']['FP_05']:8d} {r['modern_test']['FPR_05']:7.3f} "
              f"{r['in_distribution']['recall_05']:7.3f}")
    print(f"eligible: {eligible} | choice: {choice} | wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
