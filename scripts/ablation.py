"""Ablation study: what does each dataset contribute?

Trains three models on different data (same splits, same seed) and scores them all
on identical test sets, so differences come from the training data alone.

Run:  python scripts/ablation.py     (needs scripts/download_data.py first; ~4 min)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from phishguard import text_model as tm  # noqa: E402

OLD_SOURCES = ["Nazario.csv", "Nigerian_Fraud.csv", "Enron.csv", "SpamAssasin.csv"]


def main() -> int:
    corpus = tm.load_email_corpus()
    curated = tm.load_curated()
    curated_train, modern = curated[curated.split == "train"], curated[curated.split == "test"]
    pot = corpus[corpus.source == tm.HONEYPOT]
    rest = corpus[corpus.source != tm.HONEYPOT]
    cutoff = pot.sample_no.quantile(tm.HONEYPOT_TRAIN_FRACTION)
    pot_train, pot_test = pot[pot.sample_no <= cutoff], pot[pot.sample_no > cutoff]
    train, test = train_test_split(
        rest, test_size=0.2, stratify=rest.label, random_state=tm.SEED
    )
    old_test = test[test.source.isin(OLD_SOURCES)]
    variants = {
        "A: original 4 sources": train[train.source.isin(OLD_SOURCES)],
        "B: + CEAS_08 & Ling ham": train,
        "C: + honeypot (final)": pd.concat([train, pot_train]),
    }
    rows = []
    for name, frame in variants.items():
        model = tm._fit(frame, curated_train)
        old = tm._metrics(old_test.label.to_numpy(), model.predict_proba(old_test.text)[:, 1])
        pot_scores = model.predict_proba(pot_test.text)[:, 1]
        mod = tm._metrics(modern.label.to_numpy(), model.predict_proba(modern.text)[:, 1])
        rows.append(
            {
                "variant": name,
                "train_rows": len(frame),
                "future_phish_recall": round(float((pot_scores >= 0.5).mean()), 4),
                "modern_recall": mod["recall"],
                "modern_FPR": mod["false_positive_rate"],
                "old_source_F1": old["f1"],
                "old_source_FPR": old["false_positive_rate"],
            }
        )
    print(pd.DataFrame(rows).to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
