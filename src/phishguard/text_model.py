"""TF-IDF + Logistic Regression model of phishing *intent* in email text.

Why not grammar? In 2026 most phishing is AI-written with perfect grammar, so
spelling mistakes are a fading signal. What still separates phishing is what the
message *asks you to do*: verify, pay, click, reply with codes, under urgency.
TF-IDF word/bigram weights capture those patterns, and a linear model keeps
every decision explainable (each word has a visible weight).

ML security measures:
* Text is normalised before training *and* prediction by the same function.
  URLs and email addresses are *removed*: links and senders are judged by
  url_checks/header_checks, and the Enron corpus had them stripped by its
  publisher, so leaving them in taught the model "has a link = phishing"
  (measured: 10.5% false positives on unseen legitimate mail). Removing them
  also keeps raw addresses out of the vocabulary saved to disk (privacy).
* Corpus-identifying words (``enron``, ``jose``/``monkey`` from the Nazario
  mailbox, encoding residue like ``utf``) are stop words, so the model can't
  "cheat" by recognising which dataset a message came from (shortcut learning).
* Exact and near-duplicate messages are removed *before* the train/test split,
  so the same campaign can't sit in both and inflate the scores (data leakage).
* Leave-one-corpus-out tests (train without a legitimate-mail corpus, then
  measure false positives on it) show how the model behaves on mail unlike its
  training data, which the easy in-distribution split hides.
* ``joblib`` files are pickles, and unpickling can execute code. A model is only
  loaded after its SHA-256 matches the committed ``models/manifest.json``.
* Training is deterministic (``random_state=42``, single-threaded) so CI is
  reproducible.
* Modern phishing comes from the phishing_pot honeypot corpus (2022-2026, real
  ``.eml`` files parsed with our own hardened parser). It is multilingual while
  all legitimate data is English, so only English messages are used: otherwise
  the model would learn "German/Portuguese = phishing" (a language shortcut).
  It is split by *time* (oldest 70% train, newest 30% test) to measure how well
  the model catches future campaigns.
* The public corpora are mostly 2004-2020 English mail. A small hand-written set
  (``data/curated/modern_lures.csv``: AI-polished lures, gift-card/payroll BEC,
  Indian KYC/UPI/digital-arrest/courier/task scams, Hinglish, plus alarming-but-
  genuine OTP and bank alerts) is split per category: the *train* half is added
  with a fixed weight chosen in advance, and the *test* half is only ever used
  for the ``modern_test`` metric.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from .parser import EmailParseError, ParsedEmail, parse_email_file

ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = ROOT / "data" / "raw"
MODELS_DIR = ROOT / "models"
MANIFEST = MODELS_DIR / "manifest.json"
SEED = 42
MAX_TEXT_CHARS = 20_000
CURATED = ROOT / "data" / "curated" / "modern_lures.csv"
CURATED_WEIGHT = 20.0  # fixed a priori (not tuned on the test half)

_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"']{1,2048}", re.IGNORECASE)
_EMAIL = re.compile(r"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}")
_NUMBER = re.compile(r"\d+")
_SPACE = re.compile(r"\s+")
WORD_PATTERN = r"(?u)\b[a-z][a-z]+\b"  # words of 2+ letters; numbers are already masked

# Words that identify a *dataset* rather than phishing behaviour.
CORPUS_ARTIFACTS = [
    "enron", "vince", "kaminski", "louise", "daren", "houston", "ect", "hou", "jeff",
    "monkey", "jose", "nazario", "utf", "iso", "charset", "http", "https", "www", "com",
    "net", "org", "html", "htm", "nbsp", "subject", "cc", "fw", "fwd", "url",
    # honeypot anonymisation placeholder ("phishing@pot") residue. "phishing" itself
    # never occurs in the (older) legitimate corpora, so the model could only learn it
    # as a phishing signal and would flag genuine security-awareness notices.
    "pot", "phishing",
    # era markers: normal in modern legitimate mail, absent from 2000-2008 ham
    "unsubscribe", "preferences", "copyright", "reserved", "app", "apps", "ai",
    # non-English residue in otherwise-English honeypot mail (language shortcut)
    "de", "para", "que", "da", "em", "la", "el", "und", "der", "die",
    "enviado", "assunto", "remetente",  # Portuguese forwarded-message header labels
]

# Phishing = credential/payment scams. Spam rows are excluded on purpose: spam is
# unwanted marketing, not phishing, and mixing them would blur what we detect.
EMAIL_SOURCES = {
    # file: (label column filter, our label)
    "Nazario.csv": ("1", 1),
    "Nigerian_Fraud.csv": ("1", 1),
    "Enron.csv": ("0", 0),
    "SpamAssasin.csv": ("0", 0),
    "CEAS_08.csv": ("0", 0),
    "Ling.csv": ("0", 0),
}
LEGIT_SOURCES = ("Enron.csv", "SpamAssasin.csv", "CEAS_08.csv", "Ling.csv")
HONEYPOT = "phishing_pot"
HONEYPOT_CACHE_VERSION = 2  # bump when honeypot text extraction changes
_HONEYPOT_PLACEHOLDER = re.compile(r"phishing@pot", re.IGNORECASE)
HONEYPOT_TRAIN_FRACTION = 0.7  # oldest 70% by sample number train, newest 30% test
PROCESSED_DIR = ROOT / "data" / "processed"

# Common English function words: a cheap, transparent language check.
_EN_WORDS = frozenset(
    "the and to of you your is for in on this that with we be are it please have will "
    "our from as at by or if not can has an all".split()
)


class ModelIntegrityError(RuntimeError):
    """The model file is missing from the manifest or its hash doesn't match."""


def normalize_text(text: str) -> str:
    """Lower-case, drop URLs/emails, mask numbers, collapse whitespace, cap length."""
    text = text[: MAX_TEXT_CHARS * 2]
    text = _URL.sub(" ", text)
    text = _EMAIL.sub(" ", text)
    text = _NUMBER.sub(" numtoken ", text)
    return _SPACE.sub(" ", text).strip().lower()[:MAX_TEXT_CHARS]


def email_text(email: ParsedEmail) -> str:
    """The text the email model sees: subject + visible body."""
    return f"{email.subject}\n{email.body}"


def build_pipeline() -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    token_pattern=WORD_PATTERN,
                    stop_words=CORPUS_ARTIFACTS,
                    ngram_range=(1, 2),
                    min_df=3,
                    max_df=0.9,
                    max_features=50_000,
                    sublinear_tf=True,
                    strip_accents="unicode",
                    dtype=np.float32,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    C=4.0,
                    class_weight="balanced",  # phishing is the minority class
                    solver="liblinear",
                    max_iter=1000,
                    random_state=SEED,
                ),
            ),
        ]
    )


def load_email_corpus(raw_dir: Path = RAW_DIR) -> pd.DataFrame:
    """Load, label, normalise and de-duplicate the email datasets."""
    csv.field_size_limit(10**8)
    frames = []
    for name, (wanted, label) in EMAIL_SOURCES.items():
        path = raw_dir / name
        if not path.exists():
            raise FileNotFoundError(f"{path} missing - run scripts/download_data.py")
        df = pd.read_csv(path, dtype=str, keep_default_na=False, on_bad_lines="skip")
        df = df[df["label"].str.strip() == wanted]
        frames.append(
            pd.DataFrame(
                {
                    "text": (df["subject"] + "\n" + df["body"]).map(normalize_text),
                    "label": label,
                    "source": name,
                }
            )
        )
    honeypot = load_honeypot(raw_dir)
    if honeypot is not None:
        frames.append(honeypot)
    corpus = pd.concat(frames, ignore_index=True)
    corpus = corpus[corpus["text"].str.len() >= 20]
    # Near-duplicate removal: after masking numbers/URLs, template variants collapse.
    # The first copy wins (earliest honeypot sample, phishing sources before ham),
    # so a text can never appear twice, with the same or with conflicting labels.
    key = corpus["text"].str.slice(0, 2000)
    corpus = corpus.loc[~key.duplicated()]
    return corpus.reset_index(drop=True)


def is_english(text: str) -> bool:
    """Heuristic: at least 5 common English function words making up 8%+ of tokens."""
    tokens = text.split()
    hits = sum(token in _EN_WORDS for token in tokens)
    return hits >= 5 and hits / max(len(tokens), 1) >= 0.08


def load_honeypot(raw_dir: Path = RAW_DIR, cache_dir: Path = PROCESSED_DIR) -> pd.DataFrame | None:
    """English phishing_pot emails as (text, label=1, source, sample_no).

    Parsing ~12k hostile .eml files takes ~2 minutes, so normalised text is cached in
    data/processed/ (gitignored), keyed by the number and total size of the files.
    """
    email_dir = raw_dir / HONEYPOT / "email"
    if not email_dir.is_dir():
        return None
    files = sorted(email_dir.glob("sample-*.eml"))
    signature = f"{len(files)}-{sum(f.stat().st_size for f in files)}"
    cache = cache_dir / f"{HONEYPOT}_v{HONEYPOT_CACHE_VERSION}_{signature}.csv"
    df = None
    if cache.exists():
        df = pd.read_csv(cache, dtype={"text": str}, keep_default_na=False)
        if df.empty and files:  # never trust an empty cache for a non-empty folder
            df = None
    if df is None:
        rows = []
        for path in files:
            number = path.stem.removeprefix("sample-")
            if not number.isdigit():
                continue
            try:
                raw_text = email_text(parse_email_file(path))
                # The corpus replaces victims' addresses with "phishing@pot"; left in,
                # the model learns the words "phishing"/"pot" (a dataset fingerprint).
                text = normalize_text(_HONEYPOT_PLACEHOLDER.sub(" ", raw_text))
            except EmailParseError:
                continue  # over-limit or not an email: skipped, never crashes training
            rows.append((int(number), text, is_english(text)))
        df = pd.DataFrame(rows, columns=["sample_no", "text", "english"])
        cache_dir.mkdir(parents=True, exist_ok=True)
        tmp = cache.with_suffix(".csv.part")
        df.to_csv(tmp, index=False)
        tmp.replace(cache)  # atomic: a crash can never leave a half-written cache
    df = df[df["english"].astype(str) == "True"]
    return pd.DataFrame(
        {"text": df["text"], "label": 1, "source": HONEYPOT, "sample_no": df["sample_no"]}
    )


def load_curated(path: Path = CURATED) -> pd.DataFrame:
    """Hand-written modern examples with an explicit train/test split column."""
    df = pd.read_csv(path, dtype={"text": str, "split": str, "category": str})
    if not set(df["split"]) <= {"train", "test"} or not set(df["label"]) <= {0, 1}:
        raise ValueError("curated file must use split in {train,test} and label in {0,1}")
    return df.assign(text=df["text"].map(normalize_text), source="curated")


def _fit(frame: pd.DataFrame, curated_train: pd.DataFrame | None) -> Pipeline:
    weights = np.ones(len(frame))
    if curated_train is not None and len(curated_train):
        frame = pd.concat([frame, curated_train], ignore_index=True)
        weights = np.concatenate([weights, np.full(len(curated_train), CURATED_WEIGHT)])
    return build_pipeline().fit(frame["text"], frame["label"], clf__sample_weight=weights)


def _metrics(y_true, scores, threshold: float = 0.5) -> dict[str, float]:
    pred = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "n": int(len(y_true)),
        "precision": round(float(precision_score(y_true, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, pred, zero_division=0)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if fp + tn else 0.0, 4),
        "roc_auc": round(float(roc_auc_score(y_true, scores)), 4),
        "pr_auc": round(float(average_precision_score(y_true, scores)), 4),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


@dataclass
class TrainResult:
    model: Pipeline
    metrics: dict


def train_email_model(corpus: pd.DataFrame, curated: pd.DataFrame | None = None) -> TrainResult:
    """Train on a stratified 80% split and report three kinds of evidence.

    * ``test_in_distribution``: the held-out 20% (same sources as training).
    * ``leave_one_corpus_out``: for each legitimate corpus, a model trained
      *without* it is scored on it, showing false positives on unfamiliar mail.
    * ``modern_test``: the held-out half of the hand-written modern examples.
    * ``honeypot_future_test``: the newest 30% of honeypot phishing (time split).
    The returned model is the one trained on the full 80% split (+ curated train half
    + oldest 70% of the honeypot).
    """
    curated_train = curated[curated["split"] == "train"] if curated is not None else None
    pot = corpus[corpus["source"] == HONEYPOT]
    rest = corpus[corpus["source"] != HONEYPOT]
    train, test = train_test_split(rest, test_size=0.2, stratify=rest["label"], random_state=SEED)
    if len(pot):
        cutoff = pot["sample_no"].quantile(HONEYPOT_TRAIN_FRACTION)
        pot_train, pot_test = pot[pot["sample_no"] <= cutoff], pot[pot["sample_no"] > cutoff]
        train = pd.concat([train, pot_train], ignore_index=True)
    model = _fit(train, curated_train)
    metrics: dict = {
        "test_in_distribution": _metrics(
            test["label"].to_numpy(), model.predict_proba(test["text"])[:, 1]
        ),
        "class_counts_train": {
            "phishing": int(train["label"].sum()),
            "legitimate": int((train["label"] == 0).sum()),
            "by_source": {k: int(v) for k, v in train["source"].value_counts().items()},
        },
        "leave_one_corpus_out": {},
    }
    for held in LEGIT_SOURCES:
        unseen = corpus[corpus["source"] == held]
        subset = train[train["source"] != held]
        if unseen.empty or subset["label"].nunique() < 2:
            continue
        probe = _fit(subset, curated_train)
        phish_test = test[test["label"] == 1]
        unseen_scores = probe.predict_proba(unseen["text"])[:, 1]
        metrics["leave_one_corpus_out"][held] = {
            "n_unseen_legit": int(len(unseen)),
            "false_positive_rate": round(float((unseen_scores >= 0.5).mean()), 4),
            "false_positive_rate_at_quarantine_0.8": round(
                float((unseen_scores >= 0.8).mean()), 4
            ),
            "phishing_recall": round(
                float((probe.predict_proba(phish_test["text"])[:, 1] >= 0.5).mean()), 4
            ),
        }
    if len(pot):
        pot_scores = model.predict_proba(pot_test["text"])[:, 1]
        metrics["honeypot_future_test"] = {
            "n": int(len(pot_test)),
            "first_sample_no": int(pot_test["sample_no"].min()),
            "recall": round(float((pot_scores >= 0.5).mean()), 4),
            "recall_at_quarantine_0.8": round(float((pot_scores >= 0.8).mean()), 4),
        }
    if curated is not None:
        modern = curated[curated["split"] == "test"]
        scores = model.predict_proba(modern["text"])[:, 1]
        metrics["modern_test"] = _metrics(modern["label"].to_numpy(), scores)
        wrong = (scores >= 0.5).astype(int) != modern["label"].to_numpy()
        metrics["modern_test"]["errors_by_category"] = (
            modern.loc[wrong, "category"].value_counts().sort_index().to_dict()
        )
    return TrainResult(model=model, metrics=metrics)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_model(model: Pipeline, name: str, metrics: dict, models_dir: Path = MODELS_DIR) -> Path:
    """Write ``<name>.joblib`` and record its SHA-256 + metrics in the manifest."""
    models_dir.mkdir(parents=True, exist_ok=True)
    path = models_dir / f"{name}.joblib"
    tmp = path.with_suffix(".joblib.part")
    joblib.dump(model, tmp, compress=3)
    tmp.replace(path)
    manifest_path = models_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    manifest[name] = {
        "file": path.name,
        "sha256": sha256_file(path),
        "trained_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sklearn_version": sklearn.__version__,
        "metrics": metrics,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return path


def load_model(name: str, models_dir: Path = MODELS_DIR) -> Pipeline:
    """Load a model only if its SHA-256 matches the manifest (unpickling runs code)."""
    manifest_path = models_dir / "manifest.json"
    if not manifest_path.exists():
        raise ModelIntegrityError("models/manifest.json not found")
    entry = json.loads(manifest_path.read_text()).get(name)
    if not entry or not re.fullmatch(r"[\w.-]+\.joblib", entry.get("file", "")):
        raise ModelIntegrityError(f"no valid manifest entry for model '{name}'")
    path = models_dir / entry["file"]
    if not path.is_file():
        raise ModelIntegrityError(f"model file {path.name} not found - train it first")
    if sha256_file(path) != entry["sha256"]:
        raise ModelIntegrityError(
            f"{path.name} does not match its manifest hash - refusing to load"
        )
    return joblib.load(path)  # safe: bytes verified against the committed hash


class TextModel:
    """Thin wrapper used by the scorer: probability + the words that drove it."""

    def __init__(self, pipeline: Pipeline) -> None:
        self.pipeline = pipeline
        self._vec: TfidfVectorizer = pipeline.named_steps["tfidf"]
        self._coef = pipeline.named_steps["clf"].coef_[0]
        self._vocab = self._vec.get_feature_names_out()

    def predict_proba(self, text: str) -> float:
        return float(self.pipeline.predict_proba([normalize_text(text)])[0, 1])

    def top_terms(self, text: str, k: int = 5) -> list[tuple[str, float]]:
        """Terms in ``text`` that pushed the score most towards phishing."""
        row = self._vec.transform([normalize_text(text)])
        contributions = row.multiply(self._coef).tocsr()
        pairs = sorted(
            zip(contributions.indices, contributions.data, strict=True), key=lambda p: -p[1]
        )
        return [(str(self._vocab[i]), round(float(v), 3)) for i, v in pairs[:k] if v > 0]


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv != ["train-email"]:
        print("usage: python -m phishguard.text_model train-email", file=sys.stderr)
        return 2
    corpus = load_email_corpus()
    counts = corpus.groupby(["source", "label"]).size().to_dict()
    print("corpus after de-duplication:", {f"{s}:{lbl}": n for (s, lbl), n in counts.items()})
    curated = load_curated() if CURATED.exists() else None
    result = train_email_model(corpus, curated)
    path = save_model(result.model, "email_model", result.metrics)
    print(json.dumps(result.metrics, indent=2))
    print(f"saved {path.relative_to(ROOT)} (sha256 recorded in models/manifest.json)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
