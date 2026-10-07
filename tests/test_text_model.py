import json
import time
from pathlib import Path

import pandas as pd
import pytest

from phishguard import text_model
from phishguard.parser import parse_email_file
from phishguard.text_model import (
    ModelIntegrityError,
    TextModel,
    build_pipeline,
    email_text,
    load_email_corpus,
    load_model,
    normalize_text,
    save_model,
    train_email_model,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
REAL_MODEL = (ROOT / "models" / "email_model.joblib").exists()

PHISH = [
    "dear customer your account has been suspended verify your password now",
    "urgent kindly confirm your bank details to avoid account closure",
    "your mailbox is full click here to verify your account today",
    "we detected unusual activity please update your payment information",
    "dear friend i need your help to transfer funds kindly reply urgently",
    "security alert verify your identity immediately or lose access",
]
LEGIT = [
    "hi team the meeting is moved to thursday see you there thanks",
    "attached are the notes from the project review let me know questions",
    "lunch on friday? the new place near the office looks good",
    "please review the draft report before the call next week",
    "the quarterly numbers look fine we can discuss tomorrow",
    "thanks for the update i will send the slides tonight",
]


def tiny_corpus(n=6):
    rows = [(t, 1, "Nazario.csv") for t in PHISH * n] + [(t, 0, "Enron.csv") for t in LEGIT * n]
    rows += [(t + " list", 0, "SpamAssasin.csv") for t in LEGIT * n]
    df = pd.DataFrame(rows, columns=["text", "label", "source"])
    df["text"] = [f"{t} {i}x" for i, t in enumerate(df["text"])]  # unique rows
    return df.assign(text=df["text"].map(normalize_text))


# ---------- normalisation ----------


def test_normalize_removes_urls_emails_and_masks_numbers():
    out = normalize_text("Visit https://evil.test/x?a=1 or mail Bob@Example.com, code 123456!")
    assert "evil" not in out and "example" not in out and "bob" not in out
    assert "numtoken" in out and "123456" not in out
    assert out == out.lower()


def test_normalize_caps_length_and_is_fast():
    start = time.perf_counter()
    out = normalize_text("a@" * 200_000 + "http://" + "b" * 200_000)
    assert len(out) <= text_model.MAX_TEXT_CHARS
    assert time.perf_counter() - start < 1.0


def test_corpus_artifacts_are_stop_words():
    vec = build_pipeline().named_steps["tfidf"]
    assert {"enron", "jose", "monkey", "utf", "www"} <= set(vec.stop_words)


# ---------- training ----------


def test_training_is_deterministic_and_reports_metrics():
    corpus = tiny_corpus()
    a = train_email_model(corpus)
    b = train_email_model(corpus)
    assert (a.model.named_steps["clf"].coef_ == b.model.named_steps["clf"].coef_).all()
    m = a.metrics
    assert {"test_in_distribution", "leave_one_corpus_out", "class_counts_train"} <= m.keys()
    assert m["test_in_distribution"]["recall"] >= 0.9
    assert set(m["leave_one_corpus_out"]) == {"Enron.csv", "SpamAssasin.csv"}


def test_corpus_loader_filters_labels_and_dedupes(tmp_path):
    cols = ["subject", "body", "label"]
    phish = pd.DataFrame([["Verify", "Dear user verify your account now please", "1"]] * 3,
                         columns=cols)
    ham = pd.DataFrame(
        [["Notes", "Meeting notes attached for the review team", "0"],
         ["Buy now", "Cheap watches marketing spam offer today only", "1"]],  # spam: excluded
        columns=cols,
    )
    for name, (_, label) in text_model.EMAIL_SOURCES.items():  # every configured source
        (phish if label == 1 else ham).to_csv(tmp_path / name, index=False)
    corpus = load_email_corpus(tmp_path)
    assert "marketing" not in " ".join(corpus["text"])  # spam rows are not "legitimate"
    assert corpus["text"].is_unique  # duplicates removed across files
    assert set(corpus["label"]) == {0, 1}


def test_missing_dataset_has_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="download_data"):
        load_email_corpus(tmp_path)


# ---------- model integrity (pickle safety) ----------


@pytest.fixture
def saved(tmp_path):
    result = train_email_model(tiny_corpus())
    save_model(result.model, "m", result.metrics, models_dir=tmp_path)
    return tmp_path


def test_save_and_verified_load_roundtrip(saved):
    model = load_model("m", models_dir=saved)
    manifest = json.loads((saved / "manifest.json").read_text())
    assert len(manifest["m"]["sha256"]) == 64
    assert TextModel(model).predict_proba(PHISH[0]) > 0.5


def test_tampered_model_is_refused(saved):
    with (saved / "m.joblib").open("ab") as handle:
        handle.write(b"tampered")
    with pytest.raises(ModelIntegrityError, match="hash"):
        load_model("m", models_dir=saved)


def test_manifest_path_traversal_is_refused(saved):
    manifest = json.loads((saved / "manifest.json").read_text())
    manifest["m"]["file"] = "../../etc/evil.joblib"
    (saved / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ModelIntegrityError):
        load_model("m", models_dir=saved)


def test_unknown_model_and_missing_manifest(saved, tmp_path):
    with pytest.raises(ModelIntegrityError):
        load_model("nope", models_dir=saved)
    with pytest.raises(ModelIntegrityError):
        load_model("m", models_dir=tmp_path / "empty")


def test_top_terms_explain_phishing(saved):
    tm = TextModel(load_model("m", models_dir=saved))
    terms = [t for t, _ in tm.top_terms("dear customer verify your account", k=3)]
    assert terms and all(w > 0 for _, w in tm.top_terms("verify your account"))
    assert tm.top_terms("") == []


# ---------- the real trained model (skipped when datasets/model are absent, e.g. in CI) ----------


@pytest.mark.skipif(not REAL_MODEL, reason="run scripts/download_data.py + train-email first")
def test_real_model_meets_quality_bar():
    manifest = json.loads((ROOT / "models" / "manifest.json").read_text())
    metrics = manifest["email_model"]["metrics"]
    assert metrics["test_in_distribution"]["recall"] >= 0.95
    assert metrics["test_in_distribution"]["false_positive_rate"] <= 0.01
    for held in metrics["leave_one_corpus_out"].values():
        assert held["false_positive_rate_at_quarantine_0.8"] <= 0.05


@pytest.mark.skipif(not REAL_MODEL, reason="run scripts/download_data.py + train-email first")
def test_real_model_on_fixtures():
    tm = TextModel(load_model("email_model"))
    score = {
        name: tm.predict_proba(email_text(parse_email_file(FIXTURES / name)))
        for name in ("legit_newsletter.eml", "phish_spoofed_sender.eml", "phish_untrusted_pass.eml")
    }
    assert score["legit_newsletter.eml"] < 0.2
    assert score["phish_spoofed_sender.eml"] > 0.9
    assert score["phish_untrusted_pass.eml"] > 0.8


def test_download_script_pins_https_and_hashes():
    import importlib.util

    spec = importlib.util.spec_from_file_location("dl", ROOT / "scripts" / "download_data.py")
    dl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dl)
    for url, sha in dl.DATASETS.values():
        assert url.startswith("https://")
        assert sha and len(sha) == 64
    for url, commit, subdir in dl.GIT_SOURCES.values():
        assert url.startswith("https://") and len(commit) == 40 and subdir


# ---------- curated modern examples (Day 1-5 known-issue fixes) ----------

CURATED = ROOT / "data" / "curated" / "modern_lures.csv"


def test_curated_file_is_balanced_and_split_per_category():
    df = pd.read_csv(CURATED)
    assert set(df["split"]) == {"train", "test"} and set(df["label"]) == {0, 1}
    assert df["id"].is_unique and df["text"].is_unique
    counts = df.groupby(["label", "split"]).size()
    assert counts.min() >= 25 and counts.max() - counts.min() <= 2
    for _, group in df.groupby("category"):
        assert set(group["split"]) == {"train", "test"}  # every category is tested


def test_curated_file_has_no_real_links_or_addresses():
    import re

    text = " ".join(pd.read_csv(CURATED)["text"])
    assert not re.search(r"https?://|www\.|@[a-z0-9-]+\.[a-z]", text, re.IGNORECASE)


def test_load_curated_validates(tmp_path):
    from phishguard.text_model import load_curated

    bad = tmp_path / "bad.csv"
    bad.write_text("id,split,label,category,text\n1,validation,1,x,hello there\n")
    with pytest.raises(ValueError):
        load_curated(bad)
    good = load_curated(CURATED)
    assert (good["source"] == "curated").all()


def test_curated_train_half_changes_model_and_test_half_is_reported():
    corpus = tiny_corpus()
    curated = pd.DataFrame(
        {
            "text": [normalize_text(t) for t in (
                "buy gift cards and send me the codes urgently",
                "enter your upi pin to receive the refund",
                "your otp is numtoken do not share it with anyone",
                "your parcel was delivered today",
            )],
            "label": [1, 1, 0, 0],
            "split": ["train", "test", "train", "test"],
            "category": ["bec", "upi", "otp", "delivery"],
            "source": "curated",
        }
    )
    plain = train_email_model(corpus)
    boosted = train_email_model(corpus, curated)
    assert "modern_test" in boosted.metrics and "modern_test" not in plain.metrics
    assert boosted.metrics["modern_test"]["n"] == 2  # only the test half is scored
    gift = normalize_text("buy gift cards and send me the codes urgently")
    assert boosted.model.predict_proba([gift])[0, 1] > plain.model.predict_proba([gift])[0, 1]


@pytest.mark.skipif(not REAL_MODEL, reason="run scripts/bootstrap.py first")
def test_real_model_modern_test_bar():
    manifest = json.loads((ROOT / "models" / "manifest.json").read_text())
    metrics = manifest["email_model"]["metrics"]
    modern = metrics["modern_test"]
    assert modern["recall"] >= 0.75
    # Raised from 0.10 when the honeypot corpus was added: 3/28 modern legit messages
    # ("your account" notices) vs 2/28 before, in exchange for future-phishing recall
    # rising from 40% to 88% (see data/README.md, "Ablation"). Accepted trade-off.
    assert modern["false_positive_rate"] <= 0.15
    assert metrics["honeypot_future_test"]["recall"] >= 0.85


def test_bootstrap_is_noop_when_model_valid(monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location("boot", ROOT / "scripts" / "bootstrap.py")
    boot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boot)
    calls = []
    monkeypatch.setattr(boot, "model_is_valid", lambda name="email_model": True)
    monkeypatch.setattr(boot, "_download", lambda: calls.append("download") or 0)
    assert boot.main([]) == 0
    assert calls == []  # nothing downloaded or trained


# ---------- honeypot corpus loading ----------


def _write_eml(folder, number, subject, body):
    (folder / f"sample-{number}.eml").write_text(
        f"From: a@example.com\nSubject: {subject}\n\n{body}\n", encoding="utf-8"
    )


def test_honeypot_loader_filters_language_and_caches_atomically(tmp_path):
    from phishguard.text_model import load_honeypot

    folder = tmp_path / "raw" / "phishing_pot" / "email"
    folder.mkdir(parents=True)
    _write_eml(folder, 1, "Verify your account", "Please verify your account and confirm the "
               "password for your mailbox, or it will be closed. We are the security team.")
    _write_eml(folder, 2, "Ihr Konto", "Bitte bestaetigen Sie Ihr Konto und Ihr Passwort sofort.")
    (folder / "sample-3.eml").write_bytes(b"")  # unparseable: skipped, not a crash
    cache_dir = tmp_path / "processed"
    df = load_honeypot(tmp_path / "raw", cache_dir)
    assert list(df["sample_no"]) == [1]  # German sample filtered out
    assert (df["label"] == 1).all() and (df["source"] == "phishing_pot").all()
    caches = list(cache_dir.glob("*.csv"))
    assert len(caches) == 1 and not list(cache_dir.glob("*.part"))


def test_empty_honeypot_cache_is_rebuilt(tmp_path):
    from phishguard.text_model import load_honeypot

    folder = tmp_path / "raw" / "phishing_pot" / "email"
    folder.mkdir(parents=True)
    _write_eml(folder, 7, "Account notice", "Please confirm your account details with us "
               "and update your password for the mailbox today, it is for your security.")
    cache_dir = tmp_path / "processed"
    load_honeypot(tmp_path / "raw", cache_dir)
    cache = next(cache_dir.glob("*.csv"))
    cache.write_text("sample_no,text,english\n")  # simulate a truncated cache
    assert len(load_honeypot(tmp_path / "raw", cache_dir)) == 1


def test_is_english():
    from phishguard.text_model import is_english

    assert is_english("please verify your account and the password for this mailbox now")
    assert not is_english("bitte bestaetigen sie ihr konto und ihr passwort sofort")
    assert not is_english("ok")
