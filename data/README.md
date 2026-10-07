# Datasets

Raw and processed data are **never committed** (`data/raw/` and `data/processed/` are
gitignored). Fetch them with:

```bash
python scripts/bootstrap.py        # download (if needed) + train (if model missing/invalid)
python scripts/download_data.py    # just the data: HTTPS-only, size/hash/commit-pinned
```

The full download is about 1.7 GB, most of it honeypot attachments that are never opened.

## What is used

| Source | Rows used (after de-dup) | Our label | Origin | Licence / terms |
|--------|--------------------------|-----------|--------|-----------------|
| `Nazario.csv` | 1,526 | phishing (2004–2020) | Jose Nazario phishing corpus | Free for research |
| `Nigerian_Fraud.csv` | 3,200 | phishing (advance-fee/impersonation fraud) | CLAIR fraud email collection (Radev) | Research use |
| **`phishing_pot/`** | **3,342 English** (of 12,269 parsed) | **modern phishing (2022–2026)** | Real honeypot `.eml` files, [rf-peixoto/phishing_pot](https://github.com/rf-peixoto/phishing_pot) | **CC BY-NC 4.0** (non-commercial) |
| `Enron.csv` | 14,444 (`label == 0` only) | legitimate (corporate, 2001) | Enron-Spam (Metsis et al.) | Public research corpus |
| `SpamAssasin.csv` | 4,073 (`label == 0` only) | legitimate (personal/lists, 2002) | Apache SpamAssassin public corpus | Apache-hosted public corpus |
| **`CEAS_08.csv`** | **16,968** (`label == 0` only) | legitimate (2008) | CEAS 2008 challenge corpus | Research use |
| **`Ling.csv`** | **2,396** (`label == 0` only) | legitimate (academic mailing list) | Ling-Spam (Androutsopoulos et al.) | Research use |
| `sms.tsv` | 5,572 | SMS (Day 6) | UCI SMS Spam Collection | CC BY 4.0 |
| `data/curated/modern_lures.csv` | 112 (committed) | modern phishing + legitimate | Hand-written for this project | Same as this repository |

**Total training rows: 6,125 phishing and 30,304 legitimate,** plus the curated train half.

**Spam rows are deliberately excluded everywhere.** Spam (unwanted marketing) isn't
phishing (credential or payment fraud), and labelling it "phishing" would blur what
the model detects.

**`data/curated/modern_lures.csv`** has 112 hand-written messages (56 phishing,
56 legitimate, 27 categories). Phishing categories cover AI-polished credential
lures, gift-card and payroll BEC, and Indian KYC, UPI, digital-arrest, courier,
task-job, bill and refund scams, plus Hinglish. Legitimate categories cover
alarming-but-genuine OTPs, bank alerts, security notices and deliveries, and
everyday work, college and Hinglish mail. It contains no real people, links or
addresses. Each category is split into a `train` half (fixed weight 20) and a
`test` half used **only** for the `modern_test` metric.

## How each dataset is evaluated
- **In-distribution:** a stratified 20% of the CSV sources, never trained on.
- **Leave-one-corpus-out:** for each legitimate corpus, a model trained *without*
  it measures false positives on it (mail in an unfamiliar style).
- **Honeypot future test:** the honeypot is split by **time** (sample number). The
  oldest 70% trains and the newest 30% (2026) tests, which mimics catching
  next month's campaigns.
- **Modern test:** the held-out half of the curated file.

## Ablation: what each dataset contributes
All variants were scored on the same test sets. Reproduce with `python scripts/ablation.py`.

| Training data | Future real phishing caught | Modern test recall / FPR | FPR, old-source test |
|---|---|---|---|
| A: Nazario + Nigerian + Enron + SpamAssassin | **40.6%** | 78.6% / 7.1% | 0.21% |
| B: A + CEAS_08 + Ling legitimate | 30.0% | 78.6% / 7.1% | 0.16% |
| **C: B + honeypot modern phishing (final)** | **87.9%** | **85.7%** / 10.7% | 0.30% |

A model trained only on the classic corpora scored 99% on its own test split, yet
**missed ~60% of real 2025–26 phishing.** Adding modern data roughly doubles
real-world recall for a small false-positive cost.

## Provenance
The email CSVs are the per-source files behind the Kaggle "Phishing Email Dataset"
(Al-Subaiey et al., 2024). The original hosts (Kaggle, UCI, monkey.org, CMU) are
blocked in some environments, so the script downloads public **GitHub mirrors**:

- Email CSVs: `github.com/rokibulroni/Phishing-Email-Dataset` (unofficial mirror, no licence file)
- SMS: `github.com/justmarkham/pycon-2016-tutorial` (`data/sms.tsv`)
- Honeypot: `github.com/rf-peixoto/phishing_pot` (sparse checkout of `email/` only)

CSV files are pinned by SHA-256. The honeypot is pinned to a full git commit
(`89e2bc05…`), and git verifies every object against it; git transport is
restricted to HTTPS. A pin proves *consistency*, not *authenticity*: the CSV
mirrors are third-party copies. The original sources' licences and terms apply
(note **CC BY-NC** for the honeypot: non-commercial use only), and this repository
does not redistribute any of the data.

## Known dataset biases (and what we did about them)
Each of these was found by inspecting the model's strongest words or by
out-of-distribution tests, not by the headline score.

| Shortcut found | Evidence | Fix |
|---|---|---|
| Enron had URLs and addresses stripped, so "has a link = phishing" | 10.5% false positives on unseen legitimate mail | URLs and addresses removed from model text (links judged by `url_checks.py`) |
| Dataset fingerprints: `enron`, `vince`, `jose`/`monkey` (Nazario mailbox), `utf` | Top-weighted words | Stop words |
| Honeypot anonymisation placeholder `phishing@pot` (no dot, so missed by the address filter) | `phishing`, `pot` among the top phishing words, and genuine security notices flagged | Placeholder stripped on load; both words are stop words |
| **Language:** honeypot is 43% English, 14% German, 12% Portuguese; all legitimate mail is English | Would have taught "non-English = phishing" | Only English honeypot mail used (function-word check); `de`/`para`/`enviado`/`assunto` residue stop-worded |
| **Era:** all modern mail is phishing and all legitimate mail is 2000–2008 | `unsubscribe`, `app`, `ai` became phishing signals | Stop words. Residual bias remains: modern "your account" notices still score high (see below) |

**Residual bias (honest limitation):** no public corpus of *modern legitimate*
email exists, because real inboxes are private. Genuine modern account notices
("your account", "your plan") therefore still lean towards phishing. That's
3 of 28 legitimate messages in the modern test, one of them above the 0.8
quarantine threshold. The Day 6 scorer counters this with header evidence:
genuine notices come from authenticated, official domains.

## Handling rules
- These files contain **real phishing**, with live malicious links and, in the honeypot,
  possibly live malware attachments.
- Never open samples in a mail client or browser, and never click their links. The
  project only parses them statically with its own hardened parser (12,269 real
  emails parsed with 0 crashes).
- Never print or log full email bodies, including during training or debugging.
- Use the data only for research and training this model. Don't redistribute it.
- The email and SMS datasets are trained and evaluated **separately**.
