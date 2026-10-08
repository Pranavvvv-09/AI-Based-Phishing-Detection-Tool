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
| **`phishing_pot/`** | **3,349 English** (of 12,269 parsed) | **modern phishing (2022–2026)** | Real honeypot `.eml` files, [rf-peixoto/phishing_pot](https://github.com/rf-peixoto/phishing_pot) | **CC BY-NC 4.0** (non-commercial) |
| `Enron.csv` | 14,444 (`label == 0` only) | legitimate (corporate, 2001) | Enron-Spam (Metsis et al.) | Public research corpus |
| `SpamAssasin.csv` | 4,073 (`label == 0` only) | legitimate (personal/lists, 2002) | Apache SpamAssassin public corpus | Apache-hosted public corpus |
| **`CEAS_08.csv`** | **16,968** (`label == 0` only) | legitimate (2008) | CEAS 2008 challenge corpus | Research use |
| **`Ling.csv`** | **2,396** (`label == 0` only) | legitimate (academic mailing list) | Ling-Spam (Androutsopoulos et al.) | Research use |
| `sms.tsv` | 194 ham (UCI-only; the rest overlaps Mendeley) of 5,574 | legitimate SMS | UCI SMS Spam Collection (2011) | CC BY 4.0 |
| **`sms_mendeley_5971.csv`** | **4,832 ham + 434 smishing** (of 5,971) | legitimate SMS / smishing | Mishra & Soni (2022), Mendeley Data | CC BY 4.0 (as listed on the Mendeley record) |
| `data/curated/modern_lures.csv` | 112 (committed) | modern phishing + legitimate | Hand-written for this project | Same as this repository |
| `data/curated/sms_transactional_eval.csv` | 72 (committed, frozen) | **evaluation only**: genuine transactional SMS + smishing | Hand-written for this project | Same as this repository |
| `data/curated/sms_independent_bank.csv` | 12 (committed, frozen) | **evaluation only**: genuine bank SMS | Example SMS from two MIT-licensed open-source parsers | MIT (see `THIRD_PARTY_NOTICES.md`) |
| `data/curated/sms_eval_v2.csv` | 120 (committed, frozen) | **evaluation only**: genuine SMS + smishing, each with its **sender** and realistic links | Hand-written for this project | Same as this repository |
| `data/curated/email_eval_v2.csv` | 60 (committed, frozen) | **evaluation only**: modern genuine notices + phishing, each with sender, DMARC result and Reply-To | Hand-written for this project | Same as this repository |
| `data/curated/sms_templates.csv` | 663 (committed, generated) | experiment data for SMS variants V1/V2 (**not** used by the shipped model) | `scripts/generate_sms_templates.py` | Same as this repository |

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
(`kaggle.com/datasets/naserabdullahalam/phishing-email-dataset`, uploaded by Naser Abdullah
Alam; its description asks users to cite Al-Subaiey et al., 2024). The original hosts
(Kaggle, UCI, monkey.org, CMU) are blocked in some environments, so the script downloads
public **GitHub mirrors**:

- Email CSVs: `github.com/rokibulroni/Phishing-Email-Dataset` (unofficial mirror, no licence file)
- SMS: `github.com/justmarkham/pycon-2016-tutorial` (`data/sms.tsv`) and
  `github.com/nmbenton/INFO-4360-Project` (`Dataset_5971.csv`, the Mendeley file)
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

## SMS data: decisions and shortcuts found
- **Labels:** Mendeley re-labelled UCI's "spam" into *smishing* (266) vs marketing *spam*
  (311) on the 4,933 shared messages. Mendeley labels win. Marketing spam is excluded
  (as for email), and UCI-only "spam" is excluded because it can't be told apart.
- **Parsing:** UCI must be read with `quoting=QUOTE_NONE`. pandas' default treats stray
  quote characters as quoting and merges messages (5,572 rows instead of 5,574).
- **Digits dropped (decided before training):** 97% of smishing but only 16% of the
  2011-era legitimate chats contain digits. Modern legitimate SMS (OTPs, bank alerts)
  are full of numbers, so the SMS model never sees digits.
- **Fingerprints removed:** UCI anonymisation placeholders (`&lt;#&gt;`, `&lt;TIME&gt;`,
  ...; in 5% of ham, 0% of spam), plus the words `uk` (2011 British spam) and `covid`
  (only 2020–22 scams mention it).
- **Rejected dataset:** an "Indian SMS spam" set (junioralive, MIT) labels *all* of its
  credit/OTP/delivery messages as spam and has only personal chat as ham. Adding it
  would have made the problem below worse.
- **Residual bias (honest limitation):** every legitimate training SMS is casual
  personal chat, so the SMS model learned "formal = scam". On its own it flags
  **37.5%** of the genuine transactional SMS in the frozen test set (bank, UPI, OTP,
  delivery and bill alerts). No public corpus of legitimate transactional SMS exists
  (it is personal data).

### The SMS false-positive fix: a pre-registered experiment
1. **Evaluation sets frozen first**, in a commit before any fix existed:
   `sms_transactional_eval.csv` (36 genuine transactional SMS and 36 smishing in the
   same formats; per category 1 validation and 2 test messages) and
   `sms_independent_bank.csv` (12 real-format bank SMS written by other developers).
   Phone numbers are masked and every domain uses the reserved `.test` TLD.
2. **Variants and the choice rule fixed before training** (`scripts/sms_experiment.py`):
   V0 = SMS model alone; V1 = retrained with 663 synthetic transactional SMS
   (`sms_templates.csv`: every format appears as both legitimate and smishing);
   V2 = V1 averaged with the email model; V3 = V0 averaged with the email model
   (in log-odds). Guard: FPR <= 1% and recall >= 90% on the public SMS test split.
   Rule: best validation F1, then fewer false positives at 0.8, then the simpler variant.
3. **A leak was found and fixed.** Run 1 chose V1, but an overlap audit showed that some
   synthetic messages paraphrased evaluation messages (up to 8 shared consecutive
   words), which flattered V1 (test FPR 8.3%). They were rewritten using overlap
   measures only, and tests now enforce word overlap below 0.4 and no shared run of 5+
   words. Run 2 (the committed script) chose **V3**, which the scorer now uses.

| Text score on held-out data | V0: SMS model alone | **V3: SMS + email blend (shipped)** | V1: + synthetic SMS |
|---|---|---|---|
| Frozen test: genuine SMS flagged (>= 0.5) | 37.5% (9/24) | **20.8% (5/24)** | 25.0% (6/24) |
| Frozen test: genuine SMS at quarantine level (>= 0.8) | 4.2% (1/24) | **4.2% (1/24)** | 4.2% (1/24) |
| Frozen test: smishing caught (>= 0.5 / >= 0.8) | 91.7% / 66.7% | **100% / 79.2%** | 95.8% / 87.5% |
| Independent bank SMS flagged (>= 0.5 / >= 0.8) | 2 / 2 of 12 | **2 / 0 of 12** | 3 / 0 of 12 |
| Modern hand-written test: FPR / recall (>= 0.5) | 21.4% / 82.1% | **21.4% / 85.7%** | 7.1% / 89.3% |
| Public SMS test split: FPR / recall (>= 0.5) | 0.3% / 96.6% | **0.4% / 90.8%** | 0.3% / 95.4% |

V2 had the best validation score but failed the guard (public-split recall 84.9%).
**Honest reading:** V3 beat V1 on validation by one message (F1 0.750 vs 0.741), and V1
did better on the modern hand-written test. The pre-registered choice was kept anyway:
switching to whichever variant looks best on test data would make the reported numbers
optimistic. The blend costs recall on the public 2011-2022 smishing at the 0.8 level
(85.1% to 54.0%), although 90.8% is still flagged for review. Genuine transactional SMS
are still flagged too often (about 1 in 5). The real fix is consented, anonymised
transactional SMS from your *own* phone, evaluated on a fresh frozen set.

## Fresh frozen sets for the Day 6 rule fixes (`*_eval_v2.csv`)
The test half of `sms_transactional_eval.csv` was looked at during the SMS experiment,
so it can't judge a new fix fairly. Before any of the SMS sender/link rules or the email
false-positive fix was written, two new sets were committed:

* **`sms_eval_v2.csv`**: 120 SMS (60 genuine, 60 smishing) in 16 categories, each with
  the `sender` as a phone would show it: Indian DLT headers (`VM-HDFCBK-S`), mobile
  numbers, email addresses (iMessage-style) and fictional foreign numbers. Links are
  realistic, so the link rules run: genuine messages use the companies' real domains
  (`amzn.in`, `zoma.to`, `hdfcbank.com`, ...); smishing uses **invented** domains that
  must never be visited (the project never fetches links). Deliberately hard cases are
  included on both sides: genuine messages from personal numbers (couriers, delivery
  partners), genuine SMS with toll-free and "SMS BLOCK" numbers, smishing from
  header-style senders, and smishing with **no link or number at all** (OTP theft,
  "Hi Mum", wrong-number).
* **`email_eval_v2.csv`**: 60 modern emails (30 genuine, 30 phishing) with sender,
  display name, the DMARC result your provider would record, and Reply-To. Most genuine
  mail comes from companies outside the built-in brand list (Swiggy, Groww, Myntra,
  your employer, your college), and most phishing passes DMARC from the attacker's
  **own** domain, as modern phishing does.

Phone numbers are placeholders (`{MOBILE}`, `{TOLLFREE}`) filled in at load time, so
no real person's number is published. Each category has a validation third (chooses
between variants) and a test two-thirds (only reported). The same author wrote the sets
and the rules, which is a bias we can only limit, not remove: the sets were frozen
first and include cases written to defeat the rules.

## Handling rules
- These files contain **real phishing**, with live malicious links and, in the honeypot,
  possibly live malware attachments.
- Never open samples in a mail client or browser, and never click their links. The
  project only parses them statically with its own hardened parser (12,269 real
  emails parsed with 0 crashes).
- Never print or log full email bodies, including during training or debugging.
- Use the data only for research and training this model. Don't redistribute it.
- The email and SMS datasets are trained and evaluated **separately**.
