# Datasets

Raw and processed data are **never committed** (`data/raw/` and `data/processed/` are
gitignored). Fetch them with:

```bash
python scripts/download_data.py   # HTTPS-only, size-capped, SHA-256-pinned
```

## What is used

| File | Rows used | Our label | Original source | Licence / terms |
|------|-----------|-----------|-----------------|-----------------|
| `Nazario.csv` | all (1,565) | phishing | Jose Nazario phishing corpus | Free for research |
| `Nigerian_Fraud.csv` | all (3,332) | phishing (advance-fee/impersonation fraud) | Radev, "CLAIR collection of fraud email" (ACL Data and Code Repository) | Research use |
| `Enron.csv` | `label == 0` only (15,791 ham) | legitimate | Enron-Spam (Metsis et al.) / Enron corpus | Public research corpus |
| `SpamAssasin.csv` | `label == 0` only (4,091 ham) | legitimate | Apache SpamAssassin public corpus | Apache-hosted public corpus |
| `sms.tsv` | all (5,572) | SMS (Day 6) | UCI SMS Spam Collection (Almeida & Hidalgo) | CC BY 4.0 |

**Spam rows are deliberately excluded.** Spam (unwanted marketing) isn't phishing
(credential or payment fraud), and labelling it "phishing" would blur what the model
detects.

## Provenance
The email CSVs are the per-source files behind the Kaggle "Phishing Email Dataset"
(Al-Subaiey et al., 2024). The original hosts (Kaggle, UCI, monkey.org, CMU) are not
reachable from every environment, so the script downloads public **GitHub mirrors**:

- Email: `github.com/rokibulroni/Phishing-Email-Dataset` (unofficial mirror, no licence file)
- SMS: `github.com/justmarkham/pycon-2016-tutorial` (`data/sms.tsv`)

Each file's SHA-256 is pinned in `scripts/download_data.py`, so the exact bytes the
model was trained on are reproducible and any change to a mirror is detected. A pin
proves *consistency*, not *authenticity*: the mirrors are third-party copies. The
original sources' licences and terms apply, and this repository does not
redistribute the data.

## Known dataset biases (and what we did about them)
- Enron's publisher stripped email addresses and broke URLs apart, so Enron "ham"
  never contains links. A first model learned "has a link = phishing" (10.5% false
  positives on unseen legitimate mail). The text model now ignores URLs and
  addresses; links are judged by `url_checks.py` instead.
- Corpus-identifying words (`enron`, `jose`/`monkey` from the Nazario mailbox,
  encoding residue) are stop words, so the model can't identify the *dataset*
  instead of the *behaviour*.
- The phishing data is mostly 2004–2020 English-language mail. Modern AI-written
  and Indian-language lures are under-represented, which is why header and URL
  checks stay in the final score.

## Handling rules
- These files contain **real phishing**, with live malicious links and possibly personal data.
- Never open samples in a mail client or browser, and never click their links.
- Never print or log full email bodies, including during training or debugging.
- Use the data only for research and training this model. Don't redistribute it.
- The email and SMS datasets are trained and evaluated **separately**.
