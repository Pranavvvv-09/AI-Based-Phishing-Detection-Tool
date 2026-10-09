# Changelog

All notable changes to PhishGuard. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-09

First release: the result of the 10-day build.

### Added
- **Safe email parsing**: size, MIME-bomb, header-flood and charset defences, applied
  before any parsing.
- **Header checks**: SPF/DKIM/DMARC read only from your own provider's
  `Authentication-Results`, display-name and Reply-To spoofing, lookalike domains, BEC.
- **Link and attachment checks**: punycode, `@` tricks, obfuscated IP hosts, shorteners,
  link-text mismatch, risky file types. URLs are never fetched.
- **Text models**: TF-IDF + logistic regression for email (36k emails including 2022-26
  honeypot phishing) and SMS. SMS wording is judged by blending both models.
- **Explainable scorer**: log-odds fusion of text, header, link, sender and trust
  evidence. Every verdict lists its reasons with signed weights. On held-out future
  phishing, 94% is flagged and 0.5% of legitimate mail is (`models/scorer_metrics.json`).
- **SMS evidence**: brand claims from personal numbers or email addresses, links outside
  the named brand, two capped trust credits, 13 Indian consumer brands.
- **Mailbox poller**: TLS-only IMAP, reads without marking as read, moves (never deletes)
  phishing to a quarantine folder, monitor mode opens the inbox read-only.
- **Incidents**: JSON reports without body text, restore records and a hash-chained
  audit log (`python -m phishguard.poller verify-audit`).
- **Web console** (`python -m phishguard.web`): a React + Tailwind dark-mode dashboard with
  explainability chips and Restore to Inbox, plus a Quick Scan page for emails and SMS.
  Single login, CSRF, rate limits, strict CSP, listens on `127.0.0.1` only.
- **SMS screenshot scanning** in Quick Scan: upload a PNG, JPEG or WebP screenshot on the
  SMS tab and its text is read with OCR, scored like a pasted SMS, and shown above the
  verdict. Offline (RapidOCR, models bundled), optional (`pip install -e ".[ocr]"`), and
  hardened against hostile uploads: 5 MB cap, content-based type check, a pixel limit
  checked before decoding (decompression bombs), and the image is never stored.
- **Training on Windows**: honeypot samples that an antivirus quarantines mid-run are
  skipped instead of crashing training.
- **CI**: GitHub Actions on Python 3.11 and 3.13 with ruff, bandit, pytest (85% coverage
  floor), pip-audit, Playwright browser tests against the running app, and a check that
  the built dashboard matches `frontend/`. Least-privilege token, SHA-pinned actions,
  Dependabot.
- **Docs**: README quick start for Linux/macOS and Windows,
  [architecture overview](docs/architecture.md), [lab setup](docs/lab-setup.md),
  and the [model training guide](docs/PhishGuard_Model_Training_Guide.pdf).

[Unreleased]: https://github.com/Pranavvvv-09/AI-Based-Phishing-Detection-Tool/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Pranavvvv-09/AI-Based-Phishing-Detection-Tool/releases/tag/v0.1.0
