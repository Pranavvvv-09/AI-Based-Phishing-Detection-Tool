# PhishGuard architecture

PhishGuard is one Python package (`src/phishguard/`) plus a small React dashboard
(`frontend/`, built into `src/phishguard/static/app/`). Everything runs offline: no link
is fetched, no DNS lookup is made, and the only network connection is IMAP over TLS to
your own mailbox.

## Data flow

```
 .eml upload / pasted text / IMAP fetch          SMS text + sender
              |                                         |
          parser.py  (size, MIME-bomb, header-flood limits)
              |                                         |
   +----------+-----------+------------+                |
   |                      |            |                |
header_checks.py     url_checks.py   text_model.py   sms_checks.py
SPF/DKIM/DMARC,      punycode, IPs,  TF-IDF + LogReg  sender, link vs brand,
spoofing, BEC        @-trick, files  (email / SMS)    capped credits
   |                      |            |                |
   +----------+-----------+------------+----------------+
              |
          scorer.py   log-odds fusion -> score, label, action, reasons
              |
   +----------+------------------+
   |                             |
poller.py + mailbox.py       web.py
IMAP poll, MOVE to            dashboard, Quick Scan,
quarantine folder             Restore (POST /api/restore/{id})
   |                             |
   +----------> incidents.py <---+
                reports/*.json, quarantine/*.json,
                hash-chained reports/audit.log
```

## Modules

| Module | Role |
|---|---|
| `config.py` | Loads `.env`, validates every value, keeps secrets out of `repr`. Bad config fails closed. |
| `parser.py` | Turns raw `.eml` bytes into a size-bounded `ParsedEmail`. Every limit is checked before parsing. |
| `domains.py` | Offline domain helpers (bundled Public Suffix List, brand domains, lookalike detection). |
| `header_checks.py` | Reads the `Authentication-Results` header written by *your* provider (`TRUSTED_AUTHSERV_ID`), plus spoofing, Reply-To and BEC checks. |
| `url_checks.py` | Lexical link and attachment checks. URLs are never fetched (no drive-by, no SSRF, no "address is live" signal). |
| `text_model.py` | TF-IDF + logistic regression model of scam intent. Same normalisation for training and prediction. |
| `sms_checks.py` | SMS sender evidence, link-vs-brand check and two capped trust credits. |
| `scorer.py` | Fuses all evidence in log-odds and returns a `Verdict` with signed `reasons`. CLI: `python -m phishguard.scorer`. |
| `mailbox.py` | Defensive IMAP client: TLS only, `BODY.PEEK[]` (never marks as read), move never delete. |
| `poller.py` | Polls the inbox, scores new mail, quarantines or reports, restores. CLI: `python -m phishguard.poller`. |
| `incidents.py` | Atomic, owner-only JSON reports and quarantine records, plus the tamper-evident audit log. |
| `ocr.py` | Optional (`.[ocr]` extra): validates an uploaded screenshot (type, size, pixel count before decoding) and reads its text offline with RapidOCR. |
| `web.py` | FastAPI app: login, dashboard, Quick Scan and the JSON API. Also starts the poller thread when IMAP is configured. |

## Scoring

```
logit = clip(logit(text_probability), -4, +4)   # wording
      + 4 x header_risk                          # SPF/DKIM/DMARC, spoofing
      + 4 x link_risk                            # lookalike links, risky files
      - trust_credit                             # verified official sender
score = 1 / (1 + e^-logit)
```

| Score | Label | Action |
|---|---|---|
| >= `QUARANTINE_THRESHOLD` (default 0.8) | phishing | quarantine |
| >= 0.5 | suspicious | review |
| < 0.5 | legitimate | deliver |

For SMS, the text probability is the average of the SMS and email models in log-odds.
Messages that cannot be fully parsed, or that hit an internal error, always get
`review`, never `deliver`. Every constant was fixed before evaluation. The experiments
that chose them are in `scripts/` and their results in `models/*.json`. Details are in
the [model training guide](PhishGuard_Model_Training_Guide.pdf) and
[data/README.md](../data/README.md).

## Web console

| Route | Purpose |
|---|---|
| `GET/POST /login`, `POST /logout` | Single admin login from `.env` (5 attempts per minute). |
| `GET /` | React dashboard: totals, quarantine table, explainability chips, Restore. |
| `GET/POST /scan` | Quick Scan (server-rendered, htmx): paste an email or SMS, upload an `.eml`, or upload an SMS screenshot (OCR). |
| `GET /api/session` | CSRF token and poller status for the dashboard. |
| `GET /api/quarantine` | Quarantine records with their verdicts. |
| `POST /api/restore/{id}` | Moves one message back to the inbox (CSRF token, 10 per minute, audited). |
| `GET /api/health` | Liveness check. |

Security: a signed session cookie (HttpOnly, SameSite=Strict), CSRF on every POST, a strict
Content-Security-Policy with no inline code, and the server listens on `127.0.0.1` by
default. The app refuses to start with a weak secret key or a plain-text password.

## On disk

| Path | Contents | In git? |
|---|---|---|
| `models/*.joblib` | Trained models (made by `scripts/bootstrap.py`) | no |
| `models/*.json` | Manifest, metrics and experiment results | yes |
| `reports/` | Incident reports, `audit.log`, poller state | no |
| `quarantine/` | Restore records for quarantined messages | no |
| `src/phishguard/static/app/` | Built dashboard (CI checks it matches `frontend/`) | yes |
