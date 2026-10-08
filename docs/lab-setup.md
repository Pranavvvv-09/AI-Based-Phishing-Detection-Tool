# Safe Lab Setup

PhishGuard does **static analysis** only. It reads emails as text and never opens
links, downloads attachments or executes anything. Even so, the datasets contain real
phishing, so work in a contained lab.

## 1. Workstation
- Use a dedicated Python virtual environment (`python -m venv .venv`).
- Optional but recommended: work inside a VM (VirtualBox or VMware) or WSL so samples stay off your daily-use OS.
- Keep antivirus on. If it quarantines a sample `.eml`, that's expected. Don't add exclusions.

## 2. Test mailbox (your own)
1. Create a **new** Gmail account used only for this project. Never use your personal mailbox.
2. Enable 2-Step Verification (required for app passwords).
3. Create an app password: Google Account → Security → App passwords.
4. Put it in `.env` as `IMAP_APP_PASSWORD`. Never commit it or paste it anywhere else.
5. In Gmail, create a label named `PhishGuard-Quarantine`.
6. Gmail settings → Forwarding and POP/IMAP → make sure IMAP is enabled.

## 3. Test emails
- Send test "phishing" emails only from a second account **you own** to the test mailbox.
- Use harmless links such as `https://example.com/login`. Never use real phishing URLs.
- Never forward real phishing to other people.

## 4. Configuration
```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"   # use for API_KEY and FLASK_SECRET_KEY
```
Start with `MODE=monitor` (report only). Switch to `MODE=quarantine` only after you've
checked that the scores look right.

## 5. Running the mailbox poller (Day 7)
1. Fill in `IMAP_USER` and `IMAP_APP_PASSWORD` in `.env`, keep `MODE=monitor`.
2. `python -m phishguard.poller run --once --backfill 20` scans your 20 newest messages
   and writes a report for every flagged one to `reports/`. Nothing in the mailbox
   changes: the inbox is opened read-only.
3. Send yourself a harmless test "phishing" email from your second account and run
   `python -m phishguard.poller run --once` again. Check `reports/` and
   `reports/audit.log`.
4. When the verdicts look right, set `MODE=quarantine` and run
   `python -m phishguard.poller run`. Phishing now moves to the
   `PhishGuard-Quarantine` label (created if missing). In Gmail it disappears from the
   inbox but stays in *All Mail*.
5. A false positive? `python -m phishguard.poller list`, then
   `python -m phishguard.poller restore <incident-id>`. The message goes back to the
   inbox and is remembered (by content hash), so the next poll leaves it alone.
6. `python -m phishguard.poller verify-audit` checks that no audit line was edited,
   removed or reordered.

What the poller guarantees:
- TLS on port 993 with certificate checks; the app password is never logged.
- Messages are read with `BODY.PEEK`, so they stay unread.
- Only `MOVE` is used. It never sends `CLOSE` or a plain `EXPUNGE`, which would
  permanently remove messages *you* marked as deleted. Servers without MOVE or
  UIDPLUS are refused in quarantine mode.
- Only mail arriving after the first run is scanned (plus `--backfill N`); restarts
  continue where they stopped.
- A wrong password stops it at once (retrying could lock the account); network errors
  are retried with exponential backoff, up to 30 minutes.
- `reports/` and `quarantine/` contain senders and subjects of your mail: they are
  gitignored and written owner-readable only. Delete them when you're done.

## 6. Revoking access
To cut PhishGuard off at any time, delete the app password in your Google Account. The
tool immediately loses mailbox access.
