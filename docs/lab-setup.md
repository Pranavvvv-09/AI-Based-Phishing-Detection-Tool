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

## 5. Revoking access
To cut PhishGuard off at any time, delete the app password in your Google Account. The
tool immediately loses mailbox access.
