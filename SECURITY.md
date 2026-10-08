# Security Policy

PhishGuard is a **defensive, detection-only** tool.

## Design guarantees
- Analysis is static: the analyser never fetches, resolves or opens URLs or attachments.
- Quarantine moves messages and never deletes them. Every action is reversible and audited.
- The web app's only mailbox action is Restore (move back to the inbox), which needs a
  logged-in session plus a CSRF token.
- It operates only on mailboxes the operator owns and has configured.
- Secrets are loaded from environment variables and never logged.

## Reporting a vulnerability
Please use GitHub's private reporting (**Security → Report a vulnerability**) rather
than a public issue. Include steps to reproduce and the affected version.
