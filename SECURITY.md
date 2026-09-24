# Security Policy

Report vulnerabilities privately via **Security → Advisories → Report a vulnerability**. Do not open public issues.
We acknowledge reports within 3 business days.

## Truth API controls

- Truth writes require `X-ShelfCat-Gate-Key`, compared in constant time with `SHELFCAT_GATE_API_KEY`.
  If that setting is missing, writes are **disabled** (HTTP 503), never left open.
- Only `source = "rust_gate"` and `validated = true` events are accepted (HTTP 403 otherwise).
- Ledger records are SHA-256 hash-chained and, when `SHELFCAT_AUDIT_SIGNING_KEY` is set, Ed25519-signed.
- Keep all secrets in Azure Key Vault and use Key Vault references in app settings. Never put them in `local.settings.json` or source.
- Dependencies are audited in CI (`pip-audit`).
