# Security review checklist

This is the in-repo review surface for a first deploy. It does not replace an external review.

## Privilege boundaries

- [x] Docker socket is not mounted in the API/web containers.
- [x] Compose policy rejects privileged mode, sockets, host namespaces, includes, and floating `latest`.
- [x] Public PgBouncer omits `_owner`, `_migration`, `_backup`, and `_monitor` roles.
- [x] Tailscale Funnel stays disabled; mode change rewrites edge config and revokes sessions.
- [x] Internal worker routes use independent bearer tokens.
- [x] Setup signup is single-use and token-gated.

## Secrets and audit

- [x] Inventory APIs return metadata, not plaintext.
- [x] One-time reveal for runtime DB and mailbox credentials.
- [x] Audit events are redacted and not deletable through the API.
- [x] Root key stays out of PostgreSQL.

## Remaining host checks

Run after deploy: forged Host/forwarded-header bypass, public-only browser routes, verified-TLS database login, inbound SMTP without open relay, isolated restore, and an off-box `ARK_ALERT_WEBHOOK`.
