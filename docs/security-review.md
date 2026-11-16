# Security review checklist

This checklist records code-backed boundaries, not deployment acceptance. A box means a repository test exercises the rule; it does not certify the Linux daemon, public network, DNS/provider account, certificate authority, or restore repository.

## Privilege boundaries

- [x] Docker socket is not mounted in the API/web containers.
- [x] TypeScript and Go Compose policies default-deny fields and reject external/named platform resources, local-driver bind options, privileged mode, sockets, host namespaces, includes, interpolation, aliases and floating tags.
- [x] Public PgBouncer omits `_owner`, `_migration`, `_backup`, and `_monitor` roles.
- [x] `pgbouncer-public` runs digest-pinned PgBouncer 1.26.1 (at least 1.25.2, which fixes CVE-2026-6664) directly on the generated `pgbouncer.ini`, with no env-driven config generation, all capabilities dropped and read-only mounts.
- [x] The installer seeds PgBouncer with no mappings or admitted users, requiring TLS and SCRAM; the disposable CI smoke test rejects bootstrap console access and verifies authenticated TLS through the host loopback port.
- [x] Tailscale Funnel stays disabled; mode change rewrites edge config and revokes sessions.
- [x] Internal worker routes authenticate bearer identities and reject job kinds outside each typed allowlist.
- [x] Public and tailnet Caddy routes preserve deny-before-fallback ordering for internal and unknown API paths.
- [x] Setup signup is single-use and token-gated.

## Secrets and audit

- [x] Inventory APIs return metadata, not plaintext.
- [x] One-time reveal uses a conditional atomic consume and is scoped to the underlying database or mailbox.
- [x] Audit events are redacted and not deletable through the API.
- [x] Root key stays out of PostgreSQL.

## Deployment acceptance still required

- [ ] Inspect a permitted workload on an isolated Linux Docker daemon and verify the agent ledger survives restart.
- [ ] Test forged forwarding headers and the final public/tailnet origins through the deployed Caddy/Tailscale paths.
- [ ] Perform an external PgBouncer login over verified TLS and prove real IPv4/IPv6 CIDR denial.
- [ ] Deliver and read mail on disposable Stalwart, then prove alias, suspension, device revocation and relay denial.
- [ ] Complete HTTP-01 issuance/renewal against a disposable public domain.
- [ ] Restore exact database and mail snapshots in fresh isolated volumes and attach assertion results and recovery time.
- [ ] Exercise signed update failure/recovery and an independent off-host heartbeat alert.

Production-facing status must remain waiting, untrusted, paused or unverified until the corresponding observation above exists.
