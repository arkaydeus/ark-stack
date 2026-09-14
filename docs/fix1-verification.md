# Fix 1 verification record

Recorded 14 September 2026. This separates repository evidence from the final deployment acceptance gate in `fix1-plan.md`.

## Passing local evidence

- `mise run typecheck`: all four TypeScript workspaces.
- `bunx oxlint .`: no warnings.
- `mise run test`: 66 tests, 269 assertions, zero failures.
- `mise run test:agent`: Go AST policy, hash binding, Docker boundary, and durable-ledger tests pass.
- `mise run test:e2e`: Chromium completes empty-database owner creation, pre-MFA mutation denial, invalid/valid TOTP, recovery-code acknowledgement, custom IPv4/IPv6/hostnames, final dashboard, one-time recovery login, and reuse denial. The unique PostgreSQL database is removed afterward.
- Migrations `0000` through `0010` apply from an empty database. `mise run test:upgrade` constructs a representative `0000`–`0003` installation, applies `0004`–`0010`, verifies the current schema, and removes its exact disposable database.
- `mise run test:stalwart` launches the pinned Stalwart image on a random loopback port, verifies native domain/mailbox/alias creation, suspension/restoration, app-password revocation and mailbox purge, then destroys the exact test container and temporary state.
- `mise run test:agent-integration` pulls a pinned BusyBox digest, deploys the canonical manifest to a uniquely named Compose project, inspects effective capabilities/mounts/networks/resource limits, persists and reloads exact container/network ownership, performs a ledger-scoped restart, and removes the exact project and volumes.
- Platform, mail, and monitoring Compose files render successfully. Both Dockerfiles pass `docker build --check`.
- Caddy 2.10.2 adapts and validates both generated public and tailnet routes; adapted JSON has internal denial, browser allowlist, unknown-API denial, then UI fallback in that order.
- A disposable official Stalwart 0.16.22 container using the pinned OCI digest accepted native domain, account, and mailing-list creation; returned native IDs; denied primary login after suspension; restored login; created and revoked an app password with 200 then 401 observations; and confirmed native alias and account destruction. The `--rm` container and its ephemeral data were stopped and removed.
- A disposable PostgreSQL role drill created a sequence-backed table, inserted/read through generated runtime/read-only roles, denied runtime DDL, and removed the exact temporary database and roles. The database provisioner now performs these checks before recording ready.

## Deployment acceptance still required

The following cannot be fabricated locally and remain required before a production release record may call Fix 1 complete:

- Fresh disposable Linux host and representative upgrade-host runs of the complete topology.
- Authoritative public DNS, HTTP-01 staging/production issuance and external HTTPS/PostgreSQL/SMTP/IMAP certificate probes.
- Host-namespace nftables enforcement tested from allowed and denied external IPv4/IPv6 clients.
- Incoming SMTP delivery and IMAPS read, unauthorized relay denial, and controlled SES DKIM/MAIL FROM/relay tests.
- Exact pgBackRest/Restic restores booted in fresh isolated volumes with application, grant, and mail-content assertions plus measured recovery time.
- Failed stateless update recovery and blocked unsafe stateful rollback on the deployed host.
- Independently operated off-host dead-man receiver expiry after the disposable host is stopped.

Until those observations are attached, corresponding endpoints remain waiting, untrusted, paused, failed, or unverified; plan-only adapter output is not accepted as success.
