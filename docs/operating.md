# Operating

## Fresh install

1. Install Docker and pin tools with `mise install`.
2. Run `mise run host:install` to generate secrets, build the application images, migrate, and start the platform, pinned Stalwart engine, and Prometheus topology. Existing `.env` values are kept.
3. Open the printed setup URL over an SSH tunnel if the host is remote. The raw API bootstrap listener is bound only to `127.0.0.1:3000`; public administration is served only through the configured edge after domain and certificate reconciliation.
4. Create the owner, enroll MFA, then run the domain wizard.
5. Copy the generated DNS records, or publish the reviewed Cloudflare diff after MFA.
6. Recheck until endpoints leave `awaiting_dns`. Incoming mail can become ready while SES stays paused.

For local development, `mise run db:up` adds `infra/platform/docker-compose.dev.yml`, which binds the two PostgreSQL engines only on loopback ports 5433 and 5434. The production manifest has no host binding for either engine; public database access is exclusively through the TLS pooler profile and its separately enforced source policy.

## Providers

Set `DNS_API_TOKEN`, `AWS_*`, and `STALWART_*` only on the workers that need them. The public mail container must not receive AWS, DNS, or root keys. `ARK_ALERT_WEBHOOK` must be independent of this mail server.

Set `ARK_OFFHOST_HEARTBEAT_URL` to an independently hosted HTTPS dead-man receiver and give it the generated `ARK_OFFHOST_HEARTBEAT_TOKEN`. Test receiver expiry by stopping the disposable host; an on-host Prometheus instance cannot prove total host loss.

## Recovery

`mise run recover -- status` prints bootstrap state without changing data. Setup cannot be reopened while users exist. Keep local recovery codes and the generated `ARK_MFA_RECOVERY_TOKEN` off-host. If an owner loses every factor, run `mise run recover:mfa -- owner@example.com RESET:owner@example.com "$ARK_MFA_RECOVERY_TOKEN"` on the host. It revokes every session and step-up grant before permitting re-enrollment.

`mise run recover-host` prints the host-loss checklist. Restore into `infra/restore/docker-compose.yml` first. Do not reuse a failed Tailscale node identity.

## Mode changes

Switching public and tailnet administration is a durable operation that rewrites the edge config and revokes sessions. A failed private path must not silently republish the dashboard.

## Backups

Upload, integrity, and restore-test are three statuses. A successful upload is not a verified restore. Set `ARK_BACKUP_EXECUTE=1` only when pgBackRest or Restic should run. Mail jobs additionally require `ARK_MAIL_SNAPSHOT_READY=1` from a completed native snapshot/quiesce step. Plan-only execution fails the operation instead of reporting success.

## Maintenance

`mise run maintain -- infra/platform/release.json infra/platform/docker-compose.yml` requires an Ed25519 publisher key in `ARK_RELEASE_PUBLIC_KEY`, verifies the bundle signature, exact Compose-file digest, and exact immutable image set, and journals the approval. It pulls every approved digest and executes health-waiting Compose only when `ARK_MAINTENANCE_EXECUTE=1`. Stateful images require `allowStateful` after a reviewed migration and recovery plan.

## Import

`mise run import -- inventory.json` compares domains, databases, and services. Owners are never imported. Stop the old reconcilers before transferring a live mail domain.

## Local acceptance

`mise run test:e2e` refuses non-loopback PostgreSQL, creates a uniquely named disposable database, migrates it from empty, drives Chromium through owner creation, pre-MFA denial, invalid and valid TOTP, recovery-code acknowledgement, custom domain setup and one-time recovery-code use, then removes the database. The provider/Linux release checks in `security-review.md` remain separate opt-in acceptance work.
