# Operating

## Fresh install

1. Install Docker and pin tools with `mise install`.
2. Run `mise run host:install` to generate secrets, start Postgres, and migrate. Existing `.env` values are kept.
3. Open the printed setup URL over an SSH tunnel if the host is remote.
4. Create the owner, enroll MFA, then run the domain wizard.
5. Copy the generated DNS records, or publish the reviewed Cloudflare diff after MFA.
6. Recheck until endpoints leave `awaiting_dns`. Incoming mail can become ready while SES stays paused.

## Providers

Set `DNS_API_TOKEN`, `AWS_*`, and `STALWART_*` only on the workers that need them. The public mail container must not receive AWS, DNS, or root keys. `ARK_ALERT_WEBHOOK` must be independent of this mail server.

## Recovery

`mise run recover -- status` prints bootstrap state without changing data. Setup cannot be reopened while users exist. Password-reset email is not the only recovery path; keep local recovery codes and the host setup token.

`mise run recover-host` prints the host-loss checklist. Restore into `infra/restore/docker-compose.yml` first. Do not reuse a failed Tailscale node identity.

## Mode changes

Switching public and tailnet administration is a durable operation that rewrites the edge config and revokes sessions. A failed private path must not silently republish the dashboard.

## Backups

Upload, integrity, and restore-test are three statuses. A successful upload is not a verified restore. Set `ARK_BACKUP_EXECUTE=1` only when pgBackRest or Restic should run.

## Maintenance

`mise run maintain -- infra/platform/release.json` validates a digest-matching bundle. It executes Compose only when `ARK_MAINTENANCE_EXECUTE=1`. Stateful images require `allowStateful` after a reviewed plan.

## Import

`mise run import -- inventory.json` compares domains, databases, and services. Owners are never imported. Stop the old reconcilers before transferring a live mail domain.
