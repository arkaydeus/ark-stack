# Operating

## Fresh install

1. Install Docker and pin tools with `mise install`.
2. Run `mise run host:install` to generate secrets, build the application images, migrate, and start the platform, pinned Stalwart engine, and Prometheus topology. Existing `.env` values are kept.
3. Open the printed setup URL over an SSH tunnel if the host is remote. The raw API bootstrap listener is bound only to `127.0.0.1:3000`; public administration is served only through the configured edge after domain and certificate reconciliation.
4. Create the owner, enroll MFA, then run the domain wizard.
5. Copy the generated DNS records, or publish the reviewed Cloudflare diff after MFA.
6. Recheck until endpoints leave `awaiting_dns`. Incoming mail can become ready while SES stays paused.

For local development, `mise run db:up` adds `infra/platform/docker-compose.dev.yml`, which binds the two PostgreSQL engines only on loopback ports 5433 and 5434. The production manifest has no host binding for either engine; public database access is exclusively through the TLS pooler profile and its separately enforced source policy.

## Public certificates

The domain worker defaults to `ARK_ACME_STAGING=1`. Staging certificates are recorded as `untrusted` and are never served by the public edge. To enable public HTTPS, set `ARK_ACME_EMAIL` and `ARK_ACME_STAGING=0` in the installation `.env`, recreate the domain worker (`docker compose --env-file .env -f infra/platform/docker-compose.yml up -d domain-worker`), and issue or renew the endpoint certificates. Existing staging certificates need reissuance; changing the flag alone does not make them trusted.

The `edge-apply` operation evidence lists `awaitingCertificate` hostnames and `unrouted` web addresses. A switch to public administration requires an issued certificate for the admin hostname; rejection preserves routing, settings and sessions. Keep the local tunnel available while provisioning the first public certificate.

## Providers

Set `DNS_API_TOKEN`, `AWS_*`, and `STALWART_*` only on the workers that need them. The public mail container must not receive AWS, DNS, or root keys. `ARK_ALERT_WEBHOOK` must be independent of this mail server.

Set `ARK_OFFHOST_HEARTBEAT_URL` to an independently hosted HTTPS dead-man receiver and give it the generated `ARK_OFFHOST_HEARTBEAT_TOKEN`. Test receiver expiry by stopping the disposable host; an on-host Prometheus instance cannot prove total host loss.

## Public database port limits

nftables (`inet ark_db_ingress`, docs/design/front-door.md §3.11) limits every source on the public PostgreSQL port, because Vercel and similar platforms cannot be IP-allowlisted. By default each source gets 128 concurrent connections and 30 new connections per second, with a burst of 60. IPv4 sources are counted per address and IPv6 sources per /64. The rules run on both the `input` hook (today's host listener) and the `forward` hook (Docker DNAT), and they are applied after any per-database CIDR allowlist. An owner can change the limits on the settings page or with `PUT /api/settings/db-ingress`, which needs MFA and a `platform.update` step-up. The change reapplies the table through a `pgbouncer.reload` operation.

`database-ingress` exports the drop counters every 15 s to `tmp/db-ingress/counters.json`, and `/api/metrics/prometheus` serves them as `ark_nft_drop_packets_total{table,chain,reason,family}`. `ArkDatabaseIngressDrops` fires after 10 minutes of continuous drops. Check whether a legitimate client (for example a Vercel deployment's shared egress address) needs higher limits, or whether the port is under abuse. Counters restart from zero whenever the table is reapplied. `mise run test:db-ingress` (also part of `mise run test:edge`) checks the rendered rules with `nft -c` and exercises them with real connections in a privileged container (Docker Desktop or a Linux host).

## Recovery

`mise run recover -- status` prints bootstrap state without changing data. Setup cannot be reopened while users exist. Keep local recovery codes and the generated `ARK_MFA_RECOVERY_TOKEN` off-host. If an owner loses every factor, run `mise run recover:mfa -- owner@example.com RESET:owner@example.com "$ARK_MFA_RECOVERY_TOKEN"` on the host. It revokes every session and step-up grant before permitting re-enrollment.

`mise run recover-host` prints the host-loss checklist. Restore into `infra/restore/docker-compose.yml` first. Do not reuse a failed Tailscale node identity.

## Mode changes

Switching public and tailnet administration is a durable operation that rewrites the edge config and revokes sessions. A failed private path must not silently republish the dashboard.

## Backups

Upload, integrity, and restore-test are three statuses. A successful upload is not a verified restore. Set `ARK_BACKUP_EXECUTE=1` only when pgBackRest or Restic should run. Mail jobs additionally require `ARK_MAIL_SNAPSHOT_READY=1` from a completed native snapshot/quiesce step. Plan-only execution fails the operation instead of reporting success.

## Maintenance

`mise run maintain -- infra/platform/release.json infra/platform/docker-compose.yml` requires an Ed25519 publisher key in `ARK_RELEASE_PUBLIC_KEY`, verifies the bundle signature, exact Compose-file digest, and exact immutable image set, and journals the approval. It pulls every approved digest and executes health-waiting Compose only when `ARK_MAINTENANCE_EXECUTE=1`. Stateful images require `allowStateful` after a reviewed migration and recovery plan.

## Third-party image pins

Third-party images (Caddy, Tailscale, PgBouncer, PostgreSQL, Stalwart and the `oven/bun` base) are pinned as `name:version@sha256:<digest>`: the version is for readers, the digest is what Docker pulls. Dependabot (`.github/dependabot.yml`) covers only the bun workspace and GitHub Actions, so it never proposes image bumps. Bump images by hand:

1. Read the upstream release notes between the pinned and the target version, and note behaviour changes that touch Ark's config.
2. Resolve the multi-arch index digest from the registry, not from a local pull (a local `RepoDigests` entry can be a single-platform manifest):

   ```sh
   docker buildx imagetools inspect caddy:2.11.9
   ```

   Take the top-level `Digest:` of the `application/vnd.oci.image.index.v1+json` index and confirm it lists `linux/amd64` and `linux/arm64`. If a design doc or release note quotes a digest prefix, check that the resolved digest starts with it. Then confirm the pinned reference runs the expected version, for example `docker run --rm caddy:2.11.9@sha256:<digest> caddy version`.

3. Replace every reference in one change. The `oven/bun` and Prometheus pins also appear in `scripts/test-db-ingress.ts`. For Caddy that is `edge` and `tailnet-gateway` in `infra/platform/docker-compose.yml`, `caddyImage` in `scripts/test-edge-config.ts`, and the sample `infra/platform/release.json` (recompute its `digest` with `bundleDigest` from `@ark-stack/shared`). `rg '<old version>'` should then match only historical docs.
4. Run the image's integration task. For Caddy, `mise run test:edge` fails unless both Compose services use exactly the tested pin. It then validates every rendered and static Caddyfile against fixture certificates and runs the edge behaviour tests in disposable containers: header stripping, `Server`/`Via` removal (including a control proving `header_down -Via` alone is insufficient), WebSockets across `/load` and 80 s of idle, and a production-like edge (explicit uid/gid 1000:1000, 0600 private keys, bootstrap Caddyfile, `edge-admin` alias) configured through the real `writeEdge`. That edge must serve each fixture certificate over TLS, skip hostnames whose certificate is not `issued`, answer ACME challenges and 308 redirects on `:80` (404 for other hosts), and serve a renewed certificate after an identical `writeEdge` reload with `Cache-Control: must-revalidate`, which a control `/load` without the header does not. The run takes about 100 s.
5. In the PR, record the full digest, how it was resolved and verified, and the integration-task output. Roll the release out through `mise run maintain` (above).

## Import

`mise run import -- inventory.json` compares domains, databases, and services. Owners are never imported. Stop the old reconcilers before transferring a live mail domain.

## Local acceptance

`mise run test:e2e` refuses non-loopback PostgreSQL, creates a uniquely named disposable database, migrates it from empty, drives Chromium through owner creation, pre-MFA denial, invalid and valid TOTP, recovery-code acknowledgement, custom domain setup and one-time recovery-code use, then removes the database. The provider/Linux release checks in `security-review.md` remain separate opt-in acceptance work.
