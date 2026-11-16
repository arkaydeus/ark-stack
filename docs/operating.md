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

## Edge Tailscale node

The public edge has its own Tailscale node, `edge-ts` (`tag:ark-edge`, hostname `ark-edge`), in kernel mode (docs/design/front-door.md §3.6). It owns the network namespace that the `edge` Caddy container joins (`network_mode: service:edge-ts`), so `edge-ts` publishes TCP 80 and 443 and UDP 41642, and carries the `edge-admin` alias on the internal `edge-control` network. Caddy's admin API is still reachable only from `edge-control` (the domain worker), not from `api` or anything else on `admin`. `edge-ts` runs with `cap_drop: [ALL]` plus `NET_ADMIN` and `NET_RAW` and `/dev/net/tun`; Caddy in the same namespace keeps no capabilities. `NET_RAW` is needed because the image's iptables (legacy backend) cannot open its tables without it. It uses `--shields-up`, so no tailnet device can open a connection to the edge node, and `TS_ACCEPT_DNS=false`, so Docker's resolver keeps resolving `api`.

The existing admin node, `tailscale` with `tailnet-gateway` (profile `tailnet`, userspace, no capabilities), is unchanged and still serves the admin UI over the tailnet. The two nodes have separate state, keys and tags.

**Enrolling the edge node.** The edge serves public traffic without a key. Until it joins, it just waits for login.

1. In the Tailscale admin console, add the tag to the tailnet policy file, owned by the admins who enrol hosts:

   ```json
   "tagOwners": { "tag:ark-edge": ["autogroup:admin"] }
   ```

   Do not add any grant or ACL rule with `tag:ark-edge` as the source yet. With no grants, the edge can reach nothing on the tailnet (§3.7). Route grants come from the ACL snippet generator (FD-07). Also check that no catch-all rule, such as the default `"src": ["*"], "dst": ["*"]`, covers it.

2. Under **Settings → Keys → Generate auth key**, create a key with **Reusable** off (one-off), **Ephemeral** off (the node keeps its state across restarts), **Pre-approved** on, **Tags** `tag:ark-edge`, and an expiry of 1 day.
3. Put it in `.env` as `TS_EDGE_AUTHKEY=tskey-auth-…`. Running `mise run host:install` asks for it on a terminal without echoing it, or takes it from `TS_EDGE_AUTHKEY` in the environment. The installer never replaces a value that is already in `.env`, and never prints it.
4. Start the node and put `edge` back in its namespace:

   ```sh
   docker compose --env-file .env -f infra/platform/docker-compose.yml up -d edge-ts edge
   mise run edge:rejoin
   docker compose --env-file .env -f infra/platform/docker-compose.yml exec edge-ts \
     tailscale --socket=/var/run/tailscale/tailscaled.sock status --json | jq '.Self.Tags'
   ```

   The last command should print `["tag:ark-edge"]`.

5. Delete the key from `.env` (leave `TS_EDGE_AUTHKEY=` empty) and revoke it in the console. The node authenticates from its state volume (`ark_edge_ts_state`) from then on. Tagged devices have key expiry disabled by default.

Allow UDP 41642 in the host and provider firewalls so the edge node can make direct WireGuard connections. Without it, tailnet traffic is relayed through DERP. The host's own tailscaled keeps UDP 41641.

**Restarts and upgrades.** `edge` joins one specific `edge-ts` container. If `edge-ts` is recreated, or restarted in place (by a crash, `docker restart` or `docker compose restart edge-ts`), `edge` keeps running in the old, empty namespace and stops serving. Compose only recreates `edge` by itself when the same `docker compose up` also recreates `edge-ts`. `mise run maintain` runs a rejoin step after every applied release, and so does the installer. After any other `edge-ts` restart, run `mise run edge:rejoin`. It recreates every `network_mode: service:` dependent that is outside its owner's live namespace and does nothing otherwise. `mise run test:edge` checks all three cases.

`ARK_EDGE_GATE_TOKEN` is generated by the installer (never rotated on a re-run). The login gate (FD-11) uses it to authenticate the edge's calls to the API.

**Checking against a real tailnet.** CI has no tailnet, so these checks are opt-in: `mise run test:edge-tailnet`. Without `ARK_TEST_TS_EDGE_AUTHKEY` it prints a skip message and exits 0. Run it on a disposable Linux host, or under Docker Desktop, with UDP 41642 free (or set `ARK_TEST_TS_UDP_PORT`). Use a test tailnet whose policy has no catch-all rule:

```json
{
  "tagOwners": {
    "tag:ark-edge": ["autogroup:admin"],
    "tag:ark-edge-test-peer": ["autogroup:admin"]
  },
  "grants": [{ "src": ["tag:ark-edge-test-peer"], "dst": ["tag:ark-edge"], "ip": ["tcp:80"] }]
}
```

Create two **ephemeral**, pre-approved keys, one tagged `tag:ark-edge` and one tagged `tag:ark-edge-test-peer`. Ephemeral nodes are removed automatically if a run is interrupted. Then run:

```sh
ARK_TEST_TS_EDGE_AUTHKEY=tskey-auth-… ARK_TEST_TS_PEER_AUTHKEY=tskey-auth-… mise run test:edge-tailnet
```

The script starts the shipped `edge-ts` and `edge` services and checks the following:

- `edge-ts` joins with exactly `tag:ark-edge`, and `tailscale0` holds its address in the namespace `edge` runs in. tailscaled's netfilter rules are installed.
- The edge still serves the `:80` ACME challenge.
- UDP 41642 is published and tailscaled listens on it.
- With no grant from `tag:ark-edge`, the edge cannot open TCP to the peer's listener. A control shows that the peer answers on its own address.
- Although the policy lets the peer reach `tag:ark-edge:80`, `--shields-up` refuses the peer's connection. A control shows that Caddy does listen on the edge's tailnet address.
- `tailscale ping --until-direct` reports a direct path. When the network only allows DERP, this is a warning, unless `ARK_TEST_TS_REQUIRE_DIRECT=1` is set.

Without the peer key, it runs the first three checks and skips the rest with a warning. Every node it enrols is logged out at the end.

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

`mise run maintain -- infra/platform/release.json infra/platform/docker-compose.yml` requires an Ed25519 publisher key in `ARK_RELEASE_PUBLIC_KEY`, verifies the bundle signature, exact Compose-file digest, and exact immutable image set, and journals the approval. It pulls every approved digest and executes health-waiting Compose only when `ARK_MAINTENANCE_EXECUTE=1`. It then recreates `edge` if `edge-ts` was restarted or replaced under it (see "Edge Tailscale node"). Stateful images require `allowStateful` after a reviewed migration and recovery plan.

## Third-party image pins

Third-party images (Caddy, Tailscale, PgBouncer, PostgreSQL, Stalwart and the `oven/bun` base) are pinned as `name:version@sha256:<digest>`: the version is for readers, the digest is what Docker pulls. Dependabot (`.github/dependabot.yml`) covers only the bun workspace and GitHub Actions, so it never proposes image bumps. Bump images by hand:

1. Read the upstream release notes between the pinned and the target version, and note behaviour changes that touch Ark's config.
2. Resolve the multi-arch index digest from the registry, not from a local pull (a local `RepoDigests` entry can be a single-platform manifest):

   ```sh
   docker buildx imagetools inspect caddy:2.11.9
   ```

   Take the top-level `Digest:` of the `application/vnd.oci.image.index.v1+json` index and confirm it lists `linux/amd64` and `linux/arm64`. If a design doc or release note quotes a digest prefix, check that the resolved digest starts with it. Then confirm the pinned reference runs the expected version, for example `docker run --rm caddy:2.11.9@sha256:<digest> caddy version`.

3. Replace every reference in one change. For Caddy that is `edge` and `tailnet-gateway` in `infra/platform/docker-compose.yml`, `caddyImage` in `scripts/test-edge-config.ts`, and the sample `infra/platform/release.json` (recompute its `digest` with `bundleDigest` from `@ark-stack/shared`). For Tailscale it is `edge-ts` and `tailscale` in `infra/platform/docker-compose.yml`, and `tailscaleImage` in `scripts/test-edge-config.ts` and `scripts/test-edge-tailnet.ts`. `rg '<old version>'` should then match only historical docs.
4. Run the image's integration task. For Caddy and Tailscale, `mise run test:edge` fails unless both Compose services of each image use exactly the tested pin. It then validates every rendered and static Caddyfile against fixture certificates and runs the edge behaviour tests in disposable containers: header stripping, `Server`/`Via` removal (including a control proving `header_down -Via` alone is insufficient), WebSockets across `/load` and 80 s of idle, and the production edge: the shipped `edge-ts` and `edge` Compose services in a disposable project, with only host paths and ports changed (explicit uid/gid 1000:1000, 0600 private keys, bootstrap Caddyfile, `edge-admin` alias), configured through the real `writeEdge`. That edge must serve each fixture certificate over TLS, skip hostnames whose certificate is not `issued`, answer ACME challenges and 308 redirects on `:80` (404 for other hosts), and serve a renewed certificate after an identical `writeEdge` reload with `Cache-Control: must-revalidate`, which a control `/load` without the header does not.

   For the edge namespace (FD-05), the run then checks the following:

   - `edge-ts` has exactly `NET_ADMIN` and `NET_RAW` and `/dev/net/tun`. A control shows that tailscaled's iptables calls fail with `NET_ADMIN` alone.
   - `tailscale0` is in the namespace Caddy runs in. `--shields-up` and `TS_ACCEPT_DNS=false` reach tailscaled, and UDP 41642 is published.
   - A container on `edge-control` reaches `edge-admin:2019`. A container on `admin` aliased `api` cannot reach it by alias or by either `edge-ts` address.
   - `edge` comes back serving after `edge-ts` is changed through `docker compose up`, restarted in place, or recreated on its own. The last two go through the rejoin step that `mise run maintain` runs.

   `edge-ts` uses an unreachable login server, so the run never contacts Tailscale. The run takes about 2 minutes.

5. In the PR, record the full digest, how it was resolved and verified, and the integration-task output. Roll the release out through `mise run maintain` (above).

## Import

`mise run import -- inventory.json` compares domains, databases, and services. Owners are never imported. Stop the old reconcilers before transferring a live mail domain.

## Local acceptance

`mise run test:e2e` refuses non-loopback PostgreSQL, creates a uniquely named disposable database, migrates it from empty, drives Chromium through owner creation, pre-MFA denial, invalid and valid TOTP, recovery-code acknowledgement, custom domain setup and one-time recovery-code use, then removes the database. The provider/Linux release checks in `security-review.md` remain separate opt-in acceptance work.
