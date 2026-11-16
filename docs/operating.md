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

**Restarts and upgrades.** `edge` joins one specific `edge-ts` container. If `edge-ts` is recreated, or restarted in place (by a crash, `docker restart` or `docker compose restart edge-ts`), `edge` keeps running in the old, empty namespace and stops serving. Compose only recreates `edge` by itself when the same `docker compose up` also recreates `edge-ts`. `mise run maintain` runs a rejoin step after every applied release, and so does the installer. After any other `edge-ts` restart, run `mise run edge:rejoin`. It repairs only the managed `edge` dependent when it is outside its owner's live namespace; optional admin tailnet services are left alone, even if stopped. If `edge-ts` is stopped, it fails with a start-the-owner-first error instead of reporting healthy. `mise run test:edge` checks all three cases.

`ARK_EDGE_GATE_TOKEN` is generated by the installer (never rotated on a re-run). The startup secret guard rejects an explicitly supplied development placeholder; absence remains allowed until FD-11 wires the token into the API. The login gate (FD-11) uses it to authenticate the edge's calls to the API.

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
- The script temporarily disables shields-up on the disposable edge node and requires the peer to connect to TCP 80 under the documented grant. It restores shields-up even if that positive control fails, then requires the same connection to fail. A missing grant or unreachable edge fails the check rather than counting as proof of shields-up.
- `tailscale ping --until-direct` reports a direct path. When the network only allows DERP, this is a warning, unless `ARK_TEST_TS_REQUIRE_DIRECT=1` is set.

Without the peer key, it runs the first three checks and skips the rest with a warning. Every node it enrols is logged out at the end.

## Providers

Set `DNS_API_TOKEN`, `AWS_*`, and `STALWART_*` only on the workers that need them. The public mail container must not receive AWS, DNS, or root keys. `ARK_ALERT_WEBHOOK` must be independent of this mail server.

Set `ARK_OFFHOST_HEARTBEAT_URL` to an independently hosted HTTPS dead-man receiver and give it the generated `ARK_OFFHOST_HEARTBEAT_TOKEN`. Test receiver expiry by stopping the disposable host; an on-host Prometheus instance cannot prove total host loss.

## Public database port limits

nftables (`inet ark_db_ingress`, docs/design/front-door.md §3.11) limits every source on the public PostgreSQL port, because Vercel and similar platforms cannot be IP-allowlisted. By default each source gets 128 concurrent connections and 30 new connections per second, with a burst of 60. IPv4 sources are counted per address and IPv6 sources per /64. The rules run on both the `input` hook (today's host listener) and the `forward` hook (Docker DNAT), and they are applied after any per-database CIDR allowlist. An owner can change the limits on the settings page or with `PUT /api/settings/db-ingress`, which needs MFA and a `platform.update` step-up. The change updates the rules through a `pgbouncer.reload` operation. API startup also queues a policy-only reconciliation for existing public databases, so an upgrade replaces an older on-disk policy without owner action. External workers wait for the host reconciler to acknowledge the exact policy and listener state; failures appear in the operations list. The reconciler checks for changed policy or exposure every 1.5 s as a fallback for missed filesystem notifications. `mise run test:upgrade` requires Docker and checks startup activation against a legacy policy in an isolated container network namespace.

`database-ingress` exports the drop counters every 15 s to `tmp/db-ingress/counters.json`, and `/api/metrics/prometheus` serves them as `ark_nft_drop_packets_total{table,chain,reason,family}`. `ArkDatabaseIngressDrops` fires after 10 minutes of continuous drops. Check whether a legitimate client (for example a Vercel deployment's shared egress address) needs higher limits, or whether the port is under abuse. Rules are replaced atomically while dynamic sets and named counters survive reapplication. Each configured cap uses its own connection-set generation. When the cap changes, sources with sessions in an older generation cannot open new sessions until those sessions drain and the kernel collects the old entries; established sessions continue. New sources use the new cap immediately. Rate changes start a new token bucket generation. `ArkDatabaseIngressCountersStale` alerts after five minutes if snapshots are missing, unreadable or corrupt, or if snapshot age stays above five minutes. The ingress writer runs as root with only `NET_ADMIN` and `DAC_OVERRIDE` to access the installer-owned policy and snapshot directories; the API retains a read-only metrics mount. `mise run test:db-ingress` (also part of `mise run test:edge`) checks the rendered rules with `nft -c` and exercises them with real connections in a privileged container (Docker Desktop or a Linux host).

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

3. Replace every reference in one change. The `oven/bun` and Prometheus pins also appear in `scripts/test-db-ingress.ts`. For Caddy that is `edge` and `tailnet-gateway` in `infra/platform/docker-compose.yml`, `caddyImage` in `scripts/test-edge-config.ts`, and the sample `infra/platform/release.json` (recompute its `digest` with `bundleDigest` from `@ark-stack/shared`). For Tailscale it is `edge-ts` and `tailscale` in `infra/platform/docker-compose.yml`, and `tailscaleImage` in `scripts/test-edge-config.ts` and `scripts/test-edge-tailnet.ts`. `rg '<old version>'` should then match only historical docs.
4. Run the image's integration task. For Caddy and Tailscale, `mise run test:edge` fails unless both Compose services of each image use exactly the tested pin. It then validates every rendered and static Caddyfile against fixture certificates and runs the edge behaviour tests in disposable containers: header stripping, `Server`/`Via` removal (including a control proving `header_down -Via` alone is insufficient), WebSockets across `/load` and 80 s of idle, and the production edge: the shipped `edge-ts` and `edge` Compose services in a disposable project, with only host paths and ports changed (explicit uid/gid 1000:1000, 0600 private keys, bootstrap Caddyfile, `edge-admin` alias), configured through the real `writeEdge`. That edge must serve each fixture certificate over TLS, skip hostnames whose certificate is not `issued`, answer ACME challenges and 308 redirects on `:80` (404 for other hosts), and serve a renewed certificate after an identical `writeEdge` reload with `Cache-Control: must-revalidate`, which a control `/load` without the header does not.

   For the edge namespace (FD-05), the run then checks the following:

   - `edge-ts` has exactly `NET_ADMIN` and `NET_RAW` and `/dev/net/tun`. A control shows that tailscaled's iptables calls fail with `NET_ADMIN` alone.
   - `tailscale0` is in the namespace Caddy runs in. `--shields-up` and `TS_ACCEPT_DNS=false` reach tailscaled, and UDP 41642 is published.
   - A container on `edge-control` reaches `edge-admin:2019`. A container on `admin` aliased `api` cannot reach it by alias or by either `edge-ts` address.
   - `edge` comes back serving after `edge-ts` is changed through `docker compose up`, restarted in place, or recreated on its own. The last two go through the rejoin step that `mise run maintain` runs.

   `edge-ts` uses an unreachable login server, so the run never contacts Tailscale. The run takes about 2 minutes.

5. In the PR, record the full digest, how it was resolved and verified, and the integration-task output. Roll the release out through `mise run maintain` (above).

## Tailnet policy snippet

Ark never holds a Tailscale key that can write the tailnet policy. The owner copies the generated snippet from **Front door ACL** in the UI (`GET /api/front/acl` for every route and tailnet backup target, `GET /api/front/routes/:id/acl` for one route; both owner-only) and merges each section into the tailnet policy file by hand. The snippet declares the four Ark tags, one host alias per target machine, one grant per target `host:port` for `tag:ark-edge`, one per tailnet backup target for `tag:ark-backup`, and a `tests` block. Its TCP and UDP deny assertions sample common ports, every configured service port, observed non-target nodes and the other Ark tags. They catch broad allow-all rules and UDP leaks on routed ports. They do not prove isolation at untested ports, other protocols or unobserved nodes. Remove or narrow broad rules and review the complete policy before pasting. Per-route tests account for all configured routes and backup targets, so they can be merged with the global policy. If a tag already appears in your `tagOwners`, keep one entry. The page also shows what changed since the last generated snippet, a Tailnet Lock explainer, and an optional Tailscale SSH policy for `tag:ark-vps` in `check` mode, which is kept out of the snippet itself.

For a local check of **every TCP/UDP port** on known destinations, save a freshly generated **global** snippet as `global-snippet.hujson` and the entire proposed merged policy as `candidate-policy.hujson`, then run:

```sh
bun scripts/audit-tailnet-policy.ts global-snippet.hujson candidate-policy.hujson
```

The local audit compares all grant/ACL port-range boundaries, including port zero, against the trusted global snippet, rather than sampling ports. It catches missing grants, extra ports, UDP leaks and access to observed non-target addresses. Its model supports direct Ark tags, users, host aliases, IPs, CIDRs, `*` and common autogroups; unsupported rule selectors or conditions are refused. It does **not** model group membership, multi-tag membership, posture, `via`, application capabilities or protocols other than TCP/UDP; it cannot establish tailnet-wide isolation or replace Tailscale validation and a complete policy review. ICMP can be implicitly allowed by Tailscale when traffic is allowed between two nodes. Refresh inventory and the global snippet before each audit. No policy is uploaded or changed by this command.

The snippet's syntax and tests can be checked against a real tailnet with an opt-in script. CI does not run it, because it needs credentials. Use a scratch tailnet, not production:

1. In the scratch tailnet's admin console, generate an API access token (Settings → Keys). Tailscale's validate endpoint needs only the `policy_file:read` scope, so an OAuth client limited to that scope also works.
2. Run `ARK_TEST_TS_POLICY_API_KEY=tskey-api-... mise run test:tailnet-acl`. Set `ARK_TEST_TS_TAILNET` if the token can reach more than one tailnet (the default is `-`, the token's own tailnet).
3. The script calls only `POST /api/v2/tailnet/{tailnet}/acl/validate`, which never changes the policy. It checks that the §3.7 sample snippet validates on its own and together with the SSH example, and that adding a broad `*` grant or a legacy allow-all ACL makes the snippet's tests reject the policy. It exits 0 with a `skipped` message when the variable is unset.
4. Revoke the token afterwards.

## Import

`mise run import -- inventory.json` compares domains, databases, and services. Owners are never imported. Stop the old reconcilers before transferring a live mail domain.

## Local acceptance

`mise run test:e2e` refuses non-loopback PostgreSQL, creates a uniquely named disposable database, migrates it from empty, drives Chromium through owner creation, pre-MFA denial, invalid and valid TOTP, recovery-code acknowledgement, custom domain setup and one-time recovery-code use, then removes the database. The provider/Linux release checks in `security-review.md` remain separate opt-in acceptance work.
