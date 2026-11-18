# Operating

This is the operator reference. The task-oriented guides are:

- [Front door](guides/front-door.md): public routes, Postgres routes, ACL snippet, DNS and IPv6.
- [Database access from Vercel](guides/vercel-database.md): client certificates, env vars and rollover.
- [Off-VPS backups](guides/backups.md).

Runbooks in this file:

- [Edge Tailscale node](#edge-tailscale-node) (enrolment)
- [Revocation](#revocation)
- [Certificate rollover](#certificate-rollover)
- [Third-party image pins](#third-party-image-pins)
- [Opt-in live test suites](#opt-in-live-test-suites)

## Fresh install

1. Install Docker and pin tools with `mise install`.
2. On an Ubuntu VPS, follow [VPS hardening](#vps-hardening) to enroll the host and install the platform. For a local install, run `mise run host:install` to generate secrets, build the images, migrate, and start the platform, pinned Stalwart engine, and Prometheus. Existing `.env` values are kept.
3. Open the printed setup URL over an SSH tunnel if the host is remote. The raw API bootstrap listener is bound only to `127.0.0.1:3000`; public administration is served only through the configured edge after domain and certificate reconciliation.
4. Create the owner, enroll MFA, then run the domain wizard.
5. Copy the generated DNS records, or publish the reviewed Cloudflare diff after MFA.
6. Recheck until endpoints leave `awaiting_dns`. Incoming mail can become ready while SES stays paused.

For local development, `mise run db:up` adds `infra/platform/docker-compose.dev.yml`, which binds the two PostgreSQL engines only on loopback ports 5433 and 5434. The production manifest has no host binding for either engine; public database access is exclusively through the TLS pooler profile and its separately enforced source policy.

## VPS hardening

1. Keep the provider console or rescue access working. Configure the [Tailscale Ubuntu package source](https://tailscale.com/kb/1347/installation) so the installer can install the host package. In the tailnet policy, declare `tag:ark-vps` and merge the owner-only grant for TCP 22 and the SSH rule in `check` mode from [Front door ACL](#tailnet-policy-snippet). Use the owner's untagged device for SSH.
2. Create a one-off, pre-approved, non-ephemeral key tagged `tag:ark-vps`. Put it in a private file on the VPS with mode `0600`, then run the enrollment phase as root. After enrollment, remove the key file and revoke the key.

   ```sh
   sudo TS_VPS_AUTHKEY_FILE=/root/ark-vps-authkey mise run host:install --enroll-vps
   ```

3. From the owner's device, verify a new `tailscale ssh <user>@<vps-magicdns-name>` session and keep it open. From that session or the provider console, run the hardening phase. Set `ARK_MAIL_ENABLED=0` in `.env` if this install should run without Stalwart. The default maintenance window is 04:00 in the server's time zone. Set `ARK_HOST_REBOOT_TIME=HH:MM` in the installer environment or `.env` to change it.

   ```sh
   sudo mise run host:install --harden-vps
   ```

   This installs the `ark_host` nftables baseline before Docker starts at boot. Incoming connections are allowed on loopback and the host's `tailscale0`, and public traffic is limited to the enabled service ports. IP control traffic such as IPv6 neighbor discovery and path MTU discovery is allowed, as are DHCPv6 replies to the link-local client. The forward chain checks the original destination port of DNAT traffic, including Docker publications. The front policy still applies source restrictions and connection limits, and restores active raw and compatibility ports after a reboot. On an already hardened host, run subsequent installer updates as root.

   The installer checks the effective daily update schedule, Ubuntu security origin and reboot settings before running `unattended-upgrades --dry-run`. Prometheus raises `ArkHostRebootRequired` when the reboot-required flag persists for five minutes. The host refreshes the flag roughly every 30 seconds and the API exports it as `ark_host_reboot_required`.

   To disable mail on an existing installation, rerun `host:install` with `ARK_MAIL_ENABLED=0`. The installer stops the prior firewall reconciler on a hardened host, then stops Stalwart, its worker and the old API before applying the mail-off baseline. If the build fails, retry the installer to restore the API and reconciler with the saved settings. On Ubuntu, the installer and signed maintenance refuse overlapping runs. Signed maintenance keeps the mail worker stopped while mail is disabled. Mail operations return an unavailable response, and jobs already queued resume when mail is enabled again.

4. After confirming a new Tailscale SSH session works with the baseline active, remove public TCP 22 at the provider. Stop Ubuntu's legacy public OpenSSH listener or bind it to a private address before running the audit. Tailscale SSH is served by `tailscaled`. Use nftables for the Ark host firewall and remove conflicting UFW rules. Keep the provider's required ICMP and ICMPv6 allowances.

### Provider firewall and audit

Generate the inbound TCP and UDP rules from the VPS after the front policy has reconciled. Apply the generated `providerRules` to the VPS in your provider's firewall console or infrastructure configuration. The rules include both address families. Keep the provider firewall in sync when mail, shared SNI ports or raw/compatibility routes change.

```sh
sudo mise run host:audit --inventory > ark-host-inventory.json
sudo mise run host:audit
```

The inventory covers 80, 443 and 5432, enabled SNI and dedicated route ports, and UDP 41641 and 41642. TCP 25, 465, 587 and 993 belong to Stalwart and appear only with mail enabled. The local audit checks the installed nftables baseline, `ss` and Docker port mappings. An unexpected public bind or publication fails even if the firewall has blocked it. The audit accepts the firewall-gated raw range reserved by `edge-ts` and DHCP client sockets owned by the network manager. HAProxy reserves 5432 and rejects connections until a pooler endpoint or PostgreSQL route is active.

Copy the inventory to the off-host heartbeat runner or another external machine with Nmap and IPv4 and IPv6 access to the VPS. Run the external check there with permission to send raw probes. Give it the VPS's public address literals.

```sh
sudo mise run host:audit --external ark-host-inventory.json <public-ipv4> <public-ipv6>
```

The probe scans all TCP and UDP ports. Internet-enabled services must answer the TCP scan. A source-restricted raw route can be filtered from the runner's address. UDP discovery depends on a service responding to a scan probe. The external audit reports `open|filtered` as unverified and exits unsuccessfully when a required UDP port cannot be confirmed. The scratch VPS test can confirm receipt of unauthenticated probe packets after the VPS firewall.

`mise run test:host-hardening` runs against an isolated Ubuntu systemd guest, a separate scanner on its public test network, and pinned HAProxy and Stalwart images in the guest's own Docker daemon. For a real scratch VPS, `mise run test:host-hardening-live` verifies owner Tailscale SSH, runs the local audit, and checks UDP receipt using temporary counters after the Ark and Docker firewall hooks. Run it from an off-host machine with Nmap and Docker. Supply the public literals in `ARK_TEST_VPS_IPV4` and `ARK_TEST_VPS_IPV6`, an inventory export in `ARK_TEST_VPS_INVENTORY`, the VPS's MagicDNS name and local username in `ARK_TEST_VPS_SSH_ADDRESS` and `ARK_TEST_VPS_SSH_USER`, and the absolute installation path on the VPS in `ARK_TEST_VPS_ROOT`. The scratch user must be able to run `sudo -n mise` and `sudo -n nft` for the local audit and temporary counters. Supply the scratch tailnet owner's login email in `ARK_TEST_VPS_TAILNET_OWNER` and an absolute path to the private state file of a disposable, untagged owner device in `ARK_TEST_VPS_TAILNET_STATE_FILE`. Stop that device's daemon before copying its state, and complete SSH check-mode reauthentication on it before export. The live task skips unless all values are present.

### Native IPv6 and AAAA publication

Set the VPS's actual global IPv6 address in the domain wizard. On a hardened VPS, the installer enables Docker IPv6, IPv6 firewall processing and live restore. It then migrates the published networks and verifies that the edge and enabled mail service have IPv6 addresses. Only then does it disable the userland proxy and recreate publications made before the daemon change. The first upgrade can interrupt Docker traffic. Keep provider console access available during this change. The installer preserves the rest of the daemon configuration and rejects wildcard publications that would lose IPv6 when the proxy is disabled.

Bring up HTTPS for a configured hostname over IPv4 first. Preflight runs weekly, on changes to the configured address or active edge, and on demand. When a managed runner is configured, unsuccessful checks become eligible for retry after five minutes. AAAA stays withheld until a check passes. An MFA-enrolled owner can start it with `POST /api/settings/ipv6/preflight` and read status and per-port evidence from `GET /api/settings/ipv6/preflight?operationId=<id>`. A pass makes AAAA eligible for the ordinary DNS review. A failure starts withdrawal through the same provider authorization and public DNS checks used by the domain's AAAA switch.

Run probes from outside the VPS. Give the probe its own allowed IPv6 source, TLS trust roots if required, and ordinary service credentials. PostgreSQL checks authenticate and execute a read-only query. PgBouncer needs its client certificate, key and database login. A direct PostgreSQL route needs the login accepted by the target and any client certificate the route requires. Set `ARK_IPV6_PROBE_CREDENTIALS` on the probe machine to a private JSON file. Its keys are the check IDs in the request, including `pgbouncer` and PostgreSQL route IDs. Values can include `username`, `password`, `database` and PEM strings in `ca`, `cert` and `key`.

- With `ARK_OFFHOST_HEARTBEAT_URL` configured, expose the runner's `POST /preflight` over HTTPS on the heartbeat host. Run `bun --no-env-file scripts/ipv6-preflight-probe.ts serve` behind that host's HTTPS gateway, using the same `ARK_OFFHOST_HEARTBEAT_TOKEN` and setting `ARK_IPV6_PROBE_ADDRESS` to this VPS's approved public IPv6 address.
- For a manual check, save the `manual` object from the owner status response as a private `request.json` on the probe machine. Within 15 minutes run `bun --no-env-file scripts/ipv6-preflight-probe.ts run request.json https://<admin-origin>`. The script posts the signed result to the admin origin. Use the returned operation ID to look up the result. A signed report can verify listeners whose admission and target connection the edge can corroborate. If the host serves PostgreSQL on 5432, configure the HTTPS runner so database authentication can be verified.

`mise run test:ipv6-preflight` runs the mandatory local Docker and Pebble acceptance test. `mise run test:ipv6-preflight-live` runs either live check only when its settings are supplied. For the real VPS, configure the managed runner if the scratch host exposes PostgreSQL on 5432. Set `ARK_TEST_IPV6_VPS_ORIGIN`, `ARK_TEST_IPV6_VPS_ADDRESS`, `ARK_TEST_IPV6_VPS_SESSION_FILE` (a private file containing the scratch MFA-enrolled owner's Cookie header value) and `ARK_IPV6_PROBE_CREDENTIALS` (use an empty JSON object when no private credentials are needed). For Let's Encrypt staging, supply an AAAA-only scratch hostname and its address in `ARK_TEST_IPV6_STAGING_HOSTNAME` and `ARK_TEST_IPV6_STAGING_ADDRESS`, an account email in `ARK_TEST_IPV6_STAGING_EMAIL`, a key-authenticated `user@host` in `ARK_TEST_IPV6_STAGING_SSH`, and its writable challenge webroot in `ARK_TEST_IPV6_STAGING_WEBROOT`. The scratch VPS must have `lego` on the SSH user's path.

## Public certificates

The domain worker defaults to `ARK_ACME_STAGING=1`. Staging certificates are recorded as `untrusted` and are never served by the public edge. To enable public HTTPS, set `ARK_ACME_EMAIL` and `ARK_ACME_STAGING=0` in the installation `.env`, recreate the domain worker (`docker compose --env-file .env -f infra/platform/docker-compose.yml up -d domain-worker`), and issue or renew the endpoint certificates. Existing staging certificates need reissuance; changing the flag alone does not make them trusted.

The `edge-apply` operation evidence lists `awaitingCertificate` hostnames and `unrouted` web addresses. A switch to public administration requires an issued certificate for the admin hostname; rejection preserves routing, settings and sessions. Keep the local tunnel available while provisioning the first public certificate.

## Edge Tailscale node

The public edge has its own Tailscale node, `edge-ts` (`tag:ark-edge`, hostname `ark-edge`), in kernel mode (docs/design/front-door.md §3.6). It owns the network namespace that the `edge` Caddy container and the `edge-l4` HAProxy container join (`network_mode: service:edge-ts`), so `edge-ts` publishes TCP 80 and 443 and UDP 41642, and carries the `edge-admin` alias on the internal `edge-control` network. HAProxy owns 443 and Caddy's HTTPS sites listen on `127.0.0.1:8443` behind it (see "HAProxy SNI router (edge-l4)"). Caddy's admin API is still reachable only from `edge-control` (the domain worker), not from `api` or anything else on `admin`. `edge-ts` runs with `cap_drop: [ALL]` plus `NET_ADMIN` and `NET_RAW` and `/dev/net/tun`; Caddy and HAProxy in the same namespace keep no capabilities. `NET_RAW` is needed because the image's iptables (legacy backend) cannot open its tables without it. It uses `--shields-up`, so no tailnet device can open a connection to the edge node, and `TS_ACCEPT_DNS=false`, so Docker's resolver keeps resolving `api`.

The existing admin node, `tailscale` with `tailnet-gateway` (profile `tailnet`, userspace, no capabilities), is unchanged and still serves the admin UI over the tailnet. The two nodes have separate state, keys and tags.

**Enrolling the edge node.** The edge serves public traffic without a key. Until it joins, it just waits for login.

1. In the Tailscale admin console, add the tag to the tailnet policy file, owned by the admins who enrol hosts:

   ```json
   "tagOwners": { "tag:ark-edge": ["autogroup:admin"] }
   ```

   Do not add any grant or ACL rule with `tag:ark-edge` as the source yet. With no grants, the edge can reach nothing on the tailnet (§3.7). Route grants come from the ACL snippet generator (FD-07). Also check that no catch-all rule, such as the default `"src": ["*"], "dst": ["*"]`, covers it.

2. Under **Settings → Keys → Generate auth key**, create a key with **Reusable** off (one-off), **Ephemeral** off (the node keeps its state across restarts), **Pre-approved** on, **Tags** `tag:ark-edge`, and an expiry of 1 day.
3. Put it in `.env` as `TS_EDGE_AUTHKEY=tskey-auth-…`. Running `mise run host:install` asks for it on a terminal without echoing it, or takes it from `TS_EDGE_AUTHKEY` in the environment. The installer never replaces a value that is already in `.env`, and never prints it.
4. Start the node, then put `edge` and `edge-l4` back in its namespace:

   ```sh
   docker compose --env-file .env -f infra/platform/docker-compose.yml up -d edge-ts edge edge-l4
   mise run edge:rejoin
   docker compose --env-file .env -f infra/platform/docker-compose.yml exec edge-ts \
     tailscale --socket=/var/run/tailscale/tailscaled.sock status --json | jq '.Self.Tags'
   ```

   The last command should print `["tag:ark-edge"]`.

5. Delete the key from `.env` (leave `TS_EDGE_AUTHKEY=` empty) and revoke it in the console. The node authenticates from its state volume (`ark_edge_ts_state`) from then on. Tagged devices have key expiry disabled by default.
6. With Tailnet Lock enabled, sign the new node from a trusted signing node (`tailscale lock sign <node key>`). Then check `GET /api/front/tailnet`: the next `edge.observe` (or `POST /api/front/tailnet/observe`) must commit a generation whose self node carries `tag:ark-edge`. Routes then wait in `awaiting_acl` until their grants from [Tailnet policy snippet](#tailnet-policy-snippet) are merged.

**Re-enrolling or replacing the edge node.** Never reuse a failed node identity. Remove the old `ark-edge` device in the admin console, then create a fresh one-off key and repeat steps 2–6. The `ark_edge_ts_state` Compose volume (`ark-platform_ark_edge_ts_state` in Docker) holds the old identity, so stop `edge-ts` and remove that one volume first. Every route's pinned target stays valid, because pins name the target machines, not the edge. Routes are withdrawn while the lease has no valid generation and return after the first observation of the new node.

Allow UDP 41642 in the host and provider firewalls so the edge node can make direct WireGuard connections. Without it, tailnet traffic is relayed through DERP. The host's own tailscaled keeps UDP 41641.

**Restarts and upgrades.** `edge` and `edge-l4` join one specific `edge-ts` container. If `edge-ts` is recreated, or restarted in place (by a crash, `docker restart` or `docker compose restart edge-ts`), they keep running in the old, empty namespace and stop serving. Compose only recreates them by itself when the same `docker compose up` also recreates `edge-ts`. `mise run maintain` runs a rejoin step after every applied release, and so does the installer. After any other `edge-ts` restart, run `mise run edge:rejoin`. It repairs only the managed `edge` and `edge-l4` dependents when they are outside their owner's live namespace; optional admin tailnet services are left alone, even if stopped. If `edge-ts` is stopped, it fails with a start-the-owner-first error instead of reporting healthy. `mise run test:edge` checks all three cases.

`ARK_EDGE_GATE_TOKEN` is generated by the installer and never rotated on a re-run. Compose passes it to `api`, `edge` and `tailnet-gateway`. The startup secret guard rejects an explicitly supplied development placeholder.

**Gate login origin (FD-10).** The edge sends the token on the login origin's allowlisted sign-in, sign-out, get-session and two-factor requests. Public administration and tailnet administration also send it on the same exact auth paths, plus two-factor disable and backup-code generation. Client-supplied `X-Ark-*` headers are stripped first. Only on these exact paths, with the genuine token, does the API take the client address from the proxy's `X-Forwarded-For`. The public edge uses HAProxy's PROXY v2 client address. The tailnet gateway listens only on loopback, trusts only the local Tailscale Serve proxy with strict forwarding-chain parsing, and sends its resolved client address. Every other caller is identified by its transport peer address; no Docker subnet is trusted (`ARK_TRUSTED_PROXIES` is gone). Optionally, set `ARK_EDGE_PEER_ADDRESSES` to a comma-separated list of exact transport IP addresses for edge-ts and the tailnet gateway on the `admin` network as an extra check. This is not a CIDR list or a trust grant by itself.

A missing or empty token is allowed with the login origin disabled; admin requests then fall back to their transport peer and share its rate-limit bucket. Configure the generated token on all three services to preserve per-client admin limits. Without it the login origin cannot be enabled. Enable it with `PUT /api/settings/gate` and `{ "mode": "public", "hostname": "login.<domain>" }`. This needs owner, MFA and an `exposure.public` step-up, a verified domain and an HTTPS `BETTER_AUTH_URL`. Ark then creates the address records, verifies DNS, issues the certificate and serves the login site.

Sign-in and two-factor attempts are limited to 5 per minute per client address. Auth cookies are `__Host-` cookies over HTTPS: after this upgrade every admin signs in again once.

The API answers only registered hosts: the hosts of `BETTER_AUTH_URL` and `BETTER_AUTH_TRUSTED_ORIGINS`, and the login host. Keep the local bootstrap origin (`http://127.0.0.1:3000`) in `BETTER_AUTH_TRUSTED_ORIGINS` if you still sign in through an SSH tunnel.

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

- The edge observer's production LocalAPI client (FD-06) reads a complete generation as uid 1000 through the read-only socket mount, with the edge node's own tags.
- The peer appears in the edge node's status (it may connect to the edge), but its TCP 8080 is not granted to `tag:ark-edge`, so the edge-netns probe through LocalAPI `dial` fails: a route to it would stay `awaiting_acl`. With `ARK_TEST_TS_GRANTED_PORT=<port>` and a policy grant `{"src": ["tag:ark-edge"], "dst": ["tag:ark-edge-test-peer"], "ip": ["tcp:<port>"]}`, the script listens on that port on the peer and requires the probe to pass, which is what moves a route to `ready`. Without the variable this check is skipped with a warning.

Without the peer key, it runs the first three checks and the generation read, and skips the rest with a warning. Every node it enrols is logged out at the end.

## Edge observer and lease watchdog

Every tailnet route is pinned to its target machine's Tailscale identity (StableNodeID) and served only while that identity is current (docs/design/front-door.md §3.2, FD-06).

**Observation.** `edge.observe` runs in the domain worker every 5 minutes, and on demand from `POST /api/front/tailnet/observe` (owner only). It reads `GET /localapi/v0/status` from the edge node through `ark_edge_ts_socket`, mounted read-only into `domain-worker` and nowhere else; the API never has the socket. The worker runs as the non-root `bun` user, and tailscaled gives such a caller read access only. `mise run test:edge` proves this against the pinned tailscaled: status succeeds through the `:ro` mount, `PATCH /localapi/v0/prefs`, start, logout, serve-config and reset-auth answer 403 (and `POST /localapi/v0/prefs` 405), and a root control shows the same mount accepts writes. Read-only callers may also use `dial` and `ping`; Ark uses `dial` for the TCP probe below. That gives the worker no new reach, because it already writes the edge configuration. No observer sidecar and no Tailscale OAuth client or API key is used.

Each complete read is committed as one generation (the edge node and all its peers), replacing the previous one and deleting absent peers in the same transaction. Its lease lasts 6 minutes from the start of the read. A failed or partial read (tailscaled unreachable, not logged in, malformed or duplicate peers) changes nothing and never renews the lease; the operation fails and raises the usual failed-operation alert. A fresh host whose edge node has not joined yet therefore shows failed `edge.observe` runs until it is enrolled.

After each generation every route is re-validated:

- Its machine missing from the generation: `awaiting_acl` for an observed route. Routes already in `awaiting_dns` or `issuing_certificate` retain that lifecycle position and record the transient identity error in `last_error`; recovery never skips DNS or certificate work.
- The entered name now belonging to a different machine (a renamed or re-registered device): `identity_mismatch`. This sticks until the owner re-confirms the target with `PATCH /api/front/routes/:id` and an `exposure.public` step-up (see "HTTP routes").
- Same machine at a new address: the pinned IP is updated and audited.
- Valid identity: a TCP probe from the edge node's namespace to the exact target port, through LocalAPI `dial`. Only a passing probe makes the route `ready`; netmap presence alone is not enough, because a peer that may connect to the edge also appears in status. A failing probe keeps it `awaiting_acl` with the reason in `last_error`; check the tailnet grant (`GET /api/front/acl`). A route that has not finished its lifecycle yet moves on to `awaiting_dns` instead of `ready` until its hostname has an issued certificate, and routes in `awaiting_dns` queue a route-only `domain.verify` on every run (see "HTTP routes").

Each run also queues `edge.apply` when a route the lease allows, with an issued certificate that the renderer can serve, is missing from Caddy or missing or fenced in HAProxy, for example after Caddy started from the closed config during a host restart. A route that stops being servable is withdrawn durably: `edge.apply` re-renders without it, and `edge.drain` fences its HAProxy backend, verifies that its sessions have closed, and removes its Caddy proxy handler. `GET /api/front/tailnet` (owner only) shows the latest generation, its lease, the last observation run, and each route's status, identity state and whether it is being served.

**Watchdog.** `edge-watchdog` is a small first-party container on `control` and `edge-control`, with no database credential, root key or socket. At least every second it reads `GET /api/internal/edge/lease` with `ARK_EDGE_WATCHDOG_TOKEN` (lease reads and event reports only; no operation-worker access) and withdraws each tailnet route handler that the lease does not allow from the running Caddy, through Caddy's admin API. The allowlist holds enabled `ready` routes whose pinned identity matches the current generation while its lease is valid. Native Caddy `vars` metadata binds each handler to its route ID, hostname, stable machine ID and backend. Two hostnames sharing an address remain independently revocable; unmarked legacy tailnet handlers fail closed. So the watchdog withdraws:

- a replaced or removed identity as soon as its generation commits;
- every tailnet route when the lease expires, at most 6 minutes plus 5 seconds after the last completed observation, even with every worker stopped;
- every tailnet route when it cannot read the lease for 5 seconds.

A withdrawal disables the affected HAProxy server and closes its sessions across current and leaving workers. Caddy also reloads the denied route with a fixed 503. Other routes keep serving, and `stream_close_delay` still applies to routine reloads. Each watchdog report queues `edge.apply` so the files follow the policy. The watchdog waits at most 300 ms for each lease refresh. It stops Caddy with `POST /stop` and raises a critical alert if it cannot read or update Caddy's active config. A withdrawal with delayed streams also stops Caddy if the watchdog cannot confirm scoped HAProxy control. During cutover the shared HAProxy worker keeps accepting connections while Caddy restarts from its lease-checked files. On a closed restart the watchdog can restore the currently allowed routes from the matching on-disk generation with an ETag check. Reports include a bounded backend sample and are retried on delivery failure.

**Launch guard.** `edge` starts through `infra/platform/edge-launch-guard.sh`, with the official Caddy binary unchanged. The domain worker writes `tmp/edge/Caddyfile` and `tmp/edge/Caddyfile.closed`, which renders no tailnet route. The guard asks the watchdog (`GET http://edge-watchdog:2021/v1/launch`) and starts from `Caddyfile` only if the answer is `open`: every tailnet handler in it matches an allowed route identity and pinned backend under a valid lease. Otherwise, including when the watchdog is unreachable, it starts from `Caddyfile.closed`, so ACME, redirects and the admin site keep working and tailnet routes fail closed. A `Caddyfile` with no tailnet route starts as it is. The same applies when Docker restarts Caddy after the watchdog stopped it. The guard logs its choice (`docker compose logs edge`) and stays alive as Caddy’s supervisor. Once tailnet routes exist in the rendered file or active configuration, it requires a successful `GET /v1/supervise` every second (one-second request timeout). That endpoint answers only after a verified enforcement pass within the last two seconds. After a two-second initial Caddy startup grace, a missing, frozen or unhealthy watchdog causes the supervisor to kill Caddy, closing listeners and existing sessions. Restart still uses the closed variant until the full file is authorised. Closed starts may restart repeatedly while enforcement is unavailable; configurations verified to have no tailnet routes keep serving.

`ARK_EDGE_WATCHDOG_TOKEN` is generated by the installer. Without it, the watchdog cannot read the lease and every tailnet route stays withdrawn. The watchdog enforces HAProxy (`edge-l4`) too, through its master socket; see the next section. `GET /v1/supervise?proxy=caddy` and `?proxy=haproxy` report each proxy separately. Caddy falls back to stopping when a delayed withdrawal cannot verify scoped HAProxy control.

`mise run test:edge` measures this against the shipped `edge-ts` and `edge` services, using a mocked LocalAPI and a local PostgreSQL (`DATABASE_URL`, as for `mise run test`). It checks that a replaced identity is withdrawn, and its session closed, within detection + 5 s without any `edge.apply`; that with observation stopped the route is withdrawn by last completion + lease + 5 s (the lease is shortened to 8 s for the test); that a restart with an expired lease, or without the watchdog, comes up closed; that shared-backend hostnames are revoked independently (the other hostname keeps serving without an `edge.apply`) and a stale launch file stays closed; that stopping or freezing the watchdog while serving closes existing sessions within five seconds; and that a refused reload or unreadable admin config stops Caddy and raises the alert. Listener closure is timed on Caddy's `127.0.0.1:8443` listener itself, by a prober inside the edge namespace, so HAProxy's handling on 443 does not count. The route's end-to-end outcome through 443 is checked separately, against the same five-second bound.

## HAProxy SNI router (edge-l4)

`edge-l4` is the official digest-pinned `haproxy:3.2.26-alpine` image in the `edge-ts` namespace (docs/design/front-door.md §3.8). It owns public 443 and routes by TLS SNI. Each HTTP route has a dedicated `be_http_<hostname>` backend. The admin and login sites use `be_caddy`. All of these backends connect to Caddy on `127.0.0.1:8443` with PROXY v2 and fail fast with `retries 0` and `timeout connect 1s`. Failed loopback connects show `SC` and retries `/0` in the HAProxy log. The scoped router refuses unmatched SNI. An incomplete or non-TLS connection is closed within 5 s. Caddy's HTTPS listener is loopback-only and requires the PROXY header. Caddy's `:80` listener handles plain HTTP. HTTP/3 is off. Caddy returns 421 when the HTTP/1.1 Host or HTTP/2 authority differs from the connection's SNI.

**Configuration generations.** The domain worker's `edge.l4_apply` (queued by every `edge.apply`) renders an immutable generation under `tmp/edge-l4/generations/<id>`: `haproxy.cfg`, `haproxy.closed.cfg` (L4 tailnet backends omitted, HTTP still checked by Caddy), allowlists and `manifest.json`. The ID is the SHA-256 of the generation's contents. The restricted `haproxy-validator` container (the same HAProxy digest, with no network and no Docker) re-hashes the generation, refuses symlinks and runs only `haproxy -c` on it. The worker then checks that no byte changed, swaps the `current` symlink atomically and sends `reload` on the master socket. An invalid candidate never changes `current`, and no reload is sent. Any failed or unconfirmed reload restores the previous `current` (or removes it on a first install). A durable `reload-pending` marker forces a retry, including after a timeout or process restart; a symlink alone never proves activation. The validator client allows 25 seconds for the two bounded 10-second config checks. Apply, reload and drain run under one database advisory lock. The operation evidence (`edge-l4-apply`) records the generation, the previous one, whether a reload ran and its log. Generations are kept while an older worker is still draining.

**Maintenance cutover.** Before starting the new edge services, `mise run maintain` stops the domain writer and edge proxies, then runs the approved domain-worker image once as root with CHOWN, FOWNER and DAC_OVERRIDE. The idempotent initializer seeds the missing HAProxy tree, sets uid 1000/group 4400 and modes, and converts both persisted Caddy variants to loopback 8443 with required PROXY headers while retaining their routes and certificates. Services then start from the converted files. This avoids rerunning the host installer during an upgrade. The domain worker confirms an accepting scoped HAProxy generation before it closes residual connections from the old shared Caddy backend. Subsequent withdrawals target the affected routes.

**Users, group and sockets.** HAProxy and the validator run as the image's uid 99, and the domain worker as `bun` (uid 1000). They share only the supplementary group 4400, as does the edge watchdog. The installer checks the numeric uid and that GID 4400 is free in the pinned images, seeds `tmp/edge-l4` with an initial generation, and (as root on Linux) gives it to uid 1000, group 4400: directories `2750`, files `0640`. The socket directories are tmpfs volumes, `99:4400`, mode `2770`. The master socket (`/var/run/haproxy/master.sock`), the admin socket (`admin.sock`) and the validator socket are `0660`, group 4400. No service has Docker access for this. To inspect from the host:

```sh
docker compose --env-file .env -f infra/platform/docker-compose.yml exec edge-l4 sh -c 'echo "show proc" | socat - UNIX-CONNECT:/var/run/haproxy/master.sock'
docker compose --env-file .env -f infra/platform/docker-compose.yml exec edge-l4 sh -c 'echo "show stat" | socat - UNIX-CONNECT:/var/run/haproxy/admin.sock'
```

**Withdrawal and launch guard.** The watchdog withdraws tailnet backends from HAProxy through the master CLI, admission first. In each worker that still accepts connections, it disables every server that the lease no longer allows, then shuts down that server's sessions. In leaving workers, whose listeners are already closed, it shuts down each affected session. It repeats `show proc` until the worker set is stable, then checks each worker's `show servers state` and `show sess`. A server is allowed only while its name, derived from the route ID, hostname, stable machine ID and pinned address, matches an allowed route. If withdrawal cannot be verified, the watchdog fences tailnet servers and their sessions, preserves unrelated HTTP, and raises the critical alert. Continued unverified enforcement makes the latched launch guard kill the process. `edge.drain` does the same under the edge lock. `edge-l4` starts through `infra/platform/edge-l4-launch-guard.sh`, with the official binary unchanged. A configuration without protected HTTP or L4 routes starts directly. Otherwise the guard asks `GET /v1/launch?proxy=haproxy` and starts from `haproxy.cfg` only on `open`; when the lease is not valid, or the watchdog is unreachable, it starts from `haproxy.closed.cfg`. It switches to the full configuration (and reloads) once the lease allows it. Once a protected HTTP or L4 backend has existed, supervision stays latched for the life of that master, including after the final route is removed. It polls verified HAProxy enforcement every 250 ms with a 500 ms request timeout and kills after two misses, closing listeners and sessions; the restart comes up closed. A busy HAProxy pass can use at most 3 s from its last verified observation, leaving time for supervision and shutdown within five seconds. Heartbeat enforcement runs separately from launch polling and reloads, so frozen-watchdog shutdown stays within five seconds. A failed reopen retains closed mode and retries until `Success=1`. Caddy and HAProxy enforcement run independently, so an HAProxy stall does not age Caddy’s heartbeat. The HAProxy stop fallback fences tailnet servers and sessions without closing the public HTTP frontend. The guard logs each decision (`docker compose logs edge-l4`).

`mise run test:edge` (`scripts/test-edge-l4.ts`) runs the shipped `edge-ts`, `edge`, `edge-l4` and `haproxy-validator` services, the bundled watchdog and the domain worker's code as uid 1000 with group 4400 and no capabilities. It covers socket modes, validation, refusal of an invalid candidate, `show stat`, worker enumeration and `Success=1`/`Success=0` reloads with the old worker still serving. It checks PROXY trust (headerless loopback TLS refused, the real address in `X-Forwarded-For`, 8443 unreachable from every Docker network, PROXY ignored on `:80`), the 421, the absence of `Alt-Svc`, every HTTP route through 443, and the 5 s idle close. It keeps a WebSocket open across an HAProxy and a Caddy reload, and requests sent during Caddy reloads all succeed. With Caddy's listener closed, it checks that a connection through 443 is reset within 1 s, with no retries. It shows withdrawal on identity change and on lease expiry, with sessions in both a current and a leaving worker, a closed start with an expired lease, and the switch back. No database or tailnet login is needed. The run takes about 3 minutes, plus a first build of the validator image.

## TLS-TCP and raw-TCP routes

Two more route kinds use `edge-l4` (docs/design/front-door.md §3.8, FD-14). Create them with `POST /api/front/routes` (owner, MFA and an `exposure.public` step-up bound to the exact body). They follow the same lifecycle as HTTP routes (ACL probe, DNS, certificate, `ready`), and they are listed under **Front door routes** in the UI, together with the protocol guidance table (§3.8.2).

- **`tls`**: TLS from the first byte (MQTT over TLS, AMQPS, LDAPS, Redis/Valkey TLS, standalone MongoDB, NATS with `handshake_first`). The route is selected by SNI on 443, or on a shared SNI port enabled at install time. `tlsMode` is one of these:
  - `passthrough`: the target keeps its own certificate.
  - `terminate`: the edge terminates TLS with the hostname's certificate and forwards plaintext over WireGuard. It needs a restricted, non-empty `sourceCidrs`.
  - `terminate_mtls`: as `terminate`, and clients must also present a certificate from the route's own CA, checked against its CRL. Issue client certificates with `POST /api/front/routes/:id/client-certificates` (`credential.rotate` step-up; a generated key is revealed once through `POST /api/secrets/:id/reveal`). Revoke one with `POST …/client-certificates/:certificateId/revoke`.
- **`tcp`**: raw TCP with no TLS at the edge (SSH, game servers, MySQL, raw MQTT), on a dedicated `listenPort` from 20000–20049. It is always `plain` and needs `allowPlaintext: true`. The API refuses ports outside that range, `tls` routes on raw ports, and the platform and mail ports 25, 80, 443, 465, 587, 993, 2019, 3000, 5432, 41641 and 41642.

**Admission.** Each route has its own allowlist (`sourceCidrs`) and limits (`limits.maxConn`, `perSourceConn`, `perSourceRate` per 10 s; defaults are 50/10/20 for `tls` and 20/5/10 for `tcp`). HAProxy applies them in the route's backend before it forwards, and before TLS termination for terminated routes, so the original source address is used. The immutable Lua admission action reads live source and total counters from current and leaving workers, so reloads preserve limits and closing an old session releases capacity. Inspection failures deny new admission. For a shared port, a refusal affects only that route's traffic. An empty list denies every source. Enable is refused while the list is empty. `allowInternet: true` is the only way to open a route to everyone, and it is saved with the owner's `exposure.public` confirmation. A `plain` route can only be opened to the internet with `protocolAuthConfirmed: true`. CIDRs broader than /8 (IPv4) or /16 (IPv6) are refused unless `allowInternet` is set.

**Revocation and disable.** A route's admission policy (CIDRs, limits, TLS mode, client CA and its revoked serials) is part of its lease identity and its HAProxy server names. Any policy change, a client certificate revocation, a disable or a delete therefore makes the running servers unauthorised. Within a second, the edge watchdog fences them and shuts their sessions down in every current and leaving worker, admission first; `edge.drain` does the same. `edge.l4_apply` then reloads the restricted generation. Other routes' sessions are untouched. Route CA CRLs are 14-day CRLs. `edge.l4_apply` regenerates any that are missing or have less than 7 days left, and `edge.observe` queues it when one is due. Revocation status, the regenerated CRL and durable apply/drain jobs commit atomically. The renderer uses one policy/material snapshot and refuses a CRL missing any committed revocation. Stale or malformed CRLs are refreshed regardless of expiry. Observation also restores missing or fenced L4 routes.

**Shared SNI ports.** Select them at install time: set `ARK_EDGE_SNI_PORTS` (a comma-separated subset of 8883, 5671, 636, 6380) in `.env` or in the environment, then run `mise run host:install`. The installer writes one `ARK_EDGE_SNI_PORT_<n>=<n>:<n>` entry per enabled port, and the `edge-ts` port list publishes exactly those. HAProxy keeps the enabled frontends in both generations and rejects unmatched SNI. A disabled port is published only on an ephemeral loopback port, where nothing listens. The API and domain worker read the same `ARK_EDGE_SNI_PORTS`. Changing the set recreates `edge-ts`; run `mise run edge:rejoin` afterwards. The raw range 20000–20049 is always published. A range port without an enabled route has no listener.

**Host nftables.** `renderFrontIngress` (`shared/src/front-nft.ts`) renders `inet ark_front`. TCP 80, 443 and the enabled SNI ports share a per-source budget of 256 concurrent connections and 50 new connections per second with a burst of 100. Set `ARK_FRONT_MAX_CONNECTIONS`, `ARK_FRONT_RATE_PER_SECOND` and `ARK_FRONT_RATE_BURST` in the platform environment to change it.

TCP routes and PostgreSQL compatibility ports use their own CIDR lists and per-source limits. An empty list drops traffic unless the route has explicit `allowInternet`. Ports in 20000–20049 without an enabled route drop traffic. Forward rules match only original-direction DNAT, and both policies count IPv6 sources by /64.

The domain worker submits the front policy and the 5432 limits together. `database-ingress` retires the old raw-port table in the same transaction, reads back both tables, and acknowledges the exact policy hash and request ID in `tmp/edge-l4/front-ingress/policy.status` before HAProxy reloads. A failed install or readback triggers a drop guard for the batch’s ports and records the error. A successful retry releases the guard.

`mise run test:edge` (`scripts/test-edge-l4-routes.ts`) runs the §3.8.5 example and these rules against the shipped services. See the header of that file for the full list.

## HTTP routes

Owners publish a tailnet service under a public hostname with `POST /api/front/routes` (docs/design/front-door.md §3.3, FD-08). Every role can list routes (`GET /api/front/routes`, `GET /api/front/routes/:id`) with their status, listener, pinned target, address records and certificate state. Every change is owner-only with MFA; operators and viewers get 403.

| Call                                 | Step-up grant                                                                                                                                                                                                   |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /api/front/routes`             | `exposure.public`, bound to the exact JSON body                                                                                                                                                                 |
| `PATCH /api/front/routes/:id`        | `exposure.public` bound to `{ routeId, ...body }` when it loosens (target, port, re-confirmation, `sso` → `public`, removing a redirect, a sensitive port, a new bypass path or allowed origin); none otherwise |
| `POST /api/front/routes/:id/enable`  | `exposure.public`, bound to `{ routeId }`                                                                                                                                                                       |
| `POST /api/front/routes/:id/disable` | none (tightening); the backend is drained at once                                                                                                                                                               |
| `DELETE /api/front/routes/:id`       | `resource.delete`, bound to `{ routeId }`                                                                                                                                                                       |
| `PUT /api/front/routes/:id/access`   | `role.grant`, bound to `{ routeId, userIds }`                                                                                                                                                                   |

Preparation validates before using a grant; final validation, consumption and mutation commit together, so a typo or state conflict never burns a password and MFA round. Only `kind: "http"` exists in this release. `accessMode` is `"sso"` (the default: only users on the route's access list, signed in at the login origin) or `"public"`; see "Login gate for SSO routes" below. `bypassPaths` and `allowedOrigins` apply to `sso` routes only. `redirectTo` (another hostname in the same domain) makes the apex answer with a 308 redirect to, for example, `www` (`https://example.com/x` → `https://www.example.com/x`).

A route hostname must be inside a domain claim whose ownership is verified (otherwise 422); the apex and `www` both work. Creating a route adds an A record for `public_ipv4`, and an AAAA record for `public_ipv6` only when the IPv6 preflight passed (`ipv6_status = passed`) and the domain's AAAA switch is on. Ark only writes A/AAAA, never a CNAME at the apex. DNS checks reconcile the published addresses with the IPv6 gate. They retain obsolete AAAA records as pending removals until public DNS confirms their absence. Route hostnames under `ts.net` or the configured tailnet suffix are refused.

Open **Review DNS** on the Domains screen or **DNS** beside a route. Cloudflare shows the changes for the whole domain, including any exact provider records that will be deleted. **Publish reviewed DNS** starts a tracked operation to apply that plan as DNS-only records and queue verification. Resolve blocked records such as a conflicting MX at the provider. Independent records can still be published. If the provider or plan changed, reload the review before publishing again. The API exposes the same plan at `GET /api/domains/:id/dns` and `GET /api/front/routes/:id/dns`. Send its `planHash` and an optional UUID `requestId` to `POST /api/domains/:id/publish`. Retry with the same request ID and body to retrieve the same operation. Use a fresh request ID to publish again after reviewing a failed operation. The response contains `operationId`. Read status at `GET /api/domains/:id/publish/:operationId`. The Cloudflare token needs Zone Read and DNS Edit for the zone and stays with the domain worker.

An owner can approve future withdrawal for the exact Ark-owned AAAA records in a reviewed publish. Turn that authorization off with **Revoke automatic withdrawal** or `DELETE /api/domains/:id/aaaa/authorization`. Without authorization, Cloudflare withdrawal needs a new reviewed publish. After an exact Cloudflare deletion, Ark waits the provider TTL and checks a public resolver. For Namecheap and other providers, follow the guide and remove the exact rows marked **Remove at provider**. The review stays pending until a public lookup confirms absence. Automatic checks for manual removals stop after 30 minutes. Open the review or use **Recheck DNS** to start a fresh window. When Cloudflare ownership names a previous zone, Ark needs access to the original record to confirm its removal before publishing a replacement. To disable IPv6 DNS use `PUT /api/domains/:id/aaaa` with `{ "enabled": false }`. Enabling requires an `exposure.public` step-up bound to `{ domainId, enabled: true }`.

A route then moves through `draft → awaiting_acl → awaiting_dns → issuing_certificate → ready`:

1. `draft`: creation records this audit state, then commits the route, endpoint, address records, audit events and `awaiting_acl` state atomically. The response returns the tailnet ACL snippet; periodic observation recovers the handoff if the immediate enqueue is interrupted.
2. `awaiting_acl`: waiting for the edge-netns TCP probe of the next `edge.observe` (queued at once). Add the snippet's grant to the tailnet policy.
3. `awaiting_dns`: the probe passed. Route-only `domain.verify` checks that each required address resolves to this server. Cloudflare addresses require a reviewed publish before they can pass. The route records actionable errors for proxied addresses, unexpected IPv6 and CAA restrictions that block Let's Encrypt.
4. `issuing_certificate`: the records resolve; only now is `certificate.issue` queued. A staging or local certificate is never served, so the route waits here with an explanation; a failed issuance is retried with `POST /api/domains/:id/verify`.
5. `ready`: an issued certificate and a fresh passing probe. Only `edge.observe` sets `ready`.

`enable` is refused (409) before `ready`. Changing the target re-pins it and returns the route to `awaiting_acl` (an enabled route stays enabled, is drained at once, and serves the new target only once it is `ready` again); DNS and certificate work is not repeated once the hostname has an issued certificate. Deleting a route drains it. If it is the endpoint's final route, Ark removes the endpoint and certificates and retains its address records as pending removals in the domain's DNS review. Every action and lifecycle transition writes a `front_route.*` audit event.

For manual DNS, opening the provider guide or selecting **Recheck DNS** starts a 30-minute window. The domain worker checks public DNS every two minutes during that window.

### How the edge serves a route (FD-09)

`edge.apply` reads `front_routes` and renders only enabled `ready` routes whose pinned identity the edge lease still allows; `edge.l4_apply` then adds exactly those hostnames to the HAProxy 443 map. Routes in `awaiting_acl`, `identity_mismatch`, `observation_expired` or `disabled` are in neither config. An `sso` route is served behind the login gate (below); it keeps its gate checks when admitted. A route whose stored `http_options`, bypass paths or SSO stream-close delay (at most 5 minutes) fail validation is omitted and listed under `omitted` in the `edge-apply` step, instead of failing every apply.

Each served route is a Caddy site on `127.0.0.1:8443` behind the SNI router, with:

- no `Server`, `Via` or `X-Powered-By` on any answer, `X-Content-Type-Options: nosniff`, a referrer policy, and `Strict-Transport-Security: max-age=31536000` (option `hsts`);
- client-sent `X-Ark-*` headers removed and `X-Forwarded-For` set from the real client address (PROXY v2);
- a request body limit (`maxBodyMb`, 25 MB), a 5 s dial timeout and a response-header timeout (`responseHeaderTimeout`, 60 s), no response buffering, and WebSockets kept across reloads for `streamCloseDelay` (5 min);
- `Set-Cookie` `Domain=` attributes removed, so cookies are host-only on the public name;
- `Location` values that point at the target (its tailnet IPv4, IPv6 in compressed, expanded or zero-padded form, MagicDNS or short name, with no port or the target port) rewritten to `https://<public hostname>` with path, query and fragment kept. Any other tailnet address or `.ts.net` name, a malformed or ambiguous authority (userinfo, backslashes, control characters, other IP literals, numeric IPv4 forms) or a special scheme without `//` gets the static 502 instead;
- static 502/503/504 pages from `infra/platform/edge-errors/` (mounted read-only at `/etc/caddy/errors`), which name no internal host.

The edge only controls these headers. Response bodies (HTML, scripts, JSON with absolute URLs), other URL-bearing headers (`Content-Location`, `Refresh`, `Link`), the application's own public-URL setting and the certificates the target presents are passed through unchanged: set the application's public URL to the route hostname and audit what it emits before enabling a route.

Identity failure, lease expiry, disable, deletion and re-targeting fence the affected HTTP backends in HAProxy. The watchdog or domain worker closes WebSockets and other sessions on those backends within the withdrawal bound, including sessions in workers that are leaving after a reload. A single-route withdrawal leaves unrelated HTTP and WebSocket traffic up.

Route mutations compare the prepared row version at commit. A concurrent change returns 409 and preserves the step-up grant. Grant consumption and the route mutation share one transaction. Observer probe results for an older route version are discarded.

Observer-triggered DNS checks touch only route endpoints and ownership proof; they do not publish DNS, provision other services, or retry certificate orders already in progress. Explicit domain verification can retry failed or untrusted issuance and renew a ready route whose certificate is missing, unusable, or expires within 30 days. A ready route that loses its usable certificate returns to the DNS/certificate lifecycle and requires a fresh probe before ready.

### Login gate for SSO routes (FD-11)

An `sso` route serves only users on its access list who signed in at the login origin (`PUT /api/settings/gate`, FD-10) with password and TOTP. The first request without a route session is redirected to `https://<login host>/gate/authorize`; after sign-in the browser returns through `https://<route host>/.ark/gate/callback` to the page it asked for, with a host-only `__Host-ark_gate` cookie for that route only. The upstream receives `X-Ark-User` (user ID) and `X-Ark-Email`, never the gate cookies. A request that does not accept HTML (an XHR, `Accept: application/json`) gets 401 with `WWW-Authenticate: Ark-Gate` instead of a redirect.

- **Access list.** `GET /api/front/routes/:id/access` lists the users; `PUT /api/front/routes/:id/access` with `{ "userIds": [...] }` replaces it (owner, MFA, a `role.grant` step-up bound to `{ routeId, userIds }`). Individual users only. Removing a user denies their next request.
- **WebSockets and forms.** A cookie-authenticated WebSocket upgrade or `POST`/`PUT`/`PATCH`/`DELETE` must come from the route's own origin. A page on another route, even on the same domain, gets 403, as do requests with no `Origin` or `Origin: null`. Approve another origin with `allowedOrigins` (`https://host[:port]`) on the route; that loosens exposure and needs `exposure.public`. `GET` and `HEAD` must not change state in the application.
- **Bypass paths.** `bypassPaths` (for example `["/webhooks/*"]`) skip the session check for webhooks. Requests under them still pass a raw-URI guard: dot segments, `;`, backslashes, encoded dots, slashes, backslashes or `%`, and malformed encodings get 400. `/`, `/*` and anything under `/.ark` are refused. Webhook endpoints must authenticate their callers themselves (signatures). Adding a bypass path needs `exposure.public`.
- **Sign-out.** `POST /.ark/gate/logout` on a route ends that route's session; `POST /gate/logout` on the login origin ends the login session and with it every route session.
- **Open connections.** The gate checks each request. An already upgraded WebSocket keeps its authorization until it closes. Revocations queue an affected-route drain in the revoking transaction. The domain worker fences the backend, closes its sessions across HAProxy workers, reloads the gate configuration and verifies the drain before allowing reconnections. Sockets on that route close for every connected user. If the journal is still pending after 5 s, the watchdog withdraws the route and drains it, and the API raises `Gate revocation not applied within 5 s`. The route returns after a successful drain and reload. Pending drains retry with exponential backoff from 10 seconds to 5 minutes. A later event stays pending even if a drain for an earlier event completes. Expired tokens still require a drain because their previously opened sockets can remain connected. Check the `edge.drain` operations (`reason: gate_revocation`) and the domain worker when the alert appears.

## Providers

Set `DNS_API_TOKEN`, `AWS_*`, and `STALWART_*` only on the workers that need them. The public mail container must not receive AWS, DNS, or root keys. `ARK_ALERT_WEBHOOK` must be independent of this mail server.

Set `ARK_OFFHOST_HEARTBEAT_URL` to an independently hosted HTTPS dead-man receiver and give it the generated `ARK_OFFHOST_HEARTBEAT_TOKEN`. Test receiver expiry by stopping the disposable host; an on-host Prometheus instance cannot prove total host loss.

## Public database port limits

nftables (`inet ark_db_ingress`, docs/design/front-door.md §3.11) limits every source on the public PostgreSQL port, because Vercel and similar platforms cannot be IP-allowlisted. By default each source gets 128 concurrent connections and 30 new connections per second, with a burst of 60. IPv4 sources are counted per address and IPv6 sources per /64. The rules run on the `input` hook (host listeners) and the `forward` hook (original-direction Docker DNAT). HAProxy enforces the pooler and route CIDR lists. An owner can change the limits on the settings page or with `PUT /api/settings/db-ingress`, which needs MFA and a `platform.update` step-up. The change updates the rules through a `pgbouncer.reload` operation. API startup also queues a policy-only reconciliation for existing public databases, so an upgrade replaces an older on-disk policy without owner action. External workers wait for the host reconciler to acknowledge the exact policy hash. The reconciler polls the files for published policy changes and reports failures in `allowlist.status`. The database policy file takes precedence over the 5432 section of any combined front request. If the database file cannot be read or applied, a drop guard closes only 5432. A verified database retry clears it. If the database file is absent, a verified combined request can also clear it. `mise run test:upgrade` requires Docker and checks startup activation against a legacy policy in an isolated container network namespace.

`database-ingress` exports both tables’ drop counters every 15 s to `tmp/db-ingress/counters.json`, and `/api/metrics/prometheus` serves them as `ark_nft_drop_packets_total{table,chain,reason,family}`. A failed scrape leaves that table’s most recent values and timestamp while the other table keeps updating. `ArkDatabaseIngressDrops` fires after 10 minutes of continuous drops. Check whether a legitimate client (for example a Vercel deployment's shared egress address) needs higher limits, or whether the port is under abuse. The 5432 rules are replaced atomically while their dynamic sets and named counters survive reapplication. Front policy reapplication preserves named counters and meter sets whose limits stay the same. When a front limit changes, its meter starts fresh. The 5432 policy uses a separate connection-set generation for each cap. When the cap changes, sources with sessions in an older generation cannot open new sessions until those sessions drain and the kernel collects the old entries; established sessions continue. New sources use the new cap immediately. Rate changes start a new token bucket generation. `ArkDatabaseIngressCountersStale` alerts after five minutes if snapshots are missing, unreadable or corrupt, or if snapshot age stays above five minutes. The ingress writer runs as root with only `NET_ADMIN` and `DAC_OVERRIDE` to access the installer-owned policy and snapshot directories; the API retains a read-only metrics mount. `mise run test:db-ingress` (also part of `mise run test:edge`) checks the rendered rules with `nft -c` and exercises them with real connections in a privileged container (Docker Desktop or a Linux host).

## PostgreSQL router (5432)

Public 5432 belongs to `edge-l4` (`fe_pg5432`, docs/design/front-door.md §3.8.3). `edge-ts` publishes it, and HAProxy reaches PgBouncer over the internal `pgbouncer-ingress` network; the edge namespace never joins `database-management`, so it cannot reach `app-postgres`. Classic `SSLRequest` clients (Vercel and other apps using today's drivers), `GSSENCRequest` and plaintext cancels go to PgBouncer, as does direct TLS (`sslnegotiation=direct`) with the database hostname or no SNI. A `postgres` route's hostname goes to that route; anything else is rejected, and a connection that sends nothing is closed after 5 s. `database-ingress` no longer listens on 5432 and `pgbouncer-public` publishes nothing; the host reconciler applies the 5432 per-source limits and the shared and dedicated port policies before publication.

**Pooler-wide policy.** Classic negotiation carries no database name, so PgBouncer on 5432 has one source policy for every Ark database. A database's CIDRs and its legacy Vercel clients are requests, shown in the databases view under "Public database port (5432)" and by `GET /api/databases/pooler-policy`. Verified Vercel rollover connections use the reviewed source policy and do not add a request. When they differ (for example two databases with different CIDRs, or a restricted database beside an unrestricted legacy Vercel client), PgBouncer is not routed until the owner reviews and saves one common policy (`PUT /api/databases/pooler-policy`, with MFA and an `exposure.public` step-up). An empty policy denies everybody; only "Allow the internet" opens it. A source admitted for one database is admitted for all of them: if a database needs its own isolation, keep it private or put it behind a separate listener. The upgrade adopts the single pre-existing database policy where there is one, so existing Vercel connections keep working; conflicting deployments need that review first. A safety fence reports `fenced` and denies admission even when the saved policy is otherwise publishable; a confirmed reload must lift it. Narrowing the policy applies to new connections; revoke the database client to cut its live sessions.

#### Vercel certificate rollover recovery

When Ark reports a potentially mismatched certificate and key, pause new builds for the affected Vercel target. Reveal the successor and replace both sensitive values using the project and branch in the manual guide. Redeploy the affected target, verify a database connection and confirm delivery in Ark.

An unsettled-write warning also means an earlier request may still reach Vercel. Confirm it has finished before updating the variables. Ark keeps a reservation in `vercel_env_writes` even when the integration is disconnected. If an operator confirms with Vercel that a request with no acknowledgement can no longer write, complete the manual recovery and remove only the reservation matching its `project_id`, `target`, `git_branch` and `operation_id` from the Ark platform database. The production branch key is an empty string. A local timeout or expired worker claim alone cannot establish that the write has settled.

**Postgres routes.** A `postgres` route publishes a tailnet PostgreSQL on 5432 by SNI. Use `passthrough` for PostgreSQL 17 and later, and `terminate` or `terminate_mtls` (edge termination with ALPN `postgresql`) for older servers. Clients connect with `sslmode=verify-full sslnegotiation=direct`; the route form shows the target-hardening checklist and which drivers support direct TLS. For a driver without direct TLS, a passthrough route can enable a compatibility port from 20000–20049, where the target answers `SSLRequest` itself; it uses the route's allowlist and limits. Plaintext cancel requests always reach PgBouncer, so drivers that cancel in plaintext cannot cancel queries on a route.

**Upgrading.** `mise run maintain` stops `database-ingress` (whose old relay held host 5432) before `edge-ts` is recreated with the new port and network; run `mise run edge:rejoin` if `edge-ts` was restarted by other means. `mise run test:edge` runs `scripts/test-edge-pg5432.ts`.

## Revocation

Every revocation below is owner-only with MFA. Tightening needs no step-up; the calls that need one say so. Run API calls from the admin origin (see the console helper in [the Vercel guide](guides/vercel-database.md#1-before-you-start)) or use the matching UI page.

**A public route** (HTTP, TLS, TCP or Postgres; **Front door routes**):

| Goal                               | Call                                                                                                                                                                                                                                                                             |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stop serving now, keep the route   | `POST /api/front/routes/:id/disable` (no step-up). The backend is fenced and its sessions closed within the withdrawal bound; other routes keep serving.                                                                                                                         |
| Remove the route                   | `DELETE /api/front/routes/:id` (`resource.delete` bound to `{ routeId }`). It drains the route. Removing the endpoint's final route also removes its certificates and leaves the address records as pending removals in the DNS review (publish or remove them at the provider). |
| Narrow who may connect (L4 routes) | `PATCH /api/front/routes/:id` with a smaller `sourceCidrs` or lower `limits` (no step-up). The HAProxy server names change, so the watchdog fences the old servers and `edge.drain` closes their sessions.                                                                       |
| Revoke one `terminate_mtls` client | `POST /api/front/routes/:id/client-certificates/:certificateId/revoke` (no step-up). The CRL is regenerated and the route's servers are renamed; sessions with the revoked certificate are closed.                                                                               |
| Cut the tailnet path entirely      | Remove the route's grant from the tailnet policy. The next `edge.observe` probe fails and the route returns to `awaiting_acl` (withdrawn).                                                                                                                                       |

**A gate user** (SSO routes; **Gate users**):

- Remove the user from one route with `PUT /api/front/routes/:id/access` and the reduced `{ "userIds": [...] }` (`role.grant` bound to `{ routeId, userIds }`). Their next request is denied.
- Delete the user everywhere with `DELETE /api/gate/users/:id` (`role.grant` bound to `{ gateUsers: "delete", userId }`). This deletes the user's sessions and every route session.

Each revocation is journalled in the same transaction and queues an `edge.drain` (`reason: gate_revocation`) of every affected route. Open WebSockets on that route close for every user, and reconnecting users pass the gate again. If the drain is not applied within 5 s, the watchdog withdraws the route and the API raises `Gate revocation not applied within 5 s` ([Login gate for SSO routes](#login-gate-for-sso-routes-fd-11)).

**A database client** (Vercel and other PgBouncer clients): `POST /api/databases/:id/clients/:clientId/revoke` (`credential.rotate` bound to `{ databaseId, clientId }`). `database.client_revoke` removes every CA generation of the client, rotates the role password and sets it `NOLOGIN`, reloads PgBouncer, runs `KILL_CLIENT` on the role's live sessions and deletes any Vercel integration credentials. New handshakes fail with `unknown ca`. Other clients and their sessions are untouched. Narrowing the pooler-wide policy does **not** close live sessions; revoke the client for that.

**The edge or backup node itself**: remove the device in the Tailscale admin console. The observation lease then expires and every tailnet route is withdrawn within 6 minutes + 5 s. Re-enrol as in [Edge Tailscale node](#edge-tailscale-node).

## Certificate rollover

**Database client certificates (90 days).** Ark issues the successor at T−30 from a fresh CA and reloads PgBouncer with both CAs. It raises `db-client-rollover:<client>`: info, then warning at T−14 (`ArkDatabaseClientRolloverWarning`) and critical at T−7 (`ArkDatabaseClientRolloverCritical`). The predecessor is retired at `not_after`, and its role is drained by `not_after + 5 s`. The step-by-step manual delivery is in [the Vercel guide, §7](guides/vercel-database.md#7-manual-rollover):

1. reveal the successor;
2. replace `ARK_DB_CLIENT_CERT_B64` and `ARK_DB_CLIENT_KEY_B64`;
3. redeploy;
4. check access;
5. `POST …/rollover/confirm`.

To start one early (for a drill or a suspected key leak), use `POST /api/databases/:id/clients/:clientId/rollover` (`credential.rotate`). A CSR client must send a new `csrPem`.

If `ArkDatabaseClientRetirementFailed` fires (`db-client-retire:<certificate>`), the database worker could not drain the old generation. The independent watchdog has already disabled the database and stopped PgBouncer, or closed the public listener when the admin socket was unusable. Check the database worker and `pgbouncer-public` logs, and the `client_certificate_retirements` row's error. The task retries with backoff. Clients reconnect once PgBouncer is back with the reduced bundle. For a mismatched Vercel push, see [Vercel certificate rollover recovery](#vercel-certificate-rollover-recovery).

**Route client CAs (`terminate_mtls`).** Route CA CRLs last 14 days. `edge.l4_apply` regenerates any CRL with less than 7 days left, and `edge.observe` queues it when one is due. Nothing needs to be done by hand. Route client certificates are reissued through `POST /api/front/routes/:id/client-certificates`, followed by revoking the old one.

**Public Let's Encrypt certificates** (routes, the login and admin hosts, and the database endpoint). `ArkCertificateExpiry` fires when a managed certificate expires within 14 days. Domain verification (`POST /api/domains/:id/verify`, or **Recheck** on the Domains screen) renews any ready endpoint whose certificate is missing, unusable or within 30 days of expiry. No scheduled job queues that renewal by itself, so run verification when the window opens or the alert fires. A renewed database certificate is served only after a successful `pgbouncer.reload` that verifies the served fingerprint. Caddy and HAProxy pick up renewed certificates through `edge.apply`.

## Recovery

`mise run recover -- status` prints bootstrap state without changing data. Setup cannot be reopened while users exist. Keep local recovery codes and the generated `ARK_MFA_RECOVERY_TOKEN` off-host. If an owner loses every factor, run `mise run recover:mfa -- owner@example.com RESET:owner@example.com "$ARK_MFA_RECOVERY_TOKEN"` on the host. It revokes every session and step-up grant before permitting re-enrollment.

`mise run recover-host` prints the host-loss checklist. Restore into `infra/restore/docker-compose.yml` first. Do not reuse a failed Tailscale node identity.

## Mode changes

Switching public and tailnet administration is a durable operation that rewrites the edge config and revokes sessions. A failed private path must not silently republish the dashboard.

## Backups

Upload, integrity, and restore-test are three statuses. File restore tests use an exact successful export and its sealed target credentials. PostgreSQL application restore tests refuse worker-local execution; use the off-VPS recovery tool for database recovery. A successful upload is not a verified restore. Set `ARK_BACKUP_EXECUTE=1` only when pgBackRest or Restic should run. Mail jobs additionally require `ARK_MAIL_SNAPSHOT_READY=1` from a completed native snapshot/quiesce step. Plan-only execution fails the operation instead of reporting success.

PostgreSQL backups run inside each cluster's container (`ark-postgres`, `ark-app-postgres`) into an encrypted local pgBackRest repo2, and leave the VPS as restic snapshots to the S3-compatible targets (FD-21) and the home machine's `rest-server --append-only` over the tailnet (FD-30, through the dedicated `backup-ts` node, `tag:ark-backup`, with its own one-off `TS_BACKUP_AUTHKEY`) configured under **Backups**. "Backups healthy" needs both. A PostgreSQL backup row is `local` until a snapshot containing it reaches a target. The installer generates `ARK_PLATFORM_PG_EXECUTOR_TOKEN`, `ARK_APP_PG_EXECUTOR_TOKEN`, `ARK_PLATFORM_PG_REPO_CIPHER_PASS` and `ARK_APP_PG_REPO_CIPHER_PASS`; without a cipher pass and an executor token of at least 24 characters WAL archiving stays off and backup health says so. Copy both cipher passes and every target's restic password off-host. `pgbackrest expire` is never run on the VPS. Provider recipes, the home-machine setup, the append-only canaries, alerts and the off-VPS restore runbook (`scripts/offsite-restore.ts`) are in [docs/guides/backups.md](guides/backups.md).

## Maintenance

`mise run maintain -- infra/platform/release.json infra/platform/docker-compose.yml` requires an Ed25519 publisher key in `ARK_RELEASE_PUBLIC_KEY`, verifies the bundle signature, exact Compose-file digest, and exact immutable image set, and journals the approval. It pulls every approved digest and executes health-waiting Compose only when `ARK_MAINTENANCE_EXECUTE=1`. It then recreates `edge` if `edge-ts` was restarted or replaced under it (see "Edge Tailscale node"). A signed release that enables native IPv6 requires an upgraded Docker bridge. On a hardened VPS, it also requires a fresh native IPv6 observer snapshot and, when mail is enabled, a dual-stack mail publication. If the runner reports that these prerequisites are missing, run the staged `mise run host:install` from the release checkout and retry signed maintenance once the observer has refreshed. Stateful images require `allowStateful` after a reviewed migration and recovery plan.

## Third-party image pins

Third-party images (Caddy, HAProxy, Tailscale, PgBouncer, PostgreSQL, Stalwart and the `oven/bun` base) are pinned as `name:version@sha256:<digest>`: the version is for readers, the digest is what Docker pulls. Dependabot (`.github/dependabot.yml`) covers only the bun workspace and GitHub Actions, so it never proposes image bumps. Bump images by hand:

1. Read the upstream release notes between the pinned and the target version, and note behaviour changes that touch Ark's config.
2. Resolve the multi-arch index digest from the registry, not from a local pull (a local `RepoDigests` entry can be a single-platform manifest):

   ```sh
   docker buildx imagetools inspect caddy:2.11.9
   ```

   Take the top-level `Digest:` of the `application/vnd.oci.image.index.v1+json` index and confirm it lists `linux/amd64` and `linux/arm64`. If a design doc or release note quotes a digest prefix, check that the resolved digest starts with it. Then confirm the pinned reference runs the expected version, for example `docker run --rm caddy:2.11.9@sha256:<digest> caddy version`.

3. Replace every reference in one change. The `oven/bun` and Prometheus pins also appear in `scripts/test-db-ingress.ts`. For Caddy that is `edge` and `tailnet-gateway` in `infra/platform/docker-compose.yml`, `caddyImage` in `scripts/test-edge-config.ts`, and the sample `infra/platform/release.json` (recompute its `digest` with `bundleDigest` from `@ark-stack/shared`). For Tailscale it is `edge-ts`, `tailscale` and `backup-ts` in `infra/platform/docker-compose.yml`, and `tailscaleImage` in `scripts/test-edge-config.ts`, `scripts/test-edge-tailnet.ts` and `scripts/test-backups-tailnet-live.ts`. For HAProxy it is `edge-l4` in `infra/platform/docker-compose.yml`, the `haproxy-validator` stage in `Dockerfile` (it must stay the same digest), `haproxyImage` in `scripts/test-edge-l4.ts` and `server/src/edge-l4-policy.test.ts`, and `scripts/install-edge-l4.test.ts`. The `oven/bun` Alpine pin of the validator stage follows the `oven/bun` version. `rg '<old version>'` should then match only historical docs.
4. Run the image's integration task. For Caddy and Tailscale, `mise run test:edge` fails unless both Compose services of each image use exactly the tested pin. It then validates every rendered and static Caddyfile against fixture certificates and runs the edge behaviour tests in disposable containers: header stripping, `Server`/`Via` removal (including a control proving `header_down -Via` alone is insufficient), WebSockets across `/load` and 80 s of idle, and the production edge: the shipped `edge-ts` and `edge` Compose services in a disposable project, with only host paths and ports changed (explicit uid/gid 1000:1000, 0600 private keys, bootstrap Caddyfile, `edge-admin` alias), configured through the real `writeEdge`. That edge must serve each fixture certificate over TLS, skip hostnames whose certificate is not `issued`, answer ACME challenges and 308 redirects on `:80` (404 for other hosts), and serve a renewed certificate after an identical `writeEdge` reload with `Cache-Control: must-revalidate`, which a control `/load` without the header does not.

   For the edge namespace (FD-05), the run then checks the following:

   - `edge-ts` has exactly `NET_ADMIN` and `NET_RAW` and `/dev/net/tun`. A control shows that tailscaled's iptables calls fail with `NET_ADMIN` alone. tailscaled uses legacy `ip6tables`, and a container cannot load kernel modules, so on a Linux host the `ip6table_filter` and `ip6table_nat` modules must already be loaded. Otherwise tailscaled logs `Table does not exist` and the check fails. CI loads them with `modprobe` first.
   - `tailscale0` is in the namespace Caddy runs in. `--shields-up` and `TS_ACCEPT_DNS=false` reach tailscaled, and UDP 41642 is published.
   - A container on `edge-control` reaches `edge-admin:2019`. A container on `admin` aliased `api` cannot reach it by alias or by either `edge-ts` address.
   - `edge` comes back serving after `edge-ts` is changed through `docker compose up`, restarted in place, or recreated on its own. The last two go through the rejoin step that `mise run maintain` runs.

   `edge-ts` uses an unreachable login server, so the run never contacts Tailscale. The run takes about 2 minutes.

   For other images, run the matching task instead:

   - HAProxy: `mise run test:edge` (`scripts/test-edge-l4.ts` and `server/src/edge-l4-policy.test.ts` compare their pin with Compose and the validator stage).
   - PgBouncer: `mise run test:pgbouncer`, which checks the `PgBouncer 1.26.1` banner.
   - Tailscale for `backup-ts`: `mise run test:backups-tailnet`.
   - The PostgreSQL base of `postgres`/`app-postgres`: `mise run test:backups`, which builds and runs the actual Compose clusters, and `mise run test:pgbouncer`.
   - Stalwart: `mise run test:stalwart`.

5. **Check the first-party build plan.** The `oven/bun`, HAProxy validator and PostgreSQL base pins are build inputs of the first-party Bake targets. Run `bun scripts/check-image-plan.ts`. It runs `docker buildx bake --print` and fails unless the default group has exactly the expected targets (`imageTargets`), each with the repository source label and annotation and minimal provenance. CI runs it as well, together with a `--no-cache` build of every target. Then `mise run images:publish -- --dry-run` shows the tags and labels a release would push.
6. In the PR, record the full digest, how it was resolved and verified, and the integration-task output. Roll the release out through `mise run maintain` (above). The release bundle's image list must contain the new digest. `scripts/edge-test/pins.ts` checks that `infra/platform/release.json` carries the tested Caddy pin and a matching `bundleDigest`.

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

`mise run test:db` runs the DB-backed server tests against a throwaway `postgres:17.6` container that it migrates as `ark_migration` and removes on completion or interruption (cleanup failure returns nonzero). `mise run test:db:up` keeps one running and prints shell exports plus the `ark_test_db <file>` helper, which isolates follow-up tests from inherited provider settings (see the README).

`mise run test:e2e` refuses non-loopback PostgreSQL, creates a uniquely named disposable database, migrates it from empty, drives Chromium through owner creation, pre-MFA denial, invalid and valid TOTP, recovery-code acknowledgement, custom domain setup and one-time recovery-code use, then removes the database. The provider/Linux release checks in `security-review.md` remain separate opt-in acceptance work.

These Docker-only container harnesses need no external credentials:

- `mise run test:edge`
- `mise run test:db-ingress`
- `mise run test:pgbouncer`, which needs the migrated platform database in `DATABASE_URL`, for example from `eval "$(mise run test:db:up)"`
- `mise run test:e2e-gate`
- `mise run test:host-hardening`
- `mise run test:ipv6-preflight`
- `mise run test:backups`
- `mise run test:backups-tailnet`
- `mise run test:upgrade`
- `mise run test:stalwart`

## Opt-in live test suites

These suites need real external accounts, so CI never runs them. Each one prints a skip message and exits 0 unless its variables are set. Use scratch accounts, never production, pass credentials only through the environment, and revoke them afterwards.

| Suite                                                  | Run                                                     | Required variables                                                                                                                                                                                                                                                                                                                    | Covers                                                                                                                         |
| ------------------------------------------------------ | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Vercel scope proof and refusals (FD-29)                | `bun --no-env-file test server/src/vercel-live.test.ts` | `ARK_TEST_VERCEL_PROJECT_ID`, `ARK_TEST_VERCEL_TEAM_ID`, `ARK_TEST_VERCEL_OTHER_PROJECT_ID`, `ARK_TEST_VERCEL_PROJECT_TOKEN`. Refusal fixtures as available: `ARK_TEST_VERCEL_TEAM_TOKEN`, `ARK_TEST_VERCEL_ACCOUNT_TOKEN`, `ARK_TEST_VERCEL_OTHER_PROJECT_TOKEN`, `ARK_TEST_VERCEL_EXPIRED_TOKEN`, `ARK_TEST_VERCEL_NO_EXPIRY_TOKEN` | The four exact probe statuses and metadata shape needed before connection can be enabled in `server/src/modules/vercel-api.ts` |
| Vercel hook delivery                                   | same file                                               | `ARK_TEST_VERCEL_DEPLOY_HOOK` (production branch), `ARK_TEST_VERCEL_PREVIEW_DEPLOY_HOOK` (non-production branch)                                                                                                                                                                                                                      | Exact READY match, target, custom-environment exclusion and branch filtering                                                   |
| Vercel env inheritance on redeploy                     | same file                                               | `ARK_TEST_VERCEL_REDEPLOY_TOKEN` (or the project token), `ARK_TEST_VERCEL_BASELINE_DEPLOYMENT_ID`, `ARK_TEST_VERCEL_CANARY_BASELINE`, optional `ARK_TEST_VERCEL_AUTOMATION_BYPASS`                                                                                                                                                    | Whether `POST /v13/deployments` with `deploymentId` picks up changed env vars (design §3.10.5)                                 |
| Edge node on a real tailnet                            | `mise run test:edge-tailnet`                            | `ARK_TEST_TS_EDGE_AUTHKEY`; optional `ARK_TEST_TS_PEER_AUTHKEY`, `ARK_TEST_TS_GRANTED_PORT`, `ARK_TEST_TS_UDP_PORT`, `ARK_TEST_TS_REQUIRE_DIRECT`                                                                                                                                                                                     | Tags, grant-less isolation, shields-up, UDP 41642, LocalAPI read and probe ([Edge Tailscale node](#edge-tailscale-node))       |
| Tailnet ACL snippet                                    | `mise run test:tailnet-acl`                             | `ARK_TEST_TS_POLICY_API_KEY` (`policy_file:read`); optional `ARK_TEST_TS_TAILNET`                                                                                                                                                                                                                                                     | `POST /acl/validate` accepts the snippet and its tests reject broad rules ([Tailnet policy snippet](#tailnet-policy-snippet))  |
| Home backup on a real tailnet                          | `mise run test:backups-tailnet-live`                    | `ARK_TEST_TS_BACKUP_AUTHKEY` and `ARK_TEST_TS_HOME_AUTHKEY` (ephemeral, pre-approved); optional `ARK_TEST_TS_EDGE_AUTHKEY`, `ARK_TEST_TS_POLICY_API_KEY`, `ARK_TEST_TS_TAILNET`                                                                                                                                                       | Backup through `backup-ts` with only `tag:ark-backup → home:8000`, edge deny                                                   |
| Hosted S3 (AWS, B2, R2)                                | `mise run test:backups-hosted`                          | `ARK_TEST_S3_PROVIDER`, `ARK_TEST_S3_ENDPOINT`, `ARK_TEST_S3_BUCKET`, `ARK_TEST_S3_ACCESS_KEY_ID`, `ARK_TEST_S3_SECRET_ACCESS_KEY`; set `ARK_TEST_S3_REGION` for B2; R2 lock evidence needs `ARK_TEST_R2_ACCOUNT_ID` and `ARK_TEST_R2_VERIFIER_TOKEN`                                                                                 | Backup and off-VPS restore against the real provider ([backups guide](guides/backups.md#testing))                              |
| Real VPS hardening                                     | `mise run test:host-hardening-live`                     | `ARK_TEST_VPS_IPV4`, `ARK_TEST_VPS_IPV6`, `ARK_TEST_VPS_INVENTORY`, `ARK_TEST_VPS_SSH_ADDRESS`, `ARK_TEST_VPS_SSH_USER`, `ARK_TEST_VPS_ROOT`, `ARK_TEST_VPS_TAILNET_OWNER`, `ARK_TEST_VPS_TAILNET_STATE_FILE`                                                                                                                         | Owner Tailscale SSH, local audit, external scan and UDP receipt ([Provider firewall and audit](#provider-firewall-and-audit))  |
| IPv6 preflight on a real VPS and Let's Encrypt staging | `mise run test:ipv6-preflight-live`                     | VPS: `ARK_TEST_IPV6_VPS_ORIGIN`, `ARK_TEST_IPV6_VPS_ADDRESS`, `ARK_TEST_IPV6_VPS_SESSION_FILE`, `ARK_IPV6_PROBE_CREDENTIALS`. Staging: `ARK_TEST_IPV6_STAGING_HOSTNAME`, `ARK_TEST_IPV6_STAGING_ADDRESS`, `ARK_TEST_IPV6_STAGING_EMAIL`, `ARK_TEST_IPV6_STAGING_SSH`, `ARK_TEST_IPV6_STAGING_WEBROOT`                                 | Preflight from outside the VPS and HTTP-01 over IPv6 ([Native IPv6 and AAAA publication](#native-ipv6-and-aaaa-publication))   |

Record the redacted output of a live run in the PR or in [`docs/fix1-verification.md`](fix1-verification.md). The Vercel scope proof is the gate for enabling the FD-29 integration.
