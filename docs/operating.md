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

**Restarts and upgrades.** `edge` and `edge-l4` join one specific `edge-ts` container. If `edge-ts` is recreated, or restarted in place (by a crash, `docker restart` or `docker compose restart edge-ts`), they keep running in the old, empty namespace and stop serving. Compose only recreates them by itself when the same `docker compose up` also recreates `edge-ts`. `mise run maintain` runs a rejoin step after every applied release, and so does the installer. After any other `edge-ts` restart, run `mise run edge:rejoin`. It repairs only the managed `edge` and `edge-l4` dependents when they are outside their owner's live namespace; optional admin tailnet services are left alone, even if stopped. If `edge-ts` is stopped, it fails with a start-the-owner-first error instead of reporting healthy. `mise run test:edge` checks all three cases.

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

Each run also queues `edge.apply` when a route the lease allows, with an issued certificate that the renderer can serve, is missing from the running Caddy, for example after Caddy started from the closed config during a host restart. A route that stops being servable is withdrawn durably: `edge.apply` re-renders without it, and `edge.drain` removes it from the running Caddy and verifies that the withdrawn route handler no longer dials its target (other authorised hostnames can share the backend). `GET /api/front/tailnet` (owner only) shows the latest generation, its lease, the last observation run, and each route's status, identity state and whether it is being served.

**Watchdog.** `edge-watchdog` is a small first-party container on `control` and `edge-control`, with no database credential, root key or socket. At least every second it reads `GET /api/internal/edge/lease` with `ARK_EDGE_WATCHDOG_TOKEN` (lease reads and event reports only; no operation-worker access) and withdraws each tailnet route handler that the lease does not allow from the running Caddy, through Caddy's admin API. The allowlist holds enabled `ready` routes whose pinned identity matches the current generation while its lease is valid. Native Caddy `vars` metadata binds each handler to its route ID, hostname, stable machine ID and backend. Two hostnames sharing an address remain independently revocable; unmarked legacy tailnet handlers fail closed. So the watchdog withdraws:

- a replaced or removed identity as soon as its generation commits;
- every tailnet route when the lease expires, at most 6 minutes plus 5 seconds after the last completed observation, even with every worker stopped;
- every tailnet route when it cannot read the lease for 5 seconds.

A withdrawal reloads Caddy with that route answering a fixed 503; the rendered `grace_period 5s` bounds in-flight requests. A reload cannot close the route's WebSockets before their 5-minute `stream_close_delay` (FD-09), so whenever the withdrawn handler has a stream-close delay, including when its backend is currently idle, the watchdog then stops Caddy. That closes every connection through Caddy at once. The launch guard restarts it from `Caddyfile.closed` (the file on disk still names the route), and the watchdog's next pass adapts the current full and closed files, verifies the active configuration is exactly that generation's closed file, and restores the full file re-checked against the lease using an atomic ETag guard, so the other routes serve again within seconds without waiting for `edge.apply`. This stop is reported as a withdrawal, not as a failure; the watchdog treats Caddy as restarting, not failed, for up to 60 s after a stop by any adapter (shared marker `tmp/edge/caddy-stopped-at`). Stop intent is persisted before reload in `tmp/edge/caddy-pending-stops/`, so a failed stop is retried even after the removed handler disappears. An unreadable pre-apply configuration aborts the apply. Each reported withdrawal makes the API queue an `edge.apply`, so the rendered files, and the next launch-guard decision, follow the current policy. Before every pass the watchdog reads the lease again, waiting at most 300 ms, so a route that `edge.apply` has just made live is not withdrawn on an older policy, and a slow API never delays expiry. If the active configuration cannot be read (after a bounded five-second initial startup grace), or the reload cannot be applied and verified, the watchdog stops Caddy (`POST /stop`) and raises a critical alert (`Edge watchdog stopped caddy…`). Stale configuration never keeps serving. The watchdog never uses Docker or root. Reports summarise the backend count with a bounded sample (at most 1,000 characters), and failed deliveries are retried on later passes even after withdrawal has converged. Repeated identical failures emit one transition report per proxy while stop attempts continue on every pass.

**Launch guard.** `edge` starts through `infra/platform/edge-launch-guard.sh`, with the official Caddy binary unchanged. The domain worker writes `tmp/edge/Caddyfile` and `tmp/edge/Caddyfile.closed`, which renders no tailnet route. The guard asks the watchdog (`GET http://edge-watchdog:2021/v1/launch`) and starts from `Caddyfile` only if the answer is `open`: every tailnet handler in it matches an allowed route identity and pinned backend under a valid lease. Otherwise, including when the watchdog is unreachable, it starts from `Caddyfile.closed`, so ACME, redirects and the admin site keep working and tailnet routes fail closed. A `Caddyfile` with no tailnet route starts as it is. The same applies when Docker restarts Caddy after the watchdog stopped it. The guard logs its choice (`docker compose logs edge`) and stays alive as Caddy’s supervisor. Once tailnet routes exist in the rendered file or active configuration, it requires a successful `GET /v1/supervise` every second (one-second request timeout). That endpoint answers only after a verified enforcement pass within the last two seconds. After a two-second initial Caddy startup grace, a missing, frozen or unhealthy watchdog causes the supervisor to kill Caddy, closing listeners and existing sessions. Restart still uses the closed variant until the full file is authorised. Closed starts may restart repeatedly while enforcement is unavailable; configurations verified to have no tailnet routes keep serving.

`ARK_EDGE_WATCHDOG_TOKEN` is generated by the installer. Without it, the watchdog cannot read the lease and every tailnet route stays withdrawn. The watchdog enforces HAProxy (`edge-l4`) too, through its master socket; see the next section. `GET /v1/supervise?proxy=caddy` and `?proxy=haproxy` report each proxy separately, so a failed HAProxy withdrawal stops HAProxy and not Caddy.

`mise run test:edge` measures this against the shipped `edge-ts` and `edge` services, using a mocked LocalAPI and a local PostgreSQL (`DATABASE_URL`, as for `mise run test`). It checks that a replaced identity is withdrawn, and its session closed, within detection + 5 s without any `edge.apply`; that with observation stopped the route is withdrawn by last completion + lease + 5 s (the lease is shortened to 8 s for the test); that a restart with an expired lease, or without the watchdog, comes up closed; that shared-backend hostnames are revoked independently (the other hostname serves again after the stream stop, without an `edge.apply`) and a stale launch file stays closed; that stopping or freezing the watchdog while serving closes existing sessions within five seconds; and that a refused reload or unreadable admin config stops Caddy and raises the alert.

## HAProxy SNI router (edge-l4)

`edge-l4` is the official `haproxy:3.2.26-alpine` image (digest-pinned) in the `edge-ts` namespace (docs/design/front-door.md §3.8). It owns public 443 and routes by TLS SNI. HTTP route, admin and login hostnames go to Caddy on `127.0.0.1:8443` with a PROXY v2 header, which carries the real client address (Caddy's `X-Forwarded-For` shows the client, not `127.0.0.1`). Unknown SNI also goes to Caddy, which has no certificate for it and fails the handshake. Anything that is not a TLS ClientHello, including an idle connection, is closed within 5 s. Caddy's HTTPS listener requires the PROXY header and is bound to loopback, so headerless TLS and connections from any Docker network are refused. Caddy's `:80` server never parses PROXY headers. HTTP/3 is off, and no `Alt-Svc` header is sent. An SNI/Host mismatch between two Ark sites answers 421. TLS-TCP routes (FD-14) and the PostgreSQL router on 5432 (FD-26) build on this router later.

**Configuration generations.** The domain worker's `edge.l4_apply` (queued by every `edge.apply`) renders an immutable generation under `tmp/edge-l4/generations/<id>`: `haproxy.cfg`, `haproxy.closed.cfg` (no tailnet backend), allowlists and `manifest.json`. The ID is the SHA-256 of the generation's contents. The restricted `haproxy-validator` container (the same HAProxy digest, with no network and no Docker) re-hashes the generation, refuses symlinks and runs only `haproxy -c` on it. The worker then checks that no byte changed, swaps the `current` symlink atomically and sends `reload` on the master socket. An invalid candidate never changes `current`, and no reload is sent. Any failed or unconfirmed reload restores the previous `current` (or removes it on a first install). A durable `reload-pending` marker forces a retry, including after a timeout or process restart; a symlink alone never proves activation. The validator client allows 25 seconds for the two bounded 10-second config checks. Apply, reload and drain run under one database advisory lock. The operation evidence (`edge-l4-apply`) records the generation, the previous one, whether a reload ran and its log. Generations are kept while an older worker is still draining.

**Maintenance cutover.** Before starting the new edge services, `mise run maintain` stops the domain writer and edge proxies, then runs the approved domain-worker image once as root with CHOWN, FOWNER and DAC_OVERRIDE. The idempotent initializer seeds the missing HAProxy tree, sets uid 1000/group 4400 and modes, and converts both persisted Caddy variants to loopback 8443 with required PROXY headers while retaining their routes and certificates. Services then start from the converted files. This avoids rerunning the host installer during an upgrade.

**Users, group and sockets.** HAProxy and the validator run as the image's uid 99, and the domain worker as `bun` (uid 1000). They share only the supplementary group 4400, as does the edge watchdog. The installer checks the numeric uid and that GID 4400 is free in the pinned images, seeds `tmp/edge-l4` with an initial generation, and (as root on Linux) gives it to uid 1000, group 4400: directories `2750`, files `0640`. The socket directories are tmpfs volumes, `99:4400`, mode `2770`. The master socket (`/var/run/haproxy/master.sock`), the admin socket (`admin.sock`) and the validator socket are `0660`, group 4400. No service has Docker access for this. To inspect from the host:

```sh
docker compose --env-file .env -f infra/platform/docker-compose.yml exec edge-l4 sh -c 'echo "show proc" | socat - UNIX-CONNECT:/var/run/haproxy/master.sock'
docker compose --env-file .env -f infra/platform/docker-compose.yml exec edge-l4 sh -c 'echo "show stat" | socat - UNIX-CONNECT:/var/run/haproxy/admin.sock'
```

**Withdrawal and launch guard.** The watchdog withdraws tailnet backends from HAProxy through the master CLI, admission first. In each worker that still accepts connections, it disables every server that the lease no longer allows, then shuts down that server's sessions. In leaving workers, whose listeners are already closed, it shuts down each affected session. It repeats `show proc` until the worker set is stable, then checks each worker's `show servers state` and `show sess`. A server is allowed only while its name, derived from the route ID, hostname, stable machine ID and pinned address, matches an allowed route. If withdrawal cannot be verified, the watchdog fences tailnet servers and their sessions, preserves unrelated HTTP, and raises the critical alert. Continued unverified enforcement makes the latched launch guard kill the process. `edge.drain` does the same under the edge lock. `edge-l4` starts through `infra/platform/edge-l4-launch-guard.sh`, with the official binary unchanged. A configuration without a tailnet backend starts directly. Otherwise the guard asks `GET /v1/launch?proxy=haproxy` and starts from `haproxy.cfg` only on `open`; when the lease is not valid, or the watchdog is unreachable, it starts from `haproxy.closed.cfg`. It switches to the full configuration (and reloads) once the lease allows it. Once a tailnet backend has existed, supervision stays latched for the life of that master, including after the final route is removed. It needs verified HAProxy enforcement every second, or it kills HAProxy, closing listeners and sessions, and the restart comes up closed. Heartbeat enforcement runs separately from launch polling and reloads, so frozen-watchdog shutdown stays within five seconds. A failed reopen retains closed mode and retries until `Success=1`. Caddy and HAProxy enforcement run independently, so an HAProxy stall does not age Caddy’s heartbeat. The HAProxy stop fallback fences tailnet servers and sessions without closing the public HTTP frontend. The guard logs each decision (`docker compose logs edge-l4`).

`mise run test:edge` (`scripts/test-edge-l4.ts`) runs the shipped `edge-ts`, `edge`, `edge-l4` and `haproxy-validator` services, the bundled watchdog and the domain worker's code as uid 1000 with group 4400 and no capabilities. It covers socket modes, validation, refusal of an invalid candidate, `show stat`, worker enumeration and `Success=1`/`Success=0` reloads with the old worker still serving. It checks PROXY trust (headerless loopback TLS refused, the real address in `X-Forwarded-For`, 8443 unreachable from every Docker network, PROXY ignored on `:80`), the 421, the absence of `Alt-Svc`, every HTTP route through 443, and the 5 s idle close. It keeps a WebSocket open across an HAProxy and a Caddy reload. It shows withdrawal on identity change and on lease expiry, with sessions in both a current and a leaving worker, a closed start with an expired lease, and the switch back. No database or tailnet login is needed. The run takes about 3 minutes, plus a first build of the validator image.

## HTTP routes

Owners publish a tailnet service under a public hostname with `POST /api/front/routes` (docs/design/front-door.md §3.3, FD-08). Every role can list routes (`GET /api/front/routes`, `GET /api/front/routes/:id`) with their status, listener, pinned target, address records and certificate state. Every change is owner-only with MFA; operators and viewers get 403.

| Call                                 | Step-up grant                                                                                                                                                              |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /api/front/routes`             | `exposure.public`, bound to the exact JSON body                                                                                                                            |
| `PATCH /api/front/routes/:id`        | `exposure.public` bound to `{ routeId, ...body }` when it loosens (target, port, re-confirmation, `sso` → `public`, removing a redirect, a sensitive port); none otherwise |
| `POST /api/front/routes/:id/enable`  | `exposure.public`, bound to `{ routeId }`                                                                                                                                  |
| `POST /api/front/routes/:id/disable` | none (tightening); the backend is drained at once                                                                                                                          |
| `DELETE /api/front/routes/:id`       | `resource.delete`, bound to `{ routeId }`                                                                                                                                  |

Preparation validates before using a grant; final validation, consumption and mutation commit together, so a typo or state conflict never burns a password and MFA round. Only `kind: "http"` exists in this release. `accessMode` must be `"public"`: until the login gate ships (FD-11), creating a route with `"sso"` or without a mode (the schema default is `sso`), enabling an `sso` route, or switching a route into `sso` is refused with an "unsupported access mode" error. `redirectTo` (another hostname in the same domain) makes the apex answer with a 308 redirect to, for example, `www` (`https://example.com/x` → `https://www.example.com/x`).

A route hostname must be inside a domain claim whose ownership is verified (otherwise 422); the apex and `www` both work. Creating a route adds an A record for `public_ipv4`, and an AAAA record for `public_ipv6` only when the IPv6 preflight passed (`ipv6_status = passed`) and the domain's AAAA switch is on. Ark only writes A/AAAA, never a CNAME at the apex. Each DNS check reconciles route-owned records against the current addresses and IPv6 gates, removing obsolete AAAA records. On Cloudflare domains explicit `domain.verify` queues the existing `dns.publish`; with other providers create the records shown in the response.

A route then moves through `draft → awaiting_acl → awaiting_dns → issuing_certificate → ready`:

1. `draft`: creation records this audit state, then commits the route, endpoint, address records, audit events and `awaiting_acl` state atomically. The response returns the tailnet ACL snippet; periodic observation recovers the handoff if the immediate enqueue is interrupted.
2. `awaiting_acl`: waiting for the edge-netns TCP probe of the next `edge.observe` (queued at once). Add the snippet's grant to the tailnet policy.
3. `awaiting_dns`: the probe passed; route-only `domain.verify` (queued by every observation) checks that each required address record resolves to this server. `last_error` shows what DNS still returns.
4. `issuing_certificate`: the records resolve; only now is `certificate.issue` queued. A staging or local certificate is never served, so the route waits here with an explanation; a failed issuance is retried with `POST /api/domains/:id/verify`.
5. `ready`: an issued certificate and a fresh passing probe. Only `edge.observe` sets `ready`.

`enable` is refused (409) before `ready`. Changing the target re-pins it and returns the route to `awaiting_acl` (an enabled route stays enabled, is drained at once, and serves the new target only once it is `ready` again); DNS and certificate work is not repeated once the hostname has an issued certificate. Deleting a route drains it and removes its endpoint, certificates and stored address records unless another route still uses the endpoint; records published at a DNS provider are not deleted (FD-19). Every action and lifecycle transition writes a `front_route.*` audit event.

### How the edge serves a route (FD-09)

`edge.apply` reads `front_routes` and renders only enabled `ready` routes whose pinned identity the edge lease still allows; `edge.l4_apply` then adds exactly those hostnames to the HAProxy 443 map. Routes in `awaiting_acl`, `identity_mismatch`, `observation_expired` or `disabled` are in neither config. An enabled `sso` route (possible only through direct database edits before FD-11) is omitted and listed under `omitted` in the `edge-apply` step; it is never served as public. A route whose stored `http_options` fail validation is omitted the same way, instead of failing every apply.

Each served route is a Caddy site on `127.0.0.1:8443` behind the SNI router, with:

- no `Server`, `Via` or `X-Powered-By` on any answer, `X-Content-Type-Options: nosniff`, a referrer policy, and `Strict-Transport-Security: max-age=31536000` (option `hsts`);
- client-sent `X-Ark-*` headers removed and `X-Forwarded-For` set from the real client address (PROXY v2);
- a request body limit (`maxBodyMb`, 25 MB), a 5 s dial timeout and a response-header timeout (`responseHeaderTimeout`, 60 s), no response buffering, and WebSockets kept across reloads for `streamCloseDelay` (5 min);
- `Set-Cookie` `Domain=` attributes removed, so cookies are host-only on the public name;
- `Location` values that point at the target (its tailnet IPv4, IPv6 in compressed, expanded or zero-padded form, MagicDNS or short name, with no port or the target port) rewritten to `https://<public hostname>` with path, query and fragment kept. Any other tailnet address or `.ts.net` name, a malformed or ambiguous authority (userinfo, backslashes, control characters, other IP literals, numeric IPv4 forms) or a special scheme without `//` gets the static 502 instead;
- static 502/503/504 pages from `infra/platform/edge-errors/` (mounted read-only at `/etc/caddy/errors`), which name no internal host.

The edge only controls these headers. Response bodies (HTML, scripts, JSON with absolute URLs), other URL-bearing headers (`Content-Location`, `Refresh`, `Link`), the application's own public-URL setting and the certificates the target presents are passed through unchanged: set the application's public URL to the route hostname and audit what it emits before enabling a route.

Withdrawing a route that has an open WebSocket (identity change, lease expiry, disable, delete or re-target) stops Caddy, because a reload keeps such streams for the 5-minute `stream_close_delay`. The launch guard restarts Caddy within seconds; after a watchdog withdrawal the watchdog reloads the remaining routes at once, and after an `edge.apply` Caddy starts from the new files. Every open connection through the edge, on any route, is dropped at that moment and clients reconnect.

Route mutations compare the prepared row version at commit. A concurrent change returns 409 and preserves the step-up grant. Grant consumption and the route mutation share one transaction. Observer probe results for an older route version are discarded.

Observer-triggered DNS checks touch only route endpoints and ownership proof; they do not publish DNS, provision other services, or retry certificate orders already in progress. Explicit domain verification can retry failed or untrusted issuance and renew a ready route whose certificate is missing, unusable, or expires within 30 days. A ready route that loses its usable certificate returns to the DNS/certificate lifecycle and requires a fresh probe before ready.

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

Upload, integrity, and restore-test are three statuses. File restore tests use an exact successful export and its sealed target credentials. PostgreSQL application restore tests refuse worker-local execution; use the off-VPS recovery tool for database recovery. A successful upload is not a verified restore. Set `ARK_BACKUP_EXECUTE=1` only when pgBackRest or Restic should run. Mail jobs additionally require `ARK_MAIL_SNAPSHOT_READY=1` from a completed native snapshot/quiesce step. Plan-only execution fails the operation instead of reporting success.

PostgreSQL backups run inside each cluster's container (`ark-postgres`, `ark-app-postgres`) into an encrypted local pgBackRest repo2, and leave the VPS as restic snapshots to the S3-compatible targets (FD-21) and the home machine's `rest-server --append-only` over the tailnet (FD-30, through the dedicated `backup-ts` node, `tag:ark-backup`, with its own one-off `TS_BACKUP_AUTHKEY`) configured under **Backups**. "Backups healthy" needs both. A PostgreSQL backup row is `local` until a snapshot containing it reaches a target. The installer generates `ARK_PLATFORM_PG_EXECUTOR_TOKEN`, `ARK_APP_PG_EXECUTOR_TOKEN`, `ARK_PLATFORM_PG_REPO_CIPHER_PASS` and `ARK_APP_PG_REPO_CIPHER_PASS`; without a cipher pass and an executor token of at least 24 characters WAL archiving stays off and backup health says so. Copy both cipher passes and every target's restic password off-host. `pgbackrest expire` is never run on the VPS. Provider recipes, the home-machine setup, the append-only canaries, alerts and the off-VPS restore runbook (`scripts/offsite-restore.ts`) are in [docs/guides/backups.md](guides/backups.md).

## Maintenance

`mise run maintain -- infra/platform/release.json infra/platform/docker-compose.yml` requires an Ed25519 publisher key in `ARK_RELEASE_PUBLIC_KEY`, verifies the bundle signature, exact Compose-file digest, and exact immutable image set, and journals the approval. It pulls every approved digest and executes health-waiting Compose only when `ARK_MAINTENANCE_EXECUTE=1`. It then recreates `edge` if `edge-ts` was restarted or replaced under it (see "Edge Tailscale node"). Stateful images require `allowStateful` after a reviewed migration and recovery plan.

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

`mise run test:db` runs the DB-backed server tests against a throwaway `postgres:17.6` container that it migrates as `ark_migration` and removes on completion or interruption (cleanup failure returns nonzero). `mise run test:db:up` keeps one running and prints shell exports plus the `ark_test_db <file>` helper, which isolates follow-up tests from inherited provider settings (see the README).

`mise run test:e2e` refuses non-loopback PostgreSQL, creates a uniquely named disposable database, migrates it from empty, drives Chromium through owner creation, pre-MFA denial, invalid and valid TOTP, recovery-code acknowledgement, custom domain setup and one-time recovery-code use, then removes the database. The provider/Linux release checks in `security-review.md` remain separate opt-in acceptance work.
