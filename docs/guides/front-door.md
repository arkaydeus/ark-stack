# Front door: public hostnames for tailnet services

The front door publishes services that run anywhere on your Tailscale tailnet under your own public hostnames: `example.com`, `www.example.com`, `db.example.com` and so on. Clients use plain hostnames on standard ports wherever the protocol allows it. Everything else on the tailnet stays reachable only through the tailnet.

This guide describes the system as built. The design and its reasoning are in [`docs/design/front-door.md`](../design/front-door.md), and the operational detail (state machines, watchdog, firewall, upgrades) is in [`docs/operating.md`](../operating.md). Database access from Vercel has its own guide: [`docs/guides/vercel-database.md`](vercel-database.md).

## Contents

1. [What listens where](#1-what-listens-where)
2. [Before you start](#2-before-you-start)
3. [HTTP routes (public or Ark login)](#3-http-routes-public-or-ark-login), with [rate limits and client certificates](#34-rate-limits-and-client-certificates-fd-23)
4. [TLS-TCP routes by SNI](#4-tls-tcp-routes-by-sni)
5. [Raw TCP routes on ports 20000–20049](#5-raw-tcp-routes-on-ports-2000020049)
6. [PostgreSQL: the Ark pooler and Postgres routes](#6-postgresql-the-ark-pooler-and-postgres-routes)
7. [The tailnet ACL snippet](#7-the-tailnet-acl-snippet)
8. [DNS](#8-dns)
9. [Withdrawal, revocation and what to audit](#9-withdrawal-revocation-and-what-to-audit)

## 1. What listens where

All public front-door ports are published by the kernel-mode Tailscale container `edge-ts` (`tag:ark-edge`). HAProxy (`edge-l4`, 3.2 LTS) and Caddy (`edge`, 2.11.9) share its network namespace. The `edge` image is the official Caddy 2.11.9 image with its binary rebuilt to include the pinned `caddy-ratelimit` plugin, for HTTP route rate limits (§3.4).

| Port                               | Owner                          | Routed by                                                                                                                                                                                                                                                           |
| ---------------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TCP 80                             | Caddy                          | ACME HTTP-01 challenges, `308` to HTTPS for known hostnames, `404` otherwise.                                                                                                                                                                                       |
| TCP 443                            | HAProxy `fe_tls443`            | TLS SNI. HTTP route hostnames, `login.<domain>` and a public admin hostname go to their own `be_http_<hostname>` or `be_caddy` backend, then to Caddy on `127.0.0.1:8443` with PROXY v2. TLS-TCP route hostnames go to their route backend. Unknown SNI is refused. |
| TCP 5432                           | HAProxy `fe_pg5432`            | Classic `SSLRequest`, `GSSENCRequest`, `CancelRequest` and direct TLS for the Ark database hostname go to PgBouncer. Direct TLS with a Postgres route's SNI goes to that route. Anything else is rejected.                                                          |
| TCP 20000–20049                    | HAProxy, one frontend per port | Port. One raw-TCP route (or one Postgres compatibility port) per port. A port with no enabled route has no listener and is dropped by nftables.                                                                                                                     |
| Optional TCP 8883, 5671, 636, 6380 | HAProxy                        | SNI, like 443. Enabled at install time with `ARK_EDGE_SNI_PORTS`.                                                                                                                                                                                                   |
| UDP 41642 / 41641                  | `edge-ts` / host tailscaled    | WireGuard direct paths.                                                                                                                                                                                                                                             |

Mail keeps 25, 465, 587 and 993 when it is enabled. The front door never claims them. A connection that sends no TLS ClientHello or Postgres preamble within 5 s is closed.

Which protocol goes where (`PROTOCOL_GUIDANCE` in `shared/src/front-routes.ts`, also shown in the UI):

| Protocol                                          | Route kind                                  | Public listener                       |
| ------------------------------------------------- | ------------------------------------------- | ------------------------------------- |
| HTTPS, WebSocket over TLS                         | `http`                                      | 443                                   |
| PostgreSQL with `sslnegotiation=direct`           | `postgres`                                  | 5432                                  |
| PostgreSQL classic (`SSLRequest`)                 | Ark pooler, or a route's compatibility port | 5432 (PgBouncer) / 20000–20049        |
| MQTT over TLS, AMQPS, LDAPS, Redis/Valkey TLS     | `tls`                                       | 443 or the protocol's shared SNI port |
| MongoDB TLS (standalone, `directConnection=true`) | `tls`                                       | 443                                   |
| NATS (`handshake_first` only)                     | `tls`                                       | 443                                   |
| MySQL/MariaDB, SSH, RDP, games, raw MQTT          | `tcp`                                       | 20000–20049                           |
| SMTP/IMAP with STARTTLS                           | not offered                                 | n/a                                   |

## 2. Before you start

1. **Enrol the edge node.** Follow [Edge Tailscale node](../operating.md#edge-tailscale-node). In short: declare `tag:ark-edge` in `tagOwners` with no grants, set a one-off, pre-approved, 1-day `TS_EDGE_AUTHKEY`, start `edge-ts` and `edge`, run `mise run edge:rejoin`, then clear the key in `.env` and revoke it.
2. **Verify a domain** in the domain wizard. A route hostname must be inside a domain claim whose ownership TXT is verified. The apex and any subdomain work. Names under `ts.net` are refused.
3. **Set the public addresses** (`public_ipv4`, and optionally `public_ipv6`) in the wizard.
4. **Enable public certificates.** Set `ARK_ACME_EMAIL` and `ARK_ACME_STAGING=0` ([Public certificates](../operating.md#public-certificates)). A route never becomes `ready` with a staging certificate.
5. **For Ark-login routes,** enable the login origin first (§3.2).

Route management is **owner-only** with MFA (decision R12). Every loosening change needs a single-use step-up grant (`POST /api/step-up` with your password) bound to the exact request. The **Front door routes** page in the UI does all of this. The API is shown here because it states the exact contract.

## 3. HTTP routes (public or Ark login)

### 3.1 Create a route

```http
POST /api/front/routes            (step-up: exposure.public, bound to the exact JSON body)
{
  "kind": "http",
  "hostname": "www.example.com",
  "target": "home",               // the machine's MagicDNS name or Tailscale IP, as the edge node sees it
  "targetPort": 3000,
  "accessMode": "sso"             // default; "public" for no login
}
```

The target must be a peer in the edge node's own netmap. Ark pins its Tailscale **StableNodeID** and address. DNS is never consulted, and the edge node itself, non-tailnet addresses and reserved ranges are refused. Sensitive target ports (22, 2019, 2375, 2376, 3389 and 5900: `SENSITIVE_TARGET_PORTS` in `shared/src/tailnet.ts`) need `allowSensitivePort: true`.

The route then moves through `draft → awaiting_acl → awaiting_dns → issuing_certificate → ready`:

1. `awaiting_acl`: add the route's grant from the ACL snippet (§7) to your tailnet policy. The next `edge.observe` (every 5 minutes, or `POST /api/front/tailnet/observe`) probes the exact `host:port` from the edge namespace.
2. `awaiting_dns`: publish the A (and gated AAAA) records (§8).
3. `issuing_certificate`: Let's Encrypt HTTP-01 through Caddy's `:80`.
4. `ready`: a passing probe and an issued certificate.

Then **enable** the route (`POST /api/front/routes/:id/enable`, with `exposure.public` bound to `{ routeId }`). `GET /api/front/routes/:id` shows the status and the reason it is waiting.

**Apex and `www`.** Create both hostnames as routes. To serve one canonical name, give the apex `"redirectTo": "www.example.com"`: it then answers `308` to `https://www.example.com/<path>`. Ark only ever writes A and AAAA records, so the apex needs no CNAME flattening.

### 3.2 Ark login (SSO) routes

`accessMode: "sso"` (the default) admits only users on the route's access list who have signed in at the **login origin** with password and TOTP.

1. **Enable the login origin** with `PUT /api/settings/gate` and `{ "mode": "public", "hostname": "login.example.com" }`. This needs owner, MFA and an `exposure.public` step-up, a verified domain and an HTTPS `BETTER_AUTH_URL`. Ark creates the address records, verifies DNS, issues the certificate and serves a login site that exposes only the sign-in, MFA and gate endpoints. Gate sessions are refused by the admin API.
2. **Create gate users** under **Gate users**, or with `POST /api/gate/users` and `{ "email", "name"? }`. This needs a `role.grant` step-up bound to `{ ...body, gateUsers: "create" }`. Reveal the temporary password once with `POST /api/gate/users/:id/temporary-password` (`secret.reveal`). The user must enrol TOTP on first sign-in.
3. **Grant access per route** with `PUT /api/front/routes/:id/access` and `{ "userIds": [...] }` (`role.grant` bound to `{ routeId, userIds }`). Access lists hold individual users only.

A browser without a route session is redirected to `https://login.example.com/gate/authorize` and comes back through `https://www.example.com/.ark/gate/callback` with a host-only `__Host-ark_gate` cookie for that route. The upstream receives `X-Ark-User` and `X-Ark-Email`. Caddy strips the Ark gate cookie and forwards application cookies. Non-HTML requests get `401` with `WWW-Authenticate: Ark-Gate`.

Options for `sso` routes:

- **`bypassPaths`**, for example `["/webhooks/*"]`, skip the session check. Webhook handlers must authenticate their callers themselves. A raw-URI guard still applies.
- **`allowedOrigins`** approve cross-origin WebSockets and unsafe methods from another `https://host[:port]`.

Both loosen exposure and need `exposure.public`. The full contract is in [Login gate for SSO routes](../operating.md#login-gate-for-sso-routes-fd-11).

### 3.3 What the edge does for every HTTP route

- TLS with Ark's own Let's Encrypt certificate. `strict_sni_host` is on, so an SNI/Host mismatch returns `421`.
- Client `X-Ark-*` headers are removed, and `X-Forwarded-For` is set from the PROXY v2 address.
- No `Server`, `Via` or `X-Powered-By`; HSTS; `Set-Cookie Domain=` stripped.
- `Location` headers that point at the tailnet target are rewritten, or refused with a static `502`.
- Limits: a 25 MB body, a 5 s dial timeout and a 60 s response-header timeout.

Response bodies and other URL-bearing headers pass through unchanged. **Set the application's public URL to the route hostname, and check what the application emits before enabling the route.** Route targets must still authenticate anything sensitive: the gate is a perimeter, not a substitute.

### 3.4 Rate limits and client certificates (FD-23)

Two optional controls apply to any HTTP route, `public` or `sso`. A route that uses neither is rendered exactly as before.

**Rate limit.** `rateLimit` admits at most `requests` requests per sliding `window` from one client address. The address is the real source that HAProxy passes to Caddy with PROXY v2.

```http
PATCH /api/front/routes/:id
{ "rateLimit": { "requests": 60, "window": "1m" } }      // null removes the limit
```

- `requests` is an integer from 1 to 1000. `window` is a duration from `1s` to `1h`, such as `10s`, `1m` or `1h`.
- Requests over the limit get `429` with `Retry-After` and a static body that has no `Server` header. Caddy counts and refuses them before the login gate's `forward_auth`, before the gate's own handlers and before the upstream, so a refused request never reaches the API or the target.
- Each route has its own quota for a client address. When its limiter capacity or the shared process capacity is full, new client addresses get 429 until expired entries are swept. Existing entries retain their quotas.
- Counters live in the running Caddy process. A restart or a changed rate policy starts that history again. IPv6 clients are counted per address, not per /64. The kernel per-source limits in front of 443 (`inet ark_front`) still apply, per /64.
- Adding a limit or replacing it with a stricter policy needs no step-up. Removing a limit or allowing more requests in any window of the old duration requires `exposure.public` bound to `{ routeId, ...body }`. Stored limits outside the supported bounds close the route. Explicitly replacing or clearing one also requires the grant.

**Client certificates (HTTP mTLS).** `"mtls": true` (on create or update) gives the route its own client CA (`client_ca_id`, purpose `http-client`) and requires a certificate from it in the TLS handshake:

```http
PATCH /api/front/routes/:id
{ "mtls": true }
POST /api/front/routes/:id/client-certificates      (step-up: credential.rotate, bound to { routeId, ...body })
{ "name": "laptop-alice" }                          // or with "csrPem" for your own key
POST /api/front/routes/:id/client-certificates/:certificateId/revoke
```

- Without a certificate, or with one that the route CA did not issue, the handshake fails with a TLS alert (`certificate required`, `unknown ca` or `bad certificate`). No HTTP response is sent at all.
- Caddy has no CRL support. The edge therefore admits exactly the route CA's certificates that are unrevoked, unexpired and absent from its CRL. Issuing a certificate re-renders the edge, so a new certificate works within seconds.
- Revoking regenerates the CRL and goes through the gate revocation journal. The forced reload drops the certificate, and the route's HAProxy sessions, WebSockets included, are drained around it. If the revocation stays pending for more than 5 s, the watchdog withdraws the route. Other certificates work again after the queued apply restores the route under the verified journal revision.
- Generated keys are revealed once with `POST /api/secrets/:id/reveal` (`secret.reveal`). Certificates last 90 days. Reissue, then revoke the old one.
- `mtls` combines with either access mode. With `sso`, a request needs both a certificate and a gate session: the certificate is checked first, in the handshake, and then `forward_auth` applies. The login origin itself never asks for a certificate, so sign-in works from any browser that holds one. Bypass paths skip only the session check, never the certificate.
- `strict_sni_host` still applies: a connection opened for another hostname cannot reach the mTLS route by `Host`, and gets `421`. Caddy turns TLS session tickets off for client-certificate sites and re-checks the certificate on every resumed session.
- Switching `mtls` on is a tightening: connections admitted without a certificate are drained. Switching it off loosens exposure and needs `exposure.public`. It also retires the route CA, so every certificate it issued stops working, including if `mtls` is switched on again later.

The **Controls** and **Certificates** buttons on the Front door routes page do the same with the step-ups.

## 4. TLS-TCP routes by SNI

```http
POST /api/front/routes            (step-up: exposure.public, bound to the body)
{
  "kind": "tls",
  "hostname": "mqtt.example.com",
  "listenPort": 8883,             // 443, or an enabled shared SNI port
  "target": "nas", "targetPort": 1883,           // plaintext MQTT: the edge terminates TLS
  "tlsMode": "terminate_mtls",
  "sourceCidrs": ["203.0.113.0/24"],
  "limits": { "maxConn": 50, "perSourceConn": 10, "perSourceRate": 20 }
}
```

| `tlsMode`        | Meaning                                                                                                                                                                                                     |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `passthrough`    | HAProxy routes the encrypted stream by SNI. The target presents its own certificate for the public name.                                                                                                    |
| `terminate`      | HAProxy terminates TLS with the hostname's Let's Encrypt certificate and forwards plaintext over WireGuard. Needs a restricted, non-empty `sourceCidrs`.                                                    |
| `terminate_mtls` | As `terminate`, and the client must present a certificate from the route's own CA, checked against its CRL. Issue certificates with `POST /api/front/routes/:id/client-certificates` (`credential.rotate`). |

**Admission.** Every L4 route has its own allowlist and limits. The defaults are `maxConn` 50, `perSourceConn` 10 and `perSourceRate` 20 per 10 s for `tls`, and 20/5/10 for `tcp`. HAProxy applies them before TLS termination, so the real source address counts. An empty `sourceCidrs` with `allowInternet: false` denies everyone and prevents enabling the route. To admit the internet in an eligible mode, submit an empty list and `allowInternet: true` with owner step-up. Supplied CIDRs must always be /8 or narrower for IPv4 and /16 or narrower for IPv6. Raw TCP also requires confirmation of protocol authentication for internet-wide admission, and TLS `terminate` without mTLS always needs a restricted list.

**Shared SNI ports** (8883, 5671, 636, 6380) are opt-in at install time: set `ARK_EDGE_SNI_PORTS`, run `mise run host:install`, then `mise run edge:rejoin`. See [TLS-TCP and raw-TCP routes](../operating.md#tls-tcp-and-raw-tcp-routes).

## 5. Raw TCP routes on ports 20000–20049

Protocols without TLS-first get a dedicated port:

```json
{
  "kind": "tcp",
  "hostname": "ssh-box.example.com",
  "listenPort": 20001,
  "target": "box",
  "targetPort": 22,
  "allowSensitivePort": true,
  "tlsMode": "plain",
  "allowPlaintext": true,
  "sourceCidrs": ["198.51.100.7/32"]
}
```

`listenPort` must be in 20000–20049. Platform and mail ports are refused. The host's `inet ark_front` nftables table applies the per-port CIDR list and per-source limits. HAProxy applies `maxconn` and timeouts. Opening a `plain` route to the whole internet also needs `protocolAuthConfirmed: true`, which means the protocol authenticates its own users. Clients connect to `ssh-box.example.com:20001`.

## 6. PostgreSQL: the Ark pooler and Postgres routes

Port 5432 carries two things:

- **Ark-managed databases through PgBouncer.** These are protected by mTLS client certificates, SCRAM and least-privilege roles. Use this for Vercel and other apps: [vercel-database.md](vercel-database.md).
- **Postgres routes** to a PostgreSQL on your tailnet, selected by SNI with **direct TLS**.

### 6.1 Pooler-wide CIDR policy

Classic `SSLRequest` negotiation carries no database name, so one source policy applies to PgBouncer for **every** public Ark database. HAProxy enforces it in `be_pgbouncer`. Each database's `sourceCidrs`, and each legacy Vercel client, is a **request** shown under **Public database port (5432)** and by `GET /api/databases/pooler-policy`.

When the requests differ, PgBouncer is not routed until an owner reviews and saves one common policy:

```http
PUT /api/databases/pooler-policy      (MFA, step-up: exposure.public bound to the exact body)
{ "sourceCidrs": ["203.0.113.0/24"], "allowInternet": false, "reviewedRequests": "<requestsFingerprint from GET>" }
```

- An empty list denies every source. Only `allowInternet: true` opens the pooler to everyone, which Vercel needs.
- A source admitted for one database is admitted for all of them. To isolate a database, keep it private or serve it through a Postgres route.
- Narrowing applies to new connections. Revoke a database client to cut its live sessions.

Per-source nftables limits on 5432 apply whatever the policy says: 128 concurrent and 30/s with a burst of 60, per IPv4 address or IPv6 /64, set with `PUT /api/settings/db-ingress`.

### 6.2 Postgres routes

```json
{
  "kind": "postgres",
  "hostname": "pg-home.example.com",
  "target": "pg-home",
  "targetPort": 5432,
  "tlsMode": "passthrough",
  "sourceCidrs": ["198.51.100.0/24"]
}
```

- **`passthrough`**, for PostgreSQL ≥ 17. The target terminates TLS itself. Use `hostssl … scram-sha-256 clientcert=verify-full` with `ssl_ca_file` set to an Ark route CA and `ssl_crl_file` to its CRL.
- **`terminate` or `terminate_mtls`**, for older servers. HAProxy terminates TLS with ALPN `postgresql` and forwards plaintext over WireGuard. Give the target a `host` (not `hostssl`) line for the edge node's Tailscale IP only.
- On every target, reject superusers remotely and connect with a least-privilege role. The UI shows the full checklist (`POSTGRES_TARGET_CHECKLIST`).

**Direct TLS by driver.** Clients must use `sslnegotiation=direct`. Classic `SSLRequest` connections to a route hostname land on PgBouncer and fail on the certificate name.

| Client                                  | Option                                                                     | Since              | Verified by `mise run test:edge` |
| --------------------------------------- | -------------------------------------------------------------------------- | ------------------ | -------------------------------- |
| libpq (psql, psycopg, pgAdmin, Postico) | `sslnegotiation=direct`                                                    | libpq 17           | yes                              |
| node-postgres (`pg`)                    | `sslnegotiation: "direct"`                                                 | 8.22.0             | yes                              |
| postgres.js                             | `sslnegotiation: "direct"` (not on Cloudflare Workers)                     | 4.1.1              | yes                              |
| pgJDBC, Npgsql, pgx                     | `sslNegotiation=direct`, `SSL Negotiation=Direct`, `sslnegotiation=direct` | 42.7.4, 9.0, 5.7.5 | no                               |

psql:

```bash
psql "host=pg-home.example.com port=5432 dbname=app user=app_rw \
      sslmode=verify-full sslnegotiation=direct \
      sslcert=client.crt sslkey=client.key"      # sslcert/sslkey only for terminate_mtls or clientcert targets
```

node-postgres:

```ts
import { Client } from "pg";
const client = new Client({
  host: "pg-home.example.com",
  port: 5432,
  database: "app",
  user: "app_rw",
  password: process.env.PGPASSWORD,
  sslnegotiation: "direct",
  ssl: { rejectUnauthorized: true, servername: "pg-home.example.com" /*, cert, key */ },
});
```

postgres.js:

```ts
import postgres from "postgres";
const sql = postgres({
  host: "pg-home.example.com",
  port: 5432,
  database: "app",
  username: "app_rw",
  password: process.env.PGPASSWORD,
  sslnegotiation: "direct",
  ssl: { rejectUnauthorized: true, servername: "pg-home.example.com" /*, cert, key */ },
});
```

`sslmode=verify-full` (or `require`) is mandatory: libpq refuses direct negotiation with `sslmode=prefer`, so a client cannot be downgraded to plaintext.

**Compatibility port.** A `passthrough` route can set `compatPort` (20000–20049) for drivers without direct TLS. The target then answers `SSLRequest` itself, under the route's allowlist and limits. On that dedicated port, raw TCP, including separate plaintext `CancelRequest` connections, is forwarded to the target. On the shared port 5432, HAProxy sends plaintext `CancelRequest` to PgBouncer, so cancellation for a named Postgres route on 5432 needs the driver to use direct TLS with the route’s SNI for the cancellation connection.

## 7. The tailnet ACL snippet

Ark holds **no Tailscale credential that can write policy** (decision R10). It generates a snippet that you merge by hand:

- **Front door ACL** in the UI;
- `GET /api/front/acl` for all routes and the home backup target;
- `GET /api/front/routes/:id/acl` for one route.

The snippet declares the four Ark tags. It has one host alias per target machine and one grant per target `host:port`: `tag:ark-edge` for routes, `tag:ark-backup` for the home backup target. The `tests` block contains sampled assertions against common and configured ports, observed non-target nodes and other Ark tags. Tailscale rejects the policy when those assertions fail. Access outside the sample can still pass native validation.

```jsonc
{
  "tagOwners": { "tag:ark-edge": ["autogroup:admin"], "tag:ark-backup": ["autogroup:admin"], … },
  "hosts": { "ark-rt-home": "100.101.102.103" },
  "grants": [{ "src": ["tag:ark-edge"], "dst": ["ark-rt-home"], "ip": ["tcp:3000"] }],
  "tests": [{ "src": "tag:ark-edge", "accept": ["ark-rt-home:3000"], "deny": ["ark-rt-home:22", …] }]
}
```

- Never give `tag:ark-edge` a grant that the snippet did not generate. Never give any Ark tag a destination grant other than the documented admin and SSH grants.
- Remove or narrow catch-all rules (the default `"src": ["*"], "dst": ["*"]`) before pasting.
- For an offline comparison across TCP and UDP port ranges, run `bun scripts/audit-tailnet-policy.ts global-snippet.hujson candidate-policy.hujson`. It checks known destinations against a fresh global snippet and rejects unsupported policy constructs. Review the full policy too. See the [audit scope](../operating.md#tailnet-policy-snippet).
- The page also recommends **Tailnet Lock** and shows an optional `tag:ark-vps` Tailscale SSH policy in `check` mode.

Details: [Tailnet policy snippet](../operating.md#tailnet-policy-snippet).

## 8. DNS

Ark writes only **A** and **AAAA** records, DNS-only, for every route hostname, the login host and the database endpoint. That includes the plain apex and `www`.

- **A** is always the configured `public_ipv4`.
- **AAAA** is published only when the IPv6 preflight has passed and the domain's AAAA switch is on.

### 8.1 Cloudflare (automatic, reviewed)

With a Cloudflare token scoped to **Zone / DNS / Edit** and **Zone / Zone / Read** for the zone (held only by the domain worker), Ark computes a diff and publishes it only after you review it.

1. Open **Review DNS** on the Domains screen, or **DNS** beside a route. The API is `GET /api/domains/:id/dns` or `GET /api/front/routes/:id/dns`. The review lists `keep`, `update`, `create` and `delete` actions and any blockers, such as a conflicting MX record, which you resolve at Cloudflare.
2. Select **Publish reviewed DNS**, or `POST /api/domains/:id/publish` with the review's `planHash` and an optional UUID `requestId`. The response is `202` with an `operationId`. Follow it at `GET /api/domains/:id/publish/:operationId`, which returns `409` on a terminal conflict.

Records are always `proxied: false`. Ark refuses ambiguous same-name edits. It deletes only records it owns, after checking their exact prior value. Publishing queues `domain.verify`, which checks public DNS before any certificate is requested.

### 8.2 Namecheap and other providers (manual)

Ark shows the exact rows to create and remove, and a provider guide. Opening the guide or selecting **Recheck DNS** starts a 30-minute window of automatic checks, every two minutes.

| Type                                   | Host       | Value          | TTL                |
| -------------------------------------- | ---------- | -------------- | ------------------ |
| A                                      | `@` (apex) | `203.0.113.10` | 300 or "Automatic" |
| A                                      | `www`      | `203.0.113.10` | 300                |
| AAAA (only after the preflight passes) | `@`, `www` | `2001:db8::10` | 300                |

- **Namecheap.** Go to Domain List → **Manage** → **Advanced DNS** → Host Records → **Add New Record** → `A Record`, Host `www` (or `@`), Value the IP, TTL Automatic. Repeat with `AAAA Record` for IPv6. This works only when the domain uses Namecheap BasicDNS, PremiumDNS or FreeDNS. Ark has no Namecheap API automation.
- **Any other provider:**
  - Find the authoritative host with `dig NS example.com +short`.
  - Create the records exactly as shown, and remove conflicting A, AAAA or CNAME records on the same name.
  - Turn off any proxy, CDN or forwarding for the name.
  - Check that no CAA record excludes Let's Encrypt.
  - Wait for the TTL, then verify with `dig A www.example.com @1.1.1.1 +short` (and `dig AAAA …`).
- Rows marked **Remove at provider** stay pending until a public lookup confirms they are gone.

`domain.verify` blocks certificate requests when:

- a CAA record excludes Let's Encrypt HTTP-01;
- an address resolves inside Cloudflare's proxy ranges ("switch to DNS only");
- an unexpected or stale AAAA record is present. Let's Encrypt tries IPv6 first, so a wrong AAAA fails issuance instead of falling back.

### 8.3 IPv6 and the AAAA preflight

AAAA is published by default, but only after a preflight passes (decision R9). The preflight requires all of these:

- a global IPv6 address on the host;
- Docker native IPv6 with `userland-proxy` off, so client addresses survive;
- every public port answering over IPv6 **from outside the VPS**, with the edge log matching the probe's source.

To run it:

1. Bring up HTTPS over IPv4 first.
2. Run the preflight on demand with `POST /api/settings/ipv6/preflight` (owner, MFA). It also runs weekly, and whenever the address or the edge changes.
3. Read the result with `GET /api/settings/ipv6/preflight?operationId=<id>`.

The external probe is `scripts/ipv6-preflight-probe.ts`. It runs either as a managed runner next to the off-host heartbeat (`ARK_OFFHOST_HEARTBEAT_URL`), or manually with a one-time signed request. See [Native IPv6 and AAAA publication](../operating.md#native-ipv6-and-aaaa-publication).

- A failure withdraws AAAA records through the same reviewed provider flow. Cloudflare deletes them automatically only if you authorised withdrawal in a reviewed publish. Manual providers show the rows to remove.
- **Per-domain switch:** `PUT /api/domains/:id/aaaa` with `{ "enabled": false }` turns AAAA off. Turning it back on needs an `exposure.public` step-up bound to `{ domainId, enabled: true }`.

## 9. Withdrawal, revocation and what to audit

Disabling, deleting or re-targeting a route, a failed identity check or an expired observation lease all withdraw the route. Revoking an HTTP route's client certificate drains that route's sessions in the same way (§3.4). HAProxy fences its dedicated backend and closes its sessions, including in workers that are still draining after a reload. Caddy answers `503` for it. Unrelated routes keep serving. The watchdog checks the lease every second by default. The withdrawal budget is five seconds, including closure of existing sessions. The watchdog stops Caddy as a fallback when it cannot verify scoped control. Revoking a gate user's access drains the affected route within 5 s, or the watchdog withdraws it.

Runbooks for revoking routes, gate users and database clients are in [Revocation](../operating.md#revocation). The security boundaries and the tests that cover them are in [`docs/security-review.md`](../security-review.md).
