# Security review checklist

This checklist records code-backed boundaries, not deployment acceptance. A box means a repository test exercises the rule; it does not certify the Linux daemon, public network, DNS/provider account, certificate authority, or restore repository.

## Privilege boundaries

- [x] Docker socket is not mounted in the API/web containers.
- [x] TypeScript and Go Compose policies default-deny fields and reject external/named platform resources, local-driver bind options, privileged mode, sockets, host namespaces, includes, interpolation, aliases and floating tags.
- [x] Public PgBouncer omits `_owner`, `_migration`, `_backup`, and `_monitor` roles.
- [x] `pgbouncer-public` runs digest-pinned PgBouncer 1.26.1 (at least 1.25.2, which fixes CVE-2026-6664) directly on the generated `pgbouncer.ini`, with no env-driven config generation, all capabilities dropped and read-only mounts.
- [x] The installer seeds PgBouncer with no mappings or admitted users, requiring TLS and SCRAM; the disposable CI smoke test rejects bootstrap console access and verifies authenticated TLS through the host loopback port.
- [x] Tailscale Funnel stays disabled; mode change rewrites edge config and revokes sessions.
- [x] Public PgBouncer requires TLS 1.3, a `verify-full` client certificate from an admitted CA generation and SCRAM. Revocation and rollover retirement close live sessions (`scripts/test-pgbouncer-public.ts`). See B8 below.
- [x] Internal worker routes authenticate bearer identities and reject job kinds outside each typed allowlist.
- [x] Public and tailnet Caddy routes preserve deny-before-fallback ordering for internal and unknown API paths.
- [x] Setup signup is single-use and token-gated.

## Secrets and audit

- [x] Inventory APIs return metadata, not plaintext.
- [x] One-time reveal uses a conditional atomic consume and is scoped to the underlying database or mailbox.
- [x] Audit events are redacted and not deletable through the API.
- [x] Root key stays out of PostgreSQL.

## Front-door trust boundaries (B1–B10)

The boundaries are defined in [`docs/design/front-door.md` §2.3](design/front-door.md#23-threat-model). Each entry gives the controls as built, then the tests that exercise them.

Tests are tagged by kind:

- **[U]** unit test, run by `mise run test`;
- **[DB]** DB-backed test, run by `mise run test:db`;
- **[H: task]** container harness, Docker only;
- **[LIVE: task]** opt-in suite against a real external account ([how to run](operating.md#opt-in-live-test-suites)).

The FD-10, FD-11 and FD-12 DB cases live in `server/src/gate-*.suite.ts`; their `.test.ts` wrappers run each suite in its own process. Playwright specs under `e2e/` run with `mise run test:e2e`, and `e2e/gate.spec.ts` with `mise run test:e2e-gate`.

**Gap** marks a control that no test exercises. A gap is never covered by a nearby test. Gaps are listed again in [Open gaps](#open-gaps).

### B1: Internet ↔ VPS public ports

**Controls:**

- Host nftables `inet ark_host`: default-deny `input`, plus a `forward`-chain check of DNAT'd destination ports. Only the enabled service ports and UDP 41641/41642 are allowed, plus 25/465/587/993 when mail is enabled.
- `inet ark_db_ingress` for 5432 and `inet ark_front` for 80, 443, the SNI ports and 20000–20049: per-source `ct count` and `limit rate`, with IPv6 sources counted per /64.

**Tests:**

- [U] `shared/src/db-ingress.test.ts`: 5432 on both the input and forward hooks ahead of Docker; IPv6 /64 grouping; named drop counters.
- [U] `server/src/front-ingress.test.ts`: the shared `{ 80, 443, … }` budget (`ct count over …`) and removal of closed ports.
- [U] `shared/src/edge-l4-routes.test.ts`: every range port is closed, deny-all, allowlisted or explicitly open to the internet.
- [U] `tests/security/host-firewall.test.ts`: the provider rules match the host inventory.
- [DB] `server/src/db-ingress-settings.test.ts`: limit changes are rendered into `ark_db_ingress`.
- [H: `test:db-ingress`] `scripts/test-db-ingress.ts`: real connections take both hooks, and excess concurrent connections and bursts are dropped.
- [H: `test:host-hardening`] `scripts/test-host-hardening.ts`: `ark_host` installed in a systemd guest; an external nmap shows only the expected ports, and mail ports closed with mail off.
- [H: `test:edge`] `scripts/test-edge-pg5432.ts`: route-only 5432 kernel limits under load.
- [H: `test:edge`] `scripts/test-edge-l4-routes.ts`: raw-port deny-all and closed ports.
- [H: `test:upgrade`] `scripts/test-upgrade-migrations.ts`: startup activation of the 5432 policy.
- [LIVE: `test:host-hardening-live`] `scripts/test-host-hardening-live.ts`: a scratch VPS scan and UDP receipt.

**Gaps:**

- **Code and test gap.** Mail TCP 25/465/587/993 are only accepted (`@public_tcp` in `shared/src/host-firewall.ts`). No per-source `ct count` or `limit rate` is rendered for them, so the design's "every public TCP port" does not hold when mail is enabled.
- The `ark_host` default-deny input and forward-chain drop have no unit assertion. Only the host-hardening harness exercises them.

### B2: Internet ↔ HAProxy (`edge-l4`)

**Controls:**

- A ClientHello or Postgres preamble must arrive within 5 s.
- Unknown SNI never reaches a tailnet target; the scoped router rejects it.
- `maxconn` per frontend and per route.
- Stick-table per-source limits: frontend-wide `sc0` on `fe_tls443` and the SNI ports, and per-route `sc1`/`sc2`.
- `hard-stop-after 30m`.
- Per-route CIDR allowlists.

**Tests:**

- [U] `shared/src/edge-l4.test.ts`:
  - "443 accepts only a TLS ClientHello within 5 s …";
  - the global section asserts `hard-stop-after 30m`;
  - identity-named tailnet servers behind the allowlist and stick table (`maxconn 50`).
- [U] `shared/src/edge-l4-routes.test.ts`: shared SNI ports reject unknown SNI; per-route limits (`track-sc1`/`track-sc2`); empty allowlists deny all.
- [U] `shared/src/edge-pg5432.test.ts`: `SSLRequest`, `GSSENCRequest` and cancel requests go to PgBouncer, direct TLS goes by SNI, everything else is rejected.
- [H: `test:edge`] `scripts/test-edge-l4.ts`: an idle connection is closed within 5 s; a PROXY header on 443 is rejected as non-TLS; unknown SNI is refused before Caddy.
- [H: `test:edge`] `scripts/test-edge-l4-routes.ts`: two TLS routes on 443 with a per-source limit and `maxconn`; shared SNI port 8883; a raw TCP route on 20001 with allowlist, limits, deny-all and `edge.drain`.

**Gaps:**

- **Test gap.** No test covers the frontend-wide `track-sc0` limits (`sc0_conn_cur gt 64 || sc0_conn_rate gt 200`, `shared/src/edge-l4.ts`). Only the per-route `sc1`/`sc2` tables are tested.
- `hard-stop-after` is a string assertion only. No harness observes an old worker being stopped.

### B3: HAProxy ↔ Caddy

**Controls:**

- Caddy's HTTPS listener is loopback-only (`127.0.0.1:8443`) and requires PROXY v2: `proxy_protocol { fallback_policy require }` with no `allow` list.
- HAProxy sends `send-proxy-v2`; headerless loopback TLS fails.
- Public `:80` never parses PROXY.
- The Caddy hop fails fast (`retries 0`, `timeout connect 1s`).

**Tests:**

- [U] `shared/src/edge.test.ts`: the 8443 listener requires a PROXY header and strict SNI; `:80` never parses PROXY; HTTPS sites bind to loopback.
- [U] `shared/src/edge-l4.test.ts`: the Caddy hop has no retries, no redispatch and a short connect timeout.
- [U] `shared/src/edge-l4-routes.test.ts`: `terminate_mtls` loops through abns with PROXY v2.
- [H: `test:edge`] `scripts/test-edge-l4.ts`: live `fallback_policy` is `REQUIRE`; headerless loopback TLS to 8443 is refused; no Docker network reaches 8443; with Caddy's listener down, 443 is reset within 1 s with no retries.

**Gaps:** none found. By design this boundary does not stop a malicious process inside the trusted edge namespace from forging PROXY headers.

### B4: Internet ↔ Caddy (HTTP semantics)

**Controls:**

- Ark's Let's Encrypt TLS; deny-before-fallback routing.
- `strict_sni_host on`, so an SNI/Host mismatch gets 421.
- Header stripping (`X-Ark-*`, forged `X-Forwarded-*`, `Server`, `Via`).
- `Location` rewriting.
- Body and timeout limits.
- Optional per-route rate limits (FD-23): a per-client-address `rate_limit` zone from the pinned `caddy-ratelimit` plugin (v0.1.0, upstream hash checked at build, with limits on client entries and timestamps), ordered before `forward_auth` and the upstream, answering a static 429.
- Optional HTTP mTLS (FD-23): `client_auth` `require_and_verify` against the route's own `http-client` CA only, then a `leaf` allowlist of its unrevoked, unexpired certificates that are not in its CRL. Caddy runs the check from `VerifyConnection` and disables session tickets for client-auth policies, so a resumed session cannot skip it. An unusable CA omits the route. Revocation goes through the gate revocation journal (forced reload and HAProxy session drain, with the 5 s watchdog deadline). It combines with Ark login, and `strict_sni_host` keeps one hostname's connection from reaching another.

**Tests:**

- [U] `shared/src/edge.test.ts`: one `tls` directive per site with automation off; unrouted endpoints get a fixed 503; `strict_sni_host on`.
- [U] `shared/src/edge-http.test.ts`: a proxying route has the no-leak headers, the limits (`max_size 25MB`) and the timeouts; an injection fuzz.
- [U] `shared/src/gate-login.test.ts`: the login site block, including `request_body max_size 64KB`.
- [U] `server/src/client-ip.test.ts`: `X-Forwarded-For` is trusted only with the genuine edge token on exact login paths.
- [DB] `server/src/gate-login.suite.ts`: `X-Forwarded-Host` and `X-Forwarded-Proto` are ignored.
- [H: `test:edge`] `scripts/test-edge-config.ts`: header stripping, `Server`/`Via` removal and Ark certificates on a live Caddy.
- [H: `test:edge`] `scripts/test-edge-l4.ts`: 421 on an SNI/Host mismatch; forged `X-Forwarded-For` and `X-Ark-*` are not passed upstream.
- FD-23 rate limits and HTTP mTLS:
  - [U] `shared/src/edge-http-controls.test.ts`: limit bounds; the zone is site-level, before the gate handlers and `forward_auth`; the 429 hides `Server`; routes without controls render as before; the CA and leaf allowlist; an empty list admits nobody; an invalid limit or CA omits the route.
  - [U] `server/src/modules/route-crl.test.ts`: a CRL-listed, revoked, expired or not-yet-valid certificate is never admitted; a missing or unreadable CRL admits nobody.
  - [U] `shared/src/front-routes.test.ts`: removing or raising a limit, or switching mTLS off, needs a step-up; both fields are HTTP-only.
  - [U] `scripts/edge-test/edge-image.test.ts`: the local `edge-caddy` build and the published amd64 pin match the release bundle in their respective modes. The image build tests the limiter budget and its reclamation.
  - [DB] `server/src/http-route-controls.test.ts`: isolated database coverage for step-up, stale edits, malformed limits, concurrent issuance, queue rollback, in-flight applies, CRL repair, and mTLS lifecycle.
  - [B] `e2e/front-controls.spec.ts`: sparse PATCHes, a stale edit conflict, and a password prompt only for a loosening change.
  - [H: `test:edge`, CI verify] `scripts/test-edge-http-controls.ts`: independent quotas for two clients and two routes through HAProxy, TLS refusals and valid clients, 421 and Ark login, real HTTP revocation with worker drain and watchdog withdrawal, malformed certificates, and CRL repair.

**Gaps:**

- Body-size and timeout limits are checked only as rendered text. No harness sends an oversized body or a slow request and expects 413 or 408.
- **Design limit, untested.** HTTP rate-limit counters live in one Caddy process and reset when the process restarts or the rate policy changes, and IPv6 clients are counted per address rather than per /64. The kernel per-source limits on 443 still group IPv6 per /64.

### B5: Caddy ↔ Ark API (`forward_auth`, login origin)

**Controls:**

- The internal `admin` network.
- An `X-Ark-Edge-Token` header (`ARK_EDGE_GATE_TOKEN`).
- A path allowlist on the login origin.
- The API refuses unregistered `Host` values before Better Auth runs.

**Tests:**

- [U] `shared/src/edge-http.test.ts`: the §3.5 SSO literal with `forward_auth` and `header_up X-Ark-Edge-Token`; public routes never render `forward_auth`.
- [U] `shared/src/gate-login.test.ts`: the login-origin path allowlist.
- [U] `server/src/session-origin.test.ts`: a request for any other host is refused, never mapped to the admin origin.
- [U] `server/src/client-ip.test.ts`: a forged or missing token keys on the peer.
- [U] `tests/security/edge-ts.test.ts`: the `api` service is not on `edge-control`.
- [DB] `server/src/gate-handshake.suite.ts`: `/api/gate/check` without, or with a wrong, edge token is 401; the edge token grants no admin access; a used code, an expired code or another route's hostname fails.
- [DB] `server/src/gate-login.suite.ts`: sign-in with a foreign `Host` is refused before Better Auth; paths outside the allowlist are 404 on the login host.
- [H: `test:edge`] `scripts/test-edge-gate.ts`: `forward_auth`, identity headers, cookie stripping and the raw-URI bypass guard.

**Gaps:** no test sends `/api/gate/check` with a `Host` that is not a registered route. Cross-route replay is covered.

### B6: Edge netns ↔ tailnet

**Controls:**

- Tailscale ACL grants generated per route `host:port`, with `tests`.
- `--shields-up` on `edge-ts`.
- The upstream allowlist (SSRF guard): targets must be peers in the edge node's own netmap.
- StableNodeID pinning, with lease-based withdrawal.

**Tests:**

- ACL grants:
  - [U] `shared/src/tailnet-acl.test.ts`: no Ark tag as `dst`; edge and backup grants never overlap; the tests block rejects broad rules.
  - [DB] `server/src/front-acl.test.ts`: per-route snippets.
  - [U] `tests/security/tailnet-acl-audit.test.ts` and `tests/security/tailnet-acl-script.test.ts`: the policy audit CLI.
- Shields-up:
  - [U] `tests/security/edge-ts.test.ts`: kernel mode with shields up.
  - [U] `scripts/edge-test/shields-up.test.ts`: the harness probe logic.
  - [H: `test:edge`] `scripts/test-edge-config.ts`: `--shields-up` reaches tailscaled's prefs.
- SSRF guard:
  - [U] `shared/src/tailnet.test.ts`: rejected addresses, names absent from the snapshot (DNS is never consulted), and the edge node itself.
  - [U] `shared/src/edge.test.ts`: non-tailnet and reserved targets.
- Pinning:
  - [U] `shared/src/edge-l4.test.ts`: servers are allowed only by exact identity and pin.
  - [U] `server/src/modules/edge-route-input.test.ts`: stable-ID mismatches.
  - [H: `test:edge`] `scripts/test-edge-observer.ts`: identity withdrawal within detection + 5 s.
  - [H: `test:edge`] `scripts/test-edge-l4.ts`: the watchdog handles identity failure across HAProxy workers.
- Real tailnet:
  - [LIVE: `test:edge-tailnet`] `scripts/test-edge-tailnet.ts`: no grant means no reach; shields-up blocks inbound.
  - [LIVE: `test:tailnet-acl`] `scripts/test-tailnet-acl.ts`: Tailscale validates the snippet.
  - [LIVE: `test:backups-tailnet-live`] `scripts/test-backups-tailnet-live.ts`: the edge cannot reach the home backup.

**Gaps:** ACL enforcement and shields-up on a real tailnet are proven only by the opt-in live suites. CI covers rendering, prefs and evaluator logic.

### B7: Gate user ↔ login origin

**Controls:**

- The public login origin (R1) exposes only the sign-in, MFA and gate endpoints.
- Gate sessions are flagged and refused by the admin API.
- Better Auth limits sign-in and two-factor attempts to 5 per minute per client address.

**Tests:**

- [DB] `server/src/gate-login.suite.ts`: a gate session gets 403 on every admin route; Better Auth refuses it on the admin origin; more than 5 failed sign-ins per minute get 429; buckets are kept per client.
- [DB] `server/src/gate-handshake.suite.ts`: the login origin answers 404 for edge handlers; an admin session is not accepted by `authorize`.
- [DB] `server/src/gate-users.suite.ts`: sign-in only on the login origin with forced enrolment; the gate-user API is 404 on the login origin.
- [U] `shared/src/gate-login.test.ts`: enrolment endpoints are on the allowlist.
- [U] `server/src/session-origin.test.ts`: the request host decides the session kind.
- [H: `test:e2e-gate`] `e2e/gate.spec.ts`: the full SSO flow in Chromium.

**Gaps:** the rate limit is tested at the application layer only. The edge-layer per-source limit in front of the login origin (`fe_tls443` `sc0`) is untested (see B2).

### B8: Internet ↔ PgBouncer

**Controls:**

- nftables per-source limits and the HAProxy pooler-wide CIDR policy in `be_pgbouncer`.
- TLS 1.3, a `verify-full` client certificate from an admitted CA generation, and SCRAM.
- Runtime and read-only roles only, with privileged suffixes refused.
- Per-role and per-database limits.
- PgBouncer is reachable only over `pgbouncer-ingress`; the edge namespace never joins `database-management`.
- Revocation, and rollover retirement by `not_after + 5 s`.

**Tests:**

- [U] `shared/src/pgbouncer.test.ts`: `verify-full`, `tlsv1.3` and the admin socket; privileged roles are refused; SCRAM verifiers; revoked clients are excluded.
- [U] `tests/security/pgbouncer-smoke.test.ts`: a TLS 1.2-capable listener fails the assertion.
- [U] `tests/security/pgbouncer-public.test.ts`: only `edge-ts` reaches PgBouncer, over `pgbouncer-ingress`.
- [U] `tests/security/pgbouncer-bootstrap.test.ts`: the closed bootstrap.
- [U] `shared/src/edge-pg5432.test.ts`: `be_pgbouncer` enforces exactly the pooler-wide allowlist.
- [U] `shared/src/pooler-policy.test.ts`: the pooler-wide policy wins over per-database CIDRs.
- [U] `server/src/modules/pgbouncer.test.ts`: only active clients of public databases are admitted; revocation kills only the login role.
- [DB] `server/src/db-clients.test.ts`: issuance, reveal and revocation.
- [DB] `server/src/db-client-rollover.test.ts`: day 90, where N's generation is removed and drained by `not_after + 5 s`.
- [U] `server/src/modules/csr-fuzz.test.ts`, `server/src/modules/csr-openssl.test.ts` and `server/src/modules/x509-csr-malformed.test.ts`: the in-process CSR parser.
- [H: `test:pgbouncer`] `scripts/test-pgbouncer-public.ts`:
  - the V-8 mTLS matrix and TLS 1.2 refusal;
  - the §3.12 node-postgres module;
  - a read-only preview role;
  - revocation with `unknown ca`;
  - FD-28 rollover and retirement.
- [H: `test:edge`] `scripts/test-edge-pg5432.ts`: the pooler-wide policy, the isolation of `app-postgres` from the edge namespace, and the client-certificate lifecycle through 5432.

**Gaps:** none found.

### B9: Operator ↔ admin UI

**Controls:**

- Tailnet mode (`adminMode: "tailnet"`) omits the admin site from the public edge. Public mode serves the admin origin over HTTPS. Both modes enforce the same authentication and authorization below.
- Better Auth with MFA.
- Single-use step-up grants bound to the exact request.
- Owner-only route management (R12).

**Tests:**

- [U] `shared/src/edge.test.ts`: the renderer omits the public admin site in tailnet mode and renders the HTTPS site in public mode.
- [DB] `server/src/coordinator-edge.test.ts`: mode changes require verified edge state and revoke sessions when applied.
- [U] `shared/src/authz.test.ts`: MFA assurance; privileged actions require a recent step-up.
- [DB] `server/src/access.test.ts`: `requireOwner`; grants are consumed once, and replay, mismatch and expiry are rejected.
- [DB] `server/src/front-routes.test.ts`: operators get 403 even with a grant; owners need MFA; loosening needs a grant.
- [DB] `server/src/l4-routes.test.ts`: operators cannot create L4 routes; tightening needs no step-up.
- [U] `shared/src/edge-l4-routes.test.ts`: loosening needs a step-up.
- [DB] `server/src/gate-login.suite.ts`: the login origin is owner-only and needs an `exposure.public` step-up.
- `e2e/gate-users.spec.ts` and `e2e/front-acl.spec.ts`: failed step-ups and non-owner fallbacks in the UI.
- `e2e/vercel-rollover.spec.ts` (CI): the owner credential step-up for the Vercel integration.

**Gaps:** tailnet-only administration is checked only as "no admin site rendered". No harness proves the admin UI is unreachable through public 443.

### B10: Ark ↔ providers

**Controls:**

- A scoped Cloudflare token (Zone:DNS:Edit plus Zone:Read) and a reviewed DNS diff.
- The optional, project-scoped, expiring Vercel token, with connection disabled until the live proof is recorded.
- Write-only or append-only object-storage credentials and a home `rest-server --append-only`.
- R10 keeps Tailscale policy credentials (API keys and OAuth clients) out of Ark. Enrolment uses separate scoped auth keys, and each running Tailscale node retains its own device credentials.

**Tests:**

- Cloudflare:
  - [U] `shared/src/providers.test.ts`: ambiguous Cloudflare edits are refused.
  - [DB] `server/src/front-routes.test.ts`: apex/`www` review is read-only, a stale hash is rejected, and records are published DNS-only.
  - `e2e/dns-review.spec.ts`: withdrawal consent follows the reviewed plan.
- Vercel:
  - [DB] `server/src/db-client-rollover.test.ts`: unproven tokens are refused without writing anything.
  - [U] `server/src/vercel-api.test.ts`: hook receipts cannot prove a wrong deployment.
  - [LIVE] `server/src/vercel-live.test.ts`: scope proof and refusals.
- Object storage:
  - [U] `shared/src/backup-targets.test.ts`: the writer policy deletes only restic locks.
  - [U] `server/src/modules/backup-canary.test.ts`: B2 `deleteFiles` makes a target deletable.
  - [DB] `server/src/backup-observe.test.ts`: a server without `--append-only` is deletable.
  - [U] `tests/security/backup-no-expire.test.ts`: nothing on the VPS runs `pgbackrest expire`.
  - [H: `test:backups`] `scripts/test-backups.ts` and `scripts/backup-test/provider-policies.test.ts`: MinIO and the emulated R2 lock recipe.
  - [LIVE: `test:backups-hosted`] `scripts/test-backups-hosted.ts`.
- Tailscale credential boundaries:
  - [U] `server/src/edge-socket-policy.test.ts`: the API has no tailscaled socket; the watchdog holds no socket, database credential or root key.
  - [U] `tests/security/policy.test.ts`: Funnel stays disabled.

**Gaps:**

- **Test gap, and no code check.** Nothing verifies the Cloudflare token's scope. Ark trusts whatever token it is given.
- **Test gap.** No test asserts that Ark holds no Tailscale API key or OAuth client. Only socket isolation is tested.

### Open gaps

These items need a follow-up ticket. None of them is covered by the tests listed above.

1. B1, code and test: no per-source nftables limits on mail TCP 25/465/587/993.
2. B2 and B7: no test of the frontend-wide HAProxy `sc0` limits on 443 and the SNI ports.
3. B4: no runtime test of the body-size and timeout limits (413/408). HTTP rate-limit counters are per process and per IPv6 address (FD-23).
4. B5: no `/api/gate/check` test with an unregistered route `Host`.
5. B9: no harness proof that tailnet-only administration is unreachable on public 443.
6. B10: Cloudflare token scope is neither checked nor tested.
7. B10: no assertion that no Tailscale API or OAuth credential exists.
8. B1 and B6: the host default-deny chains and real-tailnet enforcement are proven only by the harness and the opt-in live suites.

## Deployment acceptance still required

- [ ] Inspect a permitted workload on an isolated Linux Docker daemon and verify the agent ledger survives restart.
- [ ] Test forged forwarding headers and the final public/tailnet origins through the deployed Caddy/Tailscale paths.
- [ ] Perform an external PgBouncer login over verified TLS and prove real IPv4/IPv6 CIDR denial.
- [ ] Deliver and read mail on disposable Stalwart, then prove alias, suspension, device revocation and relay denial.
- [ ] Complete HTTP-01 issuance/renewal against a disposable public domain.
- [ ] Restore exact database and mail snapshots in fresh isolated volumes and attach assertion results and recovery time.
- [ ] Exercise signed update failure/recovery and an independent off-host heartbeat alert.

Production-facing status must remain waiting, untrusted, paused or unverified until the corresponding observation above exists.
