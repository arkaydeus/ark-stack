# HTTP API

This page is the reference for the Ark HTTP API served by the `api` container: who may call it and how they authenticate, the conventions every endpoint follows, and the complete list of routes registered in [`server/src/app.ts`](../../server/src/app.ts), grouped by area.

The admin UI in `web/` is a client of this same API; there is no separate private interface. Anything the UI does, it does through the routes below.

## Overview

The API is a [Hono](https://hono.dev) application. It listens on `ARK_LISTEN_PORT` (or `PORT`, default 3000) and, when the built UI (web/dist) exists, also serves the built admin UI as static files with an `index.html` fallback for client-side routes.

Every request first passes a host guard. The canonical `Host` must be a registered admin host or the login host (`server/src/origin-hosts.ts`):

- On a registered admin host, every route below is reachable, subject to its own authentication.
- On the login host (the public gate login origin), only the Better Auth sign-in, sign-out, session and two-factor paths listed in `shared/src/gate-login.ts` and the `/gate/*` pages exist. Every other path, including `/api/health` and `/api/internal/*`, answers 404.
- On any other host, the API answers 421 `This host is not a registered Ark origin.`, except for host-independent paths that carry their own credentials or need none: `/api/internal/*`, the four gate edge handlers, `/api/health`, `/api/metrics/prometheus` and `/.well-known/acme-challenge/*`. Docker peers reach those by service name (`api:3000`).

Request bodies under `/api/*` are limited to 256 KiB.

## Authentication

### Caller types

| Caller                      | Credential                                                     | Reaches                                                             |
| --------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------- |
| Administrator (browser)     | Better Auth session cookie minted on an admin origin           | All admin routes, according to role, scope, MFA and step-up         |
| Gate user (browser)         | Better Auth session cookie minted on the login origin          | The login origin only: `/api/auth/*` allowlist and `/gate/*` pages  |
| Module workers              | `Authorization: Bearer <token>` (per-worker or internal token) | `/api/internal/*` except `/api/internal/edge/*`                     |
| Docker agent                | `Authorization: Bearer` `ARK_AGENT_TOKEN`                      | `/api/internal/*` except `/api/internal/edge/*`                     |
| Edge lease watchdog         | `Authorization: Bearer` `ARK_EDGE_WATCHDOG_TOKEN`              | `/api/internal/edge/*` only                                         |
| Edge (Caddy `forward_auth`) | `X-Ark-Edge-Token` equal to `ARK_EDGE_GATE_TOKEN`              | The four `/api/gate/*` edge handlers                                |
| Prometheus                  | `Authorization: Bearer` `ARK_METRICS_TOKEN`                    | `GET /api/metrics/prometheus`                                       |
| Off-host IPv6 probe         | A one-time signature over its report                           | The IPv6 preflight result callback                                  |
| Anyone                      | None                                                           | `GET /api/health`, `GET /api/setup/status`, ACME HTTP-01 challenges |

All token comparisons use a constant-time comparison (`secureEqual`).

### Administrator sessions

Sign-in, sign-out, session lookup and two-factor management are Better Auth endpoints under `/api/auth/*`, configured in `server/src/auth.ts`. Ark passes every `/api/auth/*` request to Better Auth after normalising its headers: the `Host` is replaced with the canonical registered host, the trusted client address is written to `X-Ark-Client-Ip` (any client-sent value is removed), the edge token is stripped, and a `Cookie` header that names any Better Auth cookie twice is refused with 400.

Better Auth is configured with email and password (minimum 12 characters) and the TOTP two-factor plugin (issuer `Ark Stack`). Its rate limiter allows 60 requests per 60 seconds per client by default, and 5 per 60 seconds on `/sign-in/email` and `/two-factor/*`.

Each session records the origin that minted it (`admin` or `gate`), set server-side. The admin API accepts only an `admin` session presented on an admin origin; a gate session gets 403 `This session cannot use the administration API.` on every admin route. Gate users can never obtain an admin-origin session.

The first administrator is created through `POST /api/auth/sign-up/email` with the `X-Setup-Token` header equal to `ARK_SETUP_TOKEN`. Ark wraps that one Better Auth endpoint: it takes an advisory lock, refuses with 403 once setup is complete or when the token does not match, and on success grants the new user the `owner` role and closes bootstrap. `GET /api/setup/status` reports whether this step (and then the first-run wizard) is still required. See [First run](../getting-started/first-run.md).

### Roles and scope

After the session check, the API loads the caller's `platform_access` row. An account with no row (a gate-only user) has no administration access at all and gets 403. Otherwise the role is one of:

| Role       | Meaning                                                                                                                   |
| ---------- | ------------------------------------------------------------------------------------------------------------------------- |
| `owner`    | Sees and manages everything. Exposure decisions (front-door routes, gate users, backup targets, settings) are owner-only. |
| `operator` | May mutate resources inside the projects and domains granted to it.                                                       |
| `viewer`   | Read-only inside granted projects and domains.                                                                            |

Project and domain grants (`projectIds`, `domainIds`) scope what non-owners see and change. Creating a project or domain grants it to its creator. In the tables below, "Operator" means owner or operator, and "scoped" means the route also checks that the target domain, project or database is granted to the caller (`server/src/access.ts`).

### MFA assurance

Most mutations call `requireMfa`. It passes only when the account has two-factor enabled, has an MFA enrolment timestamp, and the current session was created at or after that enrolment. A session that predates enrolment must sign in again. The refusal is 403 `Enroll and verify administrator MFA before making changes.`

### Step-up grants

Privileged actions need a single-use step-up grant in addition to a session with MFA assurance. The actions are defined in `shared/src/authz.ts`:

| Action              | Used for                                                                                           |
| ------------------- | -------------------------------------------------------------------------------------------------- |
| `role.grant`        | Route access lists, creating and deleting gate users                                               |
| `secret.reveal`     | One-time credential reveals, SQL workspace queries and schema reads                                |
| `resource.delete`   | Deleting aliases and front-door routes, purging mailboxes                                          |
| `restore.overwrite` | Restore tests and recording restore proof                                                          |
| `exposure.public`   | Admin mode, AAAA publication, source CIDRs, pooler policy, gate login origin, route exposure       |
| `credential.rotate` | Database role rotation, database clients, Vercel integrations, backup targets, client certificates |
| `platform.update`   | Platform maintenance, service updates, region and database ingress settings                        |

The flow is:

1. The client calls `POST /api/step-up` with the account password, the `action`, and either `request` (the binding object the target route will check) or a precomputed `planHash`.
2. The API verifies the password with Better Auth and stores a grant bound to the user, the session, the action and `privilegedRequestHash(action, request)` (`shared/src/hash.ts`). The grant expires after 10 minutes.
3. The client sends the real request. The route computes the same hash from what it received and atomically consumes the newest matching, unexpired, unconsumed grant (`consumePrivilegedGrant`).

A grant therefore authorises exactly one request with exactly that content. Routes validate their input and check scope before consuming the grant, so a 404, a scope refusal or a validation error does not burn it. A missing or mismatched grant is 403 `Verify your password and MFA for <action> before continuing.` `POST /api/step-up` itself requires an operator or owner with MFA assurance; after 5 failed password attempts within 15 minutes it answers 429 until the window passes. Successes and failures are audited as `auth.step_up` and `auth.step_up_failed`.

The binding a route checks depends on the route:

| Route                                                               | Action              | Binding (`request`)                                                                    |
| ------------------------------------------------------------------- | ------------------- | -------------------------------------------------------------------------------------- |
| `PUT /api/domains/:id/aaaa` (enabling only)                         | `exposure.public`   | `{ domainId, enabled }`                                                                |
| `DELETE /api/aliases/:id`                                           | `resource.delete`   | `{ aliasId }`                                                                          |
| `POST /api/sql/query`                                               | `secret.reveal`     | `{ databaseId, kind: "sql.query" }`                                                    |
| `POST /api/databases/:id/schema`                                    | `secret.reveal`     | `{ databaseId, kind: "schema" }`                                                       |
| `POST /api/databases/:id/rotate`                                    | `credential.rotate` | `{ databaseId, kind }`                                                                 |
| `PUT /api/databases/:id/cidrs`                                      | `exposure.public`   | `{ databaseId, cidrs }` (the submitted `sourceCidrs`)                                  |
| `PUT /api/databases/pooler-policy`                                  | `exposure.public`   | The exact request body                                                                 |
| `POST /api/databases/:id/clients`                                   | `credential.rotate` | `{ databaseId, ...body }`                                                              |
| `POST /api/databases/:id/clients/:clientId/reveal`                  | `secret.reveal`     | `{ databaseId, clientId }`                                                             |
| `POST /api/databases/:id/clients/:clientId/revoke`                  | `credential.rotate` | `{ databaseId, clientId }`                                                             |
| `POST /api/databases/:id/clients/:clientId/rollover`                | `credential.rotate` | `{ databaseId, clientId, rollover: true, ...body }`                                    |
| `POST /api/databases/:id/clients/:clientId/rollover/reveal`         | `secret.reveal`     | `{ databaseId, clientId, rollover: true }`                                             |
| `PUT /api/databases/:id/clients/:clientId/vercel-integration`       | `credential.rotate` | `{ databaseId, clientId, vercelIntegration: "connect", ... }` (`vercelConnectBinding`) |
| `POST /api/databases/:id/clients/:clientId/vercel-integration/test` | `credential.rotate` | `{ databaseId, clientId, vercelIntegration: "test" }`                                  |
| `DELETE /api/databases/:id/clients/:clientId/vercel-integration`    | `credential.rotate` | `{ databaseId, clientId, vercelIntegration: "disconnect" }`                            |
| `POST /api/devices/:id/credential`                                  | `secret.reveal`     | `{ deviceId }`                                                                         |
| `POST /api/platform/maintain`                                       | `platform.update`   | `{ maintain: body }`                                                                   |
| `POST /api/secrets/:id/reveal`                                      | `secret.reveal`     | `{ secretId }`                                                                         |
| `POST /api/databases/:id/credential`                                | `secret.reveal`     | `{ databaseId, kind: "runtime" }`                                                      |
| `POST /api/mailboxes/:id/credential`                                | `secret.reveal`     | `{ mailboxId }`                                                                        |
| `POST /api/backups/restore-test`                                    | `restore.overwrite` | `{ kind, targetId, backupId }`                                                         |
| `POST /api/backups/:id/verify-restore`                              | `restore.overwrite` | `{ backupId, verify: true }`                                                           |
| `PUT /api/backups/targets/:kind`                                    | `credential.rotate` | `{ backupTarget: "s3" or "tailnet_rest", ...body }`                                    |
| `POST /api/mailboxes/:id/lifecycle` (purge only)                    | `resource.delete`   | `{ mailboxId, lifecycle: "purged" }`                                                   |
| `POST /api/updates/apply`                                           | `platform.update`   | `{ serviceId, digest }`                                                                |
| `POST /api/settings/mode`                                           | `exposure.public`   | `{ adminMode }`                                                                        |
| `PUT /api/settings/region`                                          | `platform.update`   | The exact request body                                                                 |
| `PUT /api/settings/db-ingress`                                      | `platform.update`   | The exact request body                                                                 |
| `PUT /api/settings/gate` (mode `public` only)                       | `exposure.public`   | The exact request body                                                                 |
| `POST /api/front/routes`                                            | `exposure.public`   | The exact request body                                                                 |
| `PATCH /api/front/routes/:id` (loosening changes only)              | `exposure.public`   | `{ routeId, ...body }`                                                                 |
| `POST /api/front/routes/:id/enable`                                 | `exposure.public`   | `{ routeId }`                                                                          |
| `POST /api/front/routes/:id/client-certificates`                    | `credential.rotate` | `{ routeId, ...body }`                                                                 |
| `DELETE /api/front/routes/:id`                                      | `resource.delete`   | `{ routeId }`                                                                          |
| `PUT /api/front/routes/:id/access`                                  | `role.grant`        | `{ routeId, ...body }`                                                                 |
| `POST /api/gate/users`                                              | `role.grant`        | Derived from the body (`gateUserCreateBinding`)                                        |
| `POST /api/gate/users/:id/temporary-password`                       | `secret.reveal`     | Derived from the user id (`gateUserRevealBinding`)                                     |
| `DELETE /api/gate/users/:id`                                        | `role.grant`        | Derived from the user id (`gateUserDeleteBinding`)                                     |

Tightening changes need no grant: disabling a route, revoking a client certificate, disabling the gate login origin, turning AAAA publication off and narrowing a route with `PATCH`. A `PATCH /api/front/routes/:id` that loosens exposure without a matching grant answers 403 with `"code": "exposure_step_up_required"` and the list of loosening changes is returned on success as `loosening`.

### Worker, agent and watchdog tokens

The `/api/internal/*` middleware maps the bearer token to a worker identity:

| Token                       | Identity        | Job kinds it may claim, heartbeat and complete                                                                                  |
| --------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `ARK_AGENT_TOKEN`           | `agent`         | `service.*` and `update.apply`                                                                                                  |
| `ARK_DATABASE_WORKER_TOKEN` | `database`      | `database.*`, `pgbouncer.*`                                                                                                     |
| `ARK_DOMAIN_WORKER_TOKEN`   | `domains`       | `domain.*`, `dns.*`, `certificate.*`, `edge.*`, `admin.*`, `integration.*`, the IPv6 preflight                                  |
| `ARK_MAIL_WORKER_TOKEN`     | `mail`          | `mail.*`, `mailbox.*`, `ses.*`                                                                                                  |
| `ARK_BACKUP_WORKER_TOKEN`   | `backup`        | `backup.*`, `update.detect`, `import.*`                                                                                         |
| `ARK_INTERNAL_TOKEN`        | `module`        | All module kinds above except `integration.*` and the IPv6 preflight, plus `update.detect`; never `service.*` or `update.apply` |
| `ARK_EDGE_WATCHDOG_TOKEN`   | `edge-watchdog` | None; it may only read the edge lease and report watchdog events                                                                |

A per-worker token is recognised only when its environment variable is set on the API. The edge watchdog gets 403 on anything outside `/api/internal/edge/`, and every other identity gets 403 on `/api/internal/edge/*`. An unknown token is 401 `Invalid worker credential.` The allowlist is in `workerPrefixes` in `server/src/app.ts`; see [Operations and workers](../operations/operations-and-workers.md) for how claims, heartbeats and completions work.

### Edge gate token

The four gate handlers (`/api/gate/check`, `/api/gate/bypass-check`, `/api/gate/callback`, `/api/gate/logout-route`) are called only by the edge's Caddy, with `X-Ark-Edge-Token` equal to `ARK_EDGE_GATE_TOKEN`. When `ARK_EDGE_PEER_ADDRESSES` is set, the transport peer must also be one of those addresses. Any other caller gets 401 with `WWW-Authenticate: Ark-Edge`; with an unset token every call is refused. The token grants no authority beyond these handlers. See [trust boundary B5](../security-review.md#b5-caddy--ark-api-forward_auth-login-origin).

### Metrics and maintenance tokens

`GET /api/metrics/prometheus` requires `Authorization: Bearer` with `ARK_METRICS_TOKEN`. Outside production, an unset `ARK_METRICS_TOKEN` falls back to `ARK_INTERNAL_TOKEN`; in production it is required. See [Monitoring](../features/monitoring.md).

`POST /api/platform/maintain` additionally requires the `X-Maintenance-Token` header equal to `ARK_MAINTENANCE_TOKEN`. If that variable is unset the route answers 503 rather than accepting a placeholder.

## Conventions

### Requests

- Mutating admin requests (anything other than `GET`, `HEAD`, `OPTIONS` after the session check) must carry an `Origin` header equal to the origin of `BETTER_AUTH_URL` or one of `BETTER_AUTH_TRUSTED_ORIGINS`, and `Content-Type: application/json`. Otherwise the API answers 403 `The request origin is not trusted.` or 415 `Custom API mutations require application/json.` Routes that take no meaningful body still require the JSON content type.
- Identifiers are a short prefix, an underscore and a random hex string, created by `createId` in `shared/src/id.ts` (for example `dom_…` for domains, `db_…` for databases, `op_…` for operations).
- Input is validated with Zod schemas from `shared/src` (mostly `shared/src/schemas.ts`); many are strict and reject unknown keys.

### Errors

Every error is a JSON object with an `error` message:

```json
{ "error": "Owner access is required." }
```

Messages are written for the operator and are safe to display; secrets are redacted from them. The status codes used are:

| Status | Meaning                                                                                                                              |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| 400    | Malformed request that is not a schema error (duplicate auth cookies, an unknown backup target kind)                                 |
| 401    | No session, an unknown worker or metrics token, or a non-edge caller on a gate handler                                               |
| 403    | Not permitted: no administration access, wrong session origin, role, scope, missing MFA assurance or step-up grant, untrusted origin |
| 404    | Unknown resource or result; also every non-allowlisted path on the login origin                                                      |
| 405    | A gate edge handler called with the wrong method by the edge                                                                         |
| 409    | State conflict: already revealed, already complete, a stale review, a lease that changed, a transition that is not allowed           |
| 413    | Body larger than 256 KiB                                                                                                             |
| 415    | A mutation that is not `application/json`                                                                                            |
| 421    | The `Host` is not a registered Ark origin                                                                                            |
| 422    | Validation failure (Zod, `ValidationError`, CSR and PKI policy refusals, compose policy violations)                                  |
| 429    | Rate limited: Better Auth sign-in and two-factor attempts, step-up failures, database client issuance                                |
| 500    | Unexpected server failure, reported as `The request could not be completed.`                                                         |
| 503    | A dependency is unavailable: mail disabled (`ARK_MAIL_ENABLED`), a worker endpoint unreachable, maintenance token unset              |

### Operations

Most changes are not performed by the API itself. The handler validates and authorises the request, writes the desired state, queues a durable operation (`enqueue` in `server/src/coordinator.ts`) and returns its id, usually as `{ "operationId": "op_…" }`. A worker or the agent then claims and executes it. Some routes return 202 Accepted with the operation (DNS publish, IPv6 preflight, client issuance, revocation and rollover, tailnet observations); most return 200 with the id.

Enqueueing is idempotent. The key is the operation kind, its target ids and a hash of its payload (or an explicit key). If an operation with the same key is still in flight (`queued`, `awaiting_approval`, `running` or `waiting_external`), that operation is returned instead of a new one; `edge.apply` and `edge.l4_apply` reuse only a queued successor. Repeating a request is therefore safe and does not duplicate work.

Operation states are defined in `shared/src/operations.ts`: `queued`, `awaiting_approval`, `running`, `waiting_external`, `succeeded`, `failed`, `cancelled` and `needs_recovery`. Clients follow progress through `GET /api/state` (the 50 most recent operations and their steps, filtered to what the caller may see) or through the dedicated result endpoints (`/api/sql/results/:operationId`, `/api/services/discovery/:operationId`, `/api/services/:id/observations/:operationId`, `/api/domains/:id/publish/:operationId`). Result endpoints return `{ "status": …, "available": false }` until the operation has succeeded.

### Secrets in responses

One-time reveals and step-up responses are sent with `Cache-Control: no-store`. A one-time secret is marked consumed in the same transaction that audits the reveal, so a second reveal answers 409. Root and provider credentials (including private CA keys) are never returned by any route. Database client credentials and gate user temporary passwords leave only through their own reveal routes, never through `POST /api/secrets/:id/reveal`.

### Auditing

Every mutation writes an audit event (`audit_events`) with the actor, role, action, resource and operation id, with secrets redacted from the detail. Owners see the 50 most recent events in `GET /api/state`; other roles see only their own.

## Endpoints

Access column legend: **Public** needs no credential; **Session** is any signed-in administrator (viewer, operator or owner); **Operator** is operator or owner; **Owner** is owner only; **+MFA** adds MFA assurance; **+step-up** adds a single-use grant for the named action (which implies operator and MFA); **scoped** adds a project, domain or database grant check.

### Health, setup and session

| Endpoint                       | Access          | Purpose                                                                                                                                                                                                                                                                                                                                                                                                            |
| ------------------------------ | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET /api/health`              | Public          | Runs `SELECT 1` against the control database and returns `{ "status": "ok" }`.                                                                                                                                                                                                                                                                                                                                     |
| `GET /api/setup/status`        | Public          | Returns `required` (no administrator yet) and `wizardRequired` (administrator exists, first-run wizard not done).                                                                                                                                                                                                                                                                                                  |
| `GET /api/state`               | Session         | The admin UI's main state document: user and setup status, settings, region, database ingress, pooler policy, and every domain, record, endpoint, certificate, cluster, database, mailbox, alias, device, project, service, recent operation and step, backup, alert, audit event and update candidate the caller may see, plus which providers are configured. Alerts are included only for owners and operators. |
| `GET /api/me`                  | Session         | The caller's user row and access (role and grants).                                                                                                                                                                                                                                                                                                                                                                |
| `GET /api/metrics`             | Session         | A small JSON summary: failed and running operations, backups without restore proof, certificates expiring within 14 days.                                                                                                                                                                                                                                                                                          |
| `POST /api/step-up`            | Operator +MFA   | Mints a single-use step-up grant (see [Step-up grants](#step-up-grants)). Returns `{ action, expiresAt }`.                                                                                                                                                                                                                                                                                                         |
| `POST /api/wizard`             | Owner +MFA      | Completes the first-run wizard once: creates the base domain claim, its DNS plan, endpoints, the application cluster and optional first database and mailbox, stores admin mode and public addresses, and queues `domain.verify` (manual DNS) and the IPv6 preflight when an IPv6 address is given. 409 once the wizard is complete.                                                                               |
| `POST /api/auth/sign-up/email` | `X-Setup-Token` | Creates the first owner while bootstrap is open (see [Administrator sessions](#administrator-sessions)).                                                                                                                                                                                                                                                                                                           |
| `ALL /api/auth/*`              | Better Auth     | Every other Better Auth endpoint (sign-in, sign-out, get-session, two-factor enable, verify and backup codes). On TOTP verification Ark records the MFA enrolment time.                                                                                                                                                                                                                                            |

### Login gate

The edge handlers implement `access_mode: sso` HTTP routes; the pages are served only on the login origin. See [Admin access modes](../features/admin-access-modes.md) and [Login gate for SSO routes](../operating.md#login-gate-for-sso-routes-fd-11).

| Endpoint                      | Access     | Purpose                                                                                                                                                                                                                                               |
| ----------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /api/gate/check`         | Edge token | `forward_auth` check for a gated route: 204 with `X-Ark-User` and `X-Ark-Email` for a live gate session and an acceptable `Origin`; 403 for a refused `Origin` or unknown route; otherwise a 302 to the login origin (HTML `GET`/`HEAD` only) or 401. |
| `GET /api/gate/bypass-check`  | Edge token | 204 only when the unmodified request target (`X-Ark-Original-Uri`) passes the raw-URI guard and falls under one of the route's bypass paths; otherwise 400. Grants no session.                                                                        |
| `GET /api/gate/callback`      | Edge token | Consumes the single-use handoff code on the route host (`/.ark/gate/callback`), checks state, route, parent session, access and MFA, sets the `__Host-ark_gate` cookie and redirects (303) to the original path.                                      |
| `POST /api/gate/logout-route` | Edge token | With an `Origin` equal to the route origin, revokes this browser's gate session for the route (`/.ark/gate/logout`) and clears the cookie.                                                                                                            |

Any other method on these four paths answers 405 to the edge and 401 to anyone else. The login origin also serves these non-API pages:

| Endpoint              | Purpose                                                                                                                |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `GET /gate/login`     | Sign-in page; redirects a signed-in user to a validated relative `next`, or to enrolment if TOTP is not set up.        |
| `GET /gate/enroll`    | Forced first TOTP enrolment for a gate user.                                                                           |
| `GET /gate/authorize` | Authorises the signed-in user for a route and redirects back with a handoff code, or shows "Access denied".            |
| `POST /gate/logout`   | Global sign-out on the login origin; same-origin `Origin` required. Ending the login session ends every route session. |

Any other `/gate/*` path is 404 on every host.

### Internal: workers, agent and edge watchdog

| Endpoint                                 | Access                | Purpose                                                                                                                                                                                                                                                              |
| ---------------------------------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /api/internal/heartbeat`           | Worker or agent token | Records `{ version }` and the time for the caller's identity in `worker_heartbeats`.                                                                                                                                                                                 |
| `GET /api/internal/jobs`                 | Worker or agent token | Claims at most one queued job. Module workers must send `X-Ark-Worker-Kinds` listing prefixes from their allowlist (403 otherwise); the agent claims agent-owned work and re-checks that the operation's actor is still authorised. Each job carries a `claimToken`. |
| `POST /api/internal/jobs/:id/heartbeat`  | Worker or agent token | Extends the lease on a claimed job; body `{ claimToken }`. 409 when the lease is stale or no longer owned.                                                                                                                                                           |
| `POST /api/internal/jobs/:id/complete`   | Worker or agent token | Finishes a running job as `succeeded` or `failed` with optional `error` and `evidence`; the claim token must match (fencing). Evidence is stored, redacted, as a `worker-complete` step.                                                                             |
| `GET /api/internal/edge/lease`           | Edge watchdog token   | The current edge lease and the tailnet backends the proxies may dial, minus routes whose gate revocation is overdue. Polled every second; `Cache-Control: no-store`.                                                                                                 |
| `POST /api/internal/edge/watchdog-event` | Edge watchdog token   | Reports `withdrawn`, `withdrawal_failed`, `proxy_stopped`, `stop_failed` or `policy_unavailable`. Audits it, queues `edge.apply`, and raises a critical alert for anything but `withdrawn`.                                                                          |

### Metrics

| Endpoint                      | Access        | Purpose                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /api/metrics/prometheus` | Metrics token | Prometheus text exposition: `ark_operations` by status, `ark_backups_unverified`, `ark_certificates_expiring`, `ark_worker_heartbeat_stale` per identity (stale after 90 seconds), database client rollover and retirement gauges, nftables drop counters for the public ports, `ark_host_reboot_required` (from `ARK_HOST_METRICS_DIR`), and off-VPS backup target gauges including `ark_backups_healthy`. |

Prometheus scrapes this endpoint as configured in `infra/monitoring/prometheus.yml`; the alert rules are in `infra/monitoring/alerts.yml`. See [Monitoring](../features/monitoring.md).

### Domains and DNS

| Endpoint                                     | Access                                            | Purpose                                                                                                                                                                            |
| -------------------------------------------- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /api/domains`                          | Operator +MFA (owner for Cloudflare)              | Claims a domain and returns the `_ark-stack` TXT ownership record to publish. Choosing the `cloudflare` provider requires an owner.                                                |
| `POST /api/domains/:id/verify`               | Operator +MFA, scoped                             | Opens a 30-minute manual DNS watch window (manual domains) and queues `domain.verify`.                                                                                             |
| `POST /api/domains/:id/dns/watch`            | Operator +MFA, scoped                             | Opens or renews the manual DNS watch window without queueing; returns 204.                                                                                                         |
| `GET /api/domains/:id/dns`                   | Operator, scoped                                  | The DNS review: desired records against what the provider or resolvers show. Cloudflare reviews are fetched through the domain worker; `?local=1` returns the local plan only.     |
| `POST /api/domains/:id/publish`              | Operator +MFA, scoped                             | Publishes a reviewed Cloudflare change set; body `{ planHash, authorizeAAAAWithdrawal?, requestId? }` (the withdrawal flag needs an owner). Returns 202 with a `Location` to poll. |
| `GET /api/domains/:id/publish/:operationId`  | Operator, scoped                                  | Status of a `dns.publish` operation; answers 409 when it failed on a conflict.                                                                                                     |
| `PUT /api/domains/:id/aaaa`                  | Owner +MFA (+step-up `exposure.public` to enable) | Turns AAAA publication on or off for the domain, reconciles its records and queues `domain.verify` for route endpoints.                                                            |
| `DELETE /api/domains/:id/aaaa/authorization` | Owner +MFA                                        | Revokes a pending automatic AAAA withdrawal authorisation for the domain's records.                                                                                                |

See [Domains and DNS](../features/domains-and-dns.md) and [Native IPv6 and AAAA publication](../operating.md#native-ipv6-and-aaaa-publication).

### Projects and services

| Endpoint                                          | Access                | Purpose                                                                                                                                                                   |
| ------------------------------------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /api/projects`                              | Operator +MFA         | Creates a project and grants it to the caller.                                                                                                                            |
| `POST /api/services`                              | Operator +MFA, scoped | Registers a compose service after policy validation (`validateComposeSource`), writes the approved compose file and queues `service.deploy`. 422 lists policy violations. |
| `POST /api/services/discover`                     | Owner +MFA            | Queues `service.discover`, a redacted inventory of host containers.                                                                                                       |
| `GET /api/services/discovery/:operationId`        | Owner                 | The discovery result, classified against registered services (at most 100 containers).                                                                                    |
| `POST /api/services/adopt`                        | Operator +MFA, scoped | Adopts an existing container from an adoption-safe compose definition and queues `service.adopt`.                                                                         |
| `POST /api/services/:id/observe`                  | Operator +MFA, scoped | Queues `service.logs` or `service.stats`; body `{ kind: "logs" \| "stats" }`.                                                                                             |
| `GET /api/services/:id/observations/:operationId` | Operator, scoped      | The observation result: up to the last 500 log lines, or the stats object.                                                                                                |
| `POST /api/services/:id/:action`                  | Operator +MFA, scoped | `restart`, `start` or `stop`; queues `service.restart`, `service.start` or `service.stop`. Any other action is 404.                                                       |

Service operations are executed by the Docker agent, which enforces its own policy. See [Services](../features/services.md).

### Databases

| Endpoint                             | Access                                | Purpose                                                                                                                                                                          |
| ------------------------------------ | ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /api/databases`                | Operator +MFA, scoped                 | Creates a managed database in a cluster (default: the first) and queues `database.provision`. 400 until the wizard created a cluster.                                            |
| `POST /api/databases/:id/rotate`     | Step-up `credential.rotate`, scoped   | Queues `database.rotate` for the `runtime`, `readonly` or `migration` role.                                                                                                      |
| `PUT /api/databases/:id/cidrs`       | Step-up `exposure.public`, scoped     | Sets the database's requested source CIDRs (at most 50) and queues `pgbouncer.reload`.                                                                                           |
| `GET /api/databases/:id/admission`   | Operator, scoped                      | Whether a source address (`?ip=`) would be admitted on public 5432 under the pooler-wide policy, with the database's requested CIDRs.                                            |
| `GET /api/databases/pooler-policy`   | Operator                              | The pooler-wide source policy, the databases' requests, conflicts, fingerprint and publication state.                                                                            |
| `PUT /api/databases/pooler-policy`   | Owner +MFA +step-up `exposure.public` | Saves the pooler-wide policy. The body must echo `reviewedRequests`, the fingerprint it reviewed (409 if the requests changed). Queues an edge re-render and `pgbouncer.reload`. |
| `POST /api/databases/:id/credential` | Step-up `secret.reveal`, scoped       | One-time reveal of the runtime role password with a `verify-full` connection string. 409 once shown.                                                                             |
| `POST /api/databases/:id/schema`     | Step-up `secret.reveal`, scoped       | Queues `database.schema` (read through the readonly role); read the result from `GET /api/sql/results/:operationId`.                                                             |

See [Databases](../features/databases.md) and [Public database access](../features/public-database-access.md).

### SQL workspace

| Endpoint                            | Access                          | Purpose                                                                                                                               |
| ----------------------------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /api/sql/query`               | Step-up `secret.reveal`, scoped | Classifies the SQL (`classifySql`) and queues `database.query` for the chosen role; returns the operation and fingerprint.            |
| `GET /api/sql/results/:operationId` | Operator, scoped                | The bounded result of a `database.query` or `database.schema` operation.                                                              |
| `POST /api/sql/cancel`              | Operator +MFA, scoped           | Cancels a running query by `executionId`, through the database worker's `/cancel` endpoint (or in-process when workers are embedded). |

See [SQL workspace](../features/sql-workspace.md).

### Database clients and Vercel

All routes here are owner-only. See [Vercel database guide](../guides/vercel-database.md) and [Certificate rollover](../operating.md#certificate-rollover).

| Endpoint                                                            | Access                                  | Purpose                                                                                                                                              |
| ------------------------------------------------------------------- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /api/databases/:id/clients`                                    | Owner                                   | Lists the database's mTLS clients.                                                                                                                   |
| `POST /api/databases/:id/clients`                                   | Owner +MFA +step-up `credential.rotate` | Issues a client (generated key or a submitted CSR, validated before queueing). Rate limited (429). Returns 202 with `clientId`, role and `readOnly`. |
| `POST /api/databases/:id/clients/:clientId/reveal`                  | Owner +MFA +step-up `secret.reveal`     | One-time reveal of the issued client bundle. 409 if not issued yet, revoked or already revealed.                                                     |
| `POST /api/databases/:id/clients/:clientId/revoke`                  | Owner +MFA +step-up `credential.rotate` | Queues revocation; returns 202.                                                                                                                      |
| `GET /api/databases/:id/clients/:clientId/vercel`                   | Owner                                   | Vercel setup guidance for the client.                                                                                                                |
| `GET /api/databases/:id/clients/:clientId/rollover`                 | Owner                                   | Certificate rollover status for the client.                                                                                                          |
| `POST /api/databases/:id/clients/:clientId/rollover`                | Owner +MFA +step-up `credential.rotate` | Starts an early rollover (optional CSR); returns 202 with the predecessor certificate id.                                                            |
| `POST /api/databases/:id/clients/:clientId/rollover/reveal`         | Owner +MFA +step-up `secret.reveal`     | One-time reveal of the successor bundle.                                                                                                             |
| `POST /api/databases/:id/clients/:clientId/rollover/confirm`        | Owner +MFA                              | Confirms manual delivery of the successor certificate (`certificateId`).                                                                             |
| `GET /api/databases/:id/clients/:clientId/vercel-integration`       | Owner                                   | Status of the Vercel integration for this client.                                                                                                    |
| `PUT /api/databases/:id/clients/:clientId/vercel-integration`       | Owner +MFA +step-up `credential.rotate` | Connects the client to a Vercel project so rollovers are delivered automatically.                                                                    |
| `POST /api/databases/:id/clients/:clientId/vercel-integration/test` | Owner +MFA +step-up `credential.rotate` | Tests the stored Vercel connection.                                                                                                                  |
| `DELETE /api/databases/:id/clients/:clientId/vercel-integration`    | Owner +MFA +step-up `credential.rotate` | Disconnects the Vercel integration.                                                                                                                  |

### Mail

Every mail route except the two credential reveals answers 503 `Mail is disabled on this installation.` when `ARK_MAIL_ENABLED` disables mail. See [Mail](../features/mail.md).

| Endpoint                             | Access                                                      | Purpose                                                                                                                                                                                    |
| ------------------------------------ | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `POST /api/mailboxes`                | Operator +MFA, scoped                                       | Creates a mailbox and queues `mail.provision`.                                                                                                                                             |
| `POST /api/mailboxes/:id/credential` | Step-up `secret.reveal`, scoped                             | One-time reveal of the mailbox's initial password. 409 once none remains.                                                                                                                  |
| `POST /api/mailboxes/:id/lifecycle`  | Operator +MFA, scoped (+step-up `resource.delete` to purge) | Moves a mailbox to `active`, `suspended`, `retained` or `purged` and queues `mail.reconcile`. Purging is refused while active aliases target the address; a purged address stays reserved. |
| `POST /api/mailboxes/:id/devices`    | Operator +MFA, scoped                                       | Adds a device credential (app password) and queues `mailbox.device`.                                                                                                                       |
| `POST /api/devices/:id/credential`   | Step-up `secret.reveal`, scoped                             | One-time reveal of a device password. 409 once shown.                                                                                                                                      |
| `POST /api/devices/:id/revoke`       | Operator +MFA, scoped                                       | Revokes a device credential through `mailbox.device`.                                                                                                                                      |
| `POST /api/aliases`                  | Operator +MFA, scoped                                       | Creates an alias after external-forwarding and alias-graph checks; queues `mail.reconcile`. Needs a mailbox on the domain (409).                                                           |
| `PATCH /api/aliases/:id`             | Operator +MFA, scoped                                       | Replaces an alias's targets and description; queues `mail.reconcile`.                                                                                                                      |
| `DELETE /api/aliases/:id`            | Step-up `resource.delete`, scoped                           | Deletes an alias (directly if never provisioned, otherwise through `mail.reconcile`).                                                                                                      |
| `POST /api/mail/reconcile`           | Operator +MFA, scoped                                       | Queues `mail.reconcile` for a mailbox; body `{ mailboxId }`.                                                                                                                               |
| `POST /api/ses/reconcile`            | Operator +MFA, scoped                                       | Queues `ses.reconcile` for a domain; body `{ domainId }`.                                                                                                                                  |
| `GET /api/mail/queue`                | Operator                                                    | The Stalwart outbound queue, limited to items whose sender or recipient domain the caller may view, redacted.                                                                              |
| `POST /api/mail/queue`               | Operator +MFA, scoped                                       | Retries or deletes a queue item (`mail.queue_retry`, `mail.queue_delete`) when `canMutateQueue` allows it.                                                                                 |

### Backups

See [Backups](../features/backups.md) and the [backups guide](../guides/backups.md).

| Endpoint                               | Access                                  | Purpose                                                                                                                                                           |
| -------------------------------------- | --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /api/backups`                    | Operator +MFA, scoped                   | Queues `backup.create` for `platform-postgres`, `app-postgres`, `mail` or `volume` and a target id.                                                               |
| `POST /api/backups/restore-test`       | Step-up `restore.overwrite`, scoped     | Queues `backup.restore_test` for a specific backup of that target and kind.                                                                                       |
| `POST /api/backups/:id/verify-restore` | Step-up `restore.overwrite`, scoped     | Records human restore proof. The body must be `{ "confirmation": "restored copy booted and served its data" }`; 409 if the backup's state does not allow it.      |
| `GET /api/backups/targets`             | Owner                                   | Off-VPS targets (credentials never returned), backup health, provider recipes, the tailnet recipe, the region hint and per-bucket protection and writer policies. |
| `PUT /api/backups/targets/:kind`       | Owner +MFA +step-up `credential.rotate` | Saves the `s3` or `tailnet_rest` target and queues `backup.verify_target` (the append-only canary). Credentials are write-only.                                   |
| `POST /api/backups/targets/:id/verify` | Owner                                   | Queues `backup.verify_target` again for a saved target.                                                                                                           |
| `GET /api/backups/tailnet`             | Owner                                   | The backup tailnet node's view: its generation, lease and each home target's identity.                                                                            |
| `POST /api/backups/tailnet/observe`    | Owner +MFA                              | Queues a read-only `backup.observe`; returns 202.                                                                                                                 |

### Secrets

| Endpoint                       | Access                          | Purpose                                                                                                                                                                                                                                                              |
| ------------------------------ | ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /api/secrets/:id/reveal` | Step-up `secret.reveal`, scoped | Generic reveal of a stored secret owned by a resource the caller manages. One-time secrets answer 409 after the first reveal. Root and provider secrets, database client credentials, gate user passwords and secrets without a verified owner are refused with 403. |

### Platform settings, maintenance, updates and import

| Endpoint                            | Access                                                   | Purpose                                                                                                                                                                                             |
| ----------------------------------- | -------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PUT /api/settings`                 | Owner +MFA                                               | Saves `timezone`, `defaultQuotaGb` and `allowExternalForwarding`.                                                                                                                                   |
| `POST /api/settings/mode`           | Owner +step-up `exposure.public`                         | Changes admin mode to `public` or `tailnet`; queues `admin.mode_change`. See [Mode changes](../operating.md#mode-changes).                                                                          |
| `GET /api/settings/region`          | Session                                                  | The region preset and the suggestions derived from it.                                                                                                                                              |
| `PUT /api/settings/region`          | Owner +MFA +step-up `platform.update`                    | Sets `region` and `vpsRegionLabel`. It does not change `AWS_REGION` or SES.                                                                                                                         |
| `GET /api/settings/db-ingress`      | Session                                                  | Per-source limits on the public database port.                                                                                                                                                      |
| `PUT /api/settings/db-ingress`      | Owner +MFA +step-up `platform.update`                    | Sets `maxConnectionsPerSource`, `newConnectionsPerSecond` and `newConnectionBurst`; queues `pgbouncer.reload`. See [Public database port limits](../operating.md#public-database-port-limits).      |
| `GET /api/settings/gate`            | Owner                                                    | The gate login origin settings.                                                                                                                                                                     |
| `PUT /api/settings/gate`            | Owner +MFA (+step-up `exposure.public` for `public`)     | Sets the login origin to `public` with a hostname, or `disabled`; returns the DNS records to publish.                                                                                               |
| `GET /api/settings/ipv6/preflight`  | Owner +MFA                                               | IPv6 preflight status and, for the given or latest `operationId`, the signed manual probe challenge.                                                                                                |
| `POST /api/settings/ipv6/preflight` | Owner +MFA                                               | Queues the IPv6 preflight; returns 202.                                                                                                                                                             |
| `POST /api/platform/maintain`       | Owner + `X-Maintenance-Token` +step-up `platform.update` | Queues `platform.maintain` with `{ version, images, digest, allowStateful? }`. Normally driven by `scripts/maintain.ts`. See [Maintenance and upgrades](../operations/maintenance-and-upgrades.md). |
| `POST /api/updates/detect`          | Owner +MFA                                               | Queues `update.detect` to look for new image digests.                                                                                                                                               |
| `POST /api/updates/apply`           | Step-up `platform.update`, scoped                        | Queues `update.apply` for a service and digest.                                                                                                                                                     |
| `POST /api/import/scan`             | Owner +MFA                                               | Queues `import.scan` for an `orkmail`, `pgstack` or `compose` source, optionally limited to named domains, databases and services. The response reports `ownersImported: false`.                    |

The IPv6 probe posts its result to `/api/settings/ipv6/preflight/result` (method `POST`, path constant `ipv6PreflightResultPath` in `server/src/modules/ipv6-preflight.ts`). It needs no session: the body is `{ signature, report }`, `Content-Type` must be `application/json` (415 otherwise), and the signature must be valid, unexpired and unused (403 otherwise). An accepted report queues the preflight with the report and returns 202.

### Alerts

| Endpoint                       | Access        | Purpose                                                                |
| ------------------------------ | ------------- | ---------------------------------------------------------------------- |
| `POST /api/alerts/:id/ack`     | Operator +MFA | Marks an alert acknowledged.                                           |
| `POST /api/alerts/:id/silence` | Operator +MFA | Silences an alert for `minutes` (5 to 10080); returns `silencedUntil`. |

Alerts themselves are listed in `GET /api/state`. See [Monitoring](../features/monitoring.md).

### Front door

Route listing is open to every administrator; every change is owner-only with MFA. See the [front door guide](../guides/front-door.md) and [HTTP routes](../operating.md#http-routes).

| Endpoint                                                               | Access                                  | Purpose                                                                                                                                                                       |
| ---------------------------------------------------------------------- | --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /api/front/routes`                                                | Session                                 | Lists all front-door routes.                                                                                                                                                  |
| `GET /api/front/routes/:id`                                            | Session                                 | One route.                                                                                                                                                                    |
| `GET /api/front/listeners`                                             | Session                                 | Listener and protocol guidance: the SNI router port, shared SNI ports (available and enabled), the raw-TCP port range, reserved ports, TLS modes and Postgres route guidance. |
| `GET /api/front/routes/:id/dns`                                        | Operator, scoped                        | The DNS review for the route's domain claim (`?local=1` for the local plan only).                                                                                             |
| `POST /api/front/routes`                                               | Owner +MFA +step-up `exposure.public`   | Creates a route; returns 201 with the route, DNS records to publish, the Tailscale policy snippet and the observe operation id.                                               |
| `PATCH /api/front/routes/:id`                                          | Owner +MFA (+step-up for loosening)     | Updates a route; returns the route, its status and any loosening changes.                                                                                                     |
| `POST /api/front/routes/:id/enable`                                    | Owner +MFA +step-up `exposure.public`   | Enables a route.                                                                                                                                                              |
| `POST /api/front/routes/:id/disable`                                   | Owner +MFA                              | Disables a route (a tightening; no step-up).                                                                                                                                  |
| `DELETE /api/front/routes/:id`                                         | Owner +MFA +step-up `resource.delete`   | Deletes a route.                                                                                                                                                              |
| `GET /api/front/routes/:id/client-certificates`                        | Owner                                   | Client certificates of a `terminate_mtls` or HTTP mTLS route.                                                                                                                 |
| `POST /api/front/routes/:id/client-certificates`                       | Owner +MFA +step-up `credential.rotate` | Issues a client certificate (`name`, optional `csrPem`); returns 201.                                                                                                         |
| `POST /api/front/routes/:id/client-certificates/:certificateId/revoke` | Owner +MFA                              | Revokes a client certificate; the CRL is regenerated and the route's sessions drained.                                                                                        |
| `GET /api/front/routes/:id/access`                                     | Owner                                   | The route's access list (individual users).                                                                                                                                   |
| `PUT /api/front/routes/:id/access`                                     | Owner +MFA +step-up `role.grant`        | Replaces the access list with `userIds` (at most 500); removals revoke and drain.                                                                                             |
| `GET /api/front/acl`                                                   | Owner                                   | The global Tailscale policy snippet for all routes. Ark never writes the tailnet policy itself.                                                                               |
| `GET /api/front/routes/:id/acl`                                        | Owner                                   | The policy snippet for one route.                                                                                                                                             |
| `GET /api/front/tailnet`                                               | Owner                                   | The edge node's view of the tailnet: latest generation, lease and each route's identity state.                                                                                |
| `POST /api/front/tailnet/observe`                                      | Owner +MFA                              | Queues a read-only `edge.observe`; returns 202.                                                                                                                               |

### Gate users

Gate users are login-origin-only accounts for SSO routes, with no administration access.

| Endpoint                                      | Access                              | Purpose                                                                                               |
| --------------------------------------------- | ----------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `GET /api/gate/users`                         | Owner                               | Lists gate users.                                                                                     |
| `POST /api/gate/users`                        | Owner +MFA +step-up `role.grant`    | Creates a gate user (`email`, optional `name`); returns 201.                                          |
| `POST /api/gate/users/:id/temporary-password` | Owner +MFA +step-up `secret.reveal` | One-time reveal of the user's temporary password.                                                     |
| `DELETE /api/gate/users/:id`                  | Owner +MFA +step-up `role.grant`    | Deletes the user, cascading its sessions, gate sessions and route access, and drains affected routes. |

### Other paths

| Endpoint                                 | Access | Purpose                                                                    |
| ---------------------------------------- | ------ | -------------------------------------------------------------------------- |
| `GET /.well-known/acme-challenge/:token` | Public | Serves the key authorisation for a pending ACME HTTP-01 challenge, or 404. |

## Worker endpoints the API calls

Two workers expose a small HTTP endpoint of their own, which the API calls with the worker's token:

- The domain worker serves `POST /dns/review` at `ARK_DOMAIN_WORKER_URL`. The API uses it for Cloudflare DNS reviews because the domain worker is the only component with external provider egress. In production an unset URL is a 503; in development the review runs in-process.
- The database worker serves `POST /cancel` at `ARK_DATABASE_WORKER_URL` for SQL workspace cancellation. With `ARK_EMBEDDED_WORKERS` (development only) the cancellation runs in-process instead.

## Related pages

- [Operations and workers](../operations/operations-and-workers.md): the queue behind every `operationId`.
- [Accounts and access](../features/accounts-and-access.md): roles, grants and MFA from the operator's side.
- [Security model](../security/security-model.md) and the [security review checklist](../security-review.md#privilege-boundaries).
- [Commands](commands.md) and [Repository](../development/repository.md) for where the code lives.
