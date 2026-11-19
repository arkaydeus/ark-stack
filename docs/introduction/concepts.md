# Core concepts

This page explains, from first principles, the ideas the rest of the documentation relies on: how Ark Stack separates the control plane from your workloads, how a request becomes durable work, who is allowed to do that work, how the tailnet and front door fit in, and how secrets, MFA and access are handled. A glossary closes the page.

## Control plane and workloads

Ark Stack has two kinds of thing running on the host.

- **The control plane** is Ark itself: the API and admin UI (`api`), its PostgreSQL database (`postgres`), the workers, the Docker agent, the front-door proxies and their watchdog. Its job is to hold the description of what should exist and to make the host match it.
- **Workloads** are what the control plane manages for you: databases in the application PostgreSQL cluster (`app-postgres`), mailboxes in Stalwart, service containers deployed by the agent, and public routes to services on your tailnet.

The two are deliberately kept apart. Application databases never live in the control-plane instance. Service containers run in their own Compose projects, named `ark-<project slug>`, and the agent rejects Compose documents that reference platform networks or volumes. Workloads keep running when the API is stopped; only changes to them wait.

## Desired state and reconciliation

When you act in the UI, the API does not change the host directly. It writes **desired state** (rows such as a domain claim, a DNS record plan, an endpoint, a database, a service revision, a front-door route) and queues an **operation** that will make reality match it. A worker later performs the operation and records what it observed.

This has three consequences you will see throughout the product:

- **Status reflects observation.** Statuses move forward only when a worker has seen evidence: public DNS answers, an issued certificate, a confirmed PgBouncer reload, a restore test. Until then a resource shows the state it is waiting in, such as `awaiting_dns`.
- **Retries are safe.** Operations are idempotent by design. Enqueuing the same kind, targets and payload while an earlier copy is still in flight returns the existing operation instead of creating a second one.
- **Drift is corrected or reported.** Scheduled work re-checks the world: `domain.verify` re-reads public DNS, `edge.observe` re-reads the tailnet every five minutes, the backup worker observes its executors and targets, and the API reconciles the database ingress policy on every start.

## Operations, steps and evidence

An operation is a row in the control-plane database with a kind (for example `certificate.issue`), target IDs, a payload, an idempotency key and a status. It is durable: it survives restarts of the API and of the worker that runs it.

| Status              | Meaning                                                                                         |
| ------------------- | ----------------------------------------------------------------------------------------------- |
| `queued`            | Waiting for a worker allowed to run this kind.                                                  |
| `awaiting_approval` | Held until it is approved; it then returns to `queued`.                                         |
| `running`           | Claimed by a worker that holds its claim token and keeps its lease alive.                       |
| `waiting_external`  | Waiting on something outside Ark; it returns to `running` when that completes.                  |
| `succeeded`         | Finished, with evidence recorded. Terminal.                                                     |
| `failed`            | Finished with a redacted error. It can be queued again.                                         |
| `cancelled`         | Stopped before completion. Terminal. Cancellation never means data was rolled back.             |
| `needs_recovery`    | A worker made an external change but could not record its completion. It needs operator review. |

The allowed transitions are fixed in `shared/src/operations.ts`; any other transition is rejected.

Claiming is careful about concurrency:

- A worker claims one operation at a time under an advisory lock and receives a **claim token**. Only the holder of that token can heartbeat or complete the operation.
- Workers heartbeat each running operation every 15 seconds. An operation whose heartbeat is older than its lease (90 seconds by default) is put back to `queued` with the note "Previous worker lease expired; operation reclaimed."
- No two operations that share a target run at the same time. A second operation on the same database, domain or route waits until the first finishes.

As it runs, an operation records **steps** with JSON **evidence** (for example `certificate-issued` with the issuer, or `edge-apply` with the hostnames still awaiting a certificate). The completion call adds the worker's own evidence, redacted. Every user-initiated change also writes an **audit event** naming the actor, role, resource and operation. Audit events are redacted and cannot be deleted through the API. The **Activity** view shows operations, steps and audit history.

[Operations and workers](../operations/operations-and-workers.md) covers every operation kind and how to recover failed and stuck operations.

## Workers and typed job allowlists

Operations are executed by separate processes, each with its own bearer token and a fixed list of the operation kinds it may run. A worker polls `GET /api/internal/jobs` and states the kinds it wants in a header; the API refuses the poll if any requested kind is outside that worker's allowlist, and refuses heartbeats and completions for kinds it does not own.

| Identity | Token                       | Container         | Operation kinds                                                                                                                                      |
| -------- | --------------------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| database | `ARK_DATABASE_WORKER_TOKEN` | `database-worker` | `database.*`, `pgbouncer.*`                                                                                                                          |
| domains  | `ARK_DOMAIN_WORKER_TOKEN`   | `domain-worker`   | `domain.*` (including `domain.ipv6_preflight`), `dns.*`, `certificate.*`, `edge.*`, `admin.*`, `integration.*`                                       |
| mail     | `ARK_MAIL_WORKER_TOKEN`     | `mail-worker`     | `mail.*`, `mailbox.*`, `ses.*`                                                                                                                       |
| backup   | `ARK_BACKUP_WORKER_TOKEN`   | `backup-worker`   | `backup.*`, `update.detect`, `import.*`                                                                                                              |
| agent    | `ARK_AGENT_TOKEN`           | `agent`           | `service.*`, `update.apply`, and only when the payload has the exact shape the agent expects (for example a canonical Compose document and its hash) |
| watchdog | `ARK_EDGE_WATCHDOG_TOKEN`   | `edge-watchdog`   | None. It may only read the edge lease and report withdrawal events under `/api/internal/edge/`.                                                      |

The split follows the secrets each worker needs. Only the domain worker has outbound provider egress for DNS, ACME and integrations, and only it can reach the edge's control sockets. Only the database worker reaches the application cluster and the PgBouncer admin socket. Only the backup worker reaches the pgBackRest executors and the backup Tailscale node. Only the agent has the Docker socket. A compromised worker therefore cannot run another worker's jobs.

In local development, `ARK_EMBEDDED_WORKERS=1` runs the same job handlers inside the API process instead. The API ignores that setting when `NODE_ENV=production`, which every Ark image sets.

## The Docker agent

The agent is a small Go program (`agent/`) and the only component that mounts the host Docker socket. Every three seconds it sends a heartbeat, polls for one job and runs it. For a deployment it:

1. validates the Compose document against its own default-deny policy, independently of the TypeScript policy the API already applied, and rejects anything outside it;
2. runs Compose with a fixed argument vector, never a shell string, and keeps a ledger of the exact containers, networks and volumes it owns;
3. journals the outcome of every job locally, so a completion it could not report is still on record;
4. inspects the effective Docker settings afterwards: read-only root filesystem, bounded `/tmp`, all capabilities dropped, `no-new-privileges`, and PID, memory and CPU limits;
5. reports evidence with its claim token. When it hands out a job and before it accepts a successful completion, the API checks that the operation's actor is still authorised.

Discovery of existing containers, bounded and redacted logs, and whitelisted stats come back the same way, as evidence on a scoped operation. The API itself has no Docker access in production.

## The tailnet and node identities

Ark uses your Tailscale tailnet for every private path: owner access to the host, the tailnet admin UI, the front door's reach to your services, and backups to a home machine. Each path has its own Tailscale node with its own key, state and tag, so the reach of one never implies the reach of another.

| Tag                   | Node                                              | Purpose                                                                                                       |
| --------------------- | ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `tag:ark-vps`         | The host's own `tailscaled`                       | Tailscale SSH for the owner. Lets public TCP 22 be closed at the provider.                                    |
| `tag:ark-edge`        | `edge-ts` container, hostname `ark-edge`          | The front door's transport to tailnet targets. Kernel mode, `--shields-up`, one grant per target `host:port`. |
| `tag:ark-stack-admin` | `tailscale` container, hostname `ark-stack-admin` | Optional tailnet-only admin UI through Tailscale Serve (Compose profile `tailnet`).                           |
| `tag:ark-backup`      | `backup-ts` container, hostname `ark-backup`      | Reaches only the home backup server's `rest-server`. Userspace, `--shields-up`, SOCKS5 for the backup worker. |

Some rules apply to all of them:

- **Ark never changes your tailnet policy.** It holds no Tailscale API key or OAuth client. The **Front door ACL** page generates a policy snippet with the four tags, one host alias per target machine, one grant per route target and per backup target, and deny tests. You review and merge it by hand. See [Tailnet policy snippet](../operating.md#tailnet-policy-snippet).
- **Auth keys are one-off.** Each node joins with a single-use, pre-approved, non-ephemeral key tagged for its role, which you then remove from `.env` and revoke. Never reuse a failed node's identity.
- **Shields up.** The edge and backup nodes accept no inbound tailnet connections, whatever the policy says.
- **Pinning and leases.** Every front-door route and tailnet backup target is pinned to its target's Tailscale StableNodeID. `edge.observe` reads the edge node's LocalAPI read-only every five minutes and commits a **generation** with a six-minute **lease**. When the lease lapses, or a target no longer matches its pin, traffic to it is withdrawn. `backup.observe` does the same for `backup-ts`.

## The front door

The front door is how the internet reaches anything on the host except mail. It runs in the network namespace of `edge-ts`, which publishes the public ports:

- **HAProxy (`edge-l4`)** owns TCP 443 and routes by TLS SNI, owns TCP 5432 and sends classic PostgreSQL clients to PgBouncer and direct-TLS Postgres routes to their targets, and serves raw TCP routes on 20000–20049 and any enabled shared SNI ports.
- **Caddy (`edge`)** serves TCP 80 for ACME challenges and redirects, terminates HTTPS behind HAProxy with Ark-issued certificates, runs the login gate and applies HTTP route controls.
- **The edge watchdog (`edge-watchdog`)** checks the lease every second and withdraws a route from both proxies, including its open sessions, within a five-second budget when the lease no longer allows it. Launch guards start each proxy from a closed configuration unless the watchdog authorises the full one.

Front-door routes come in four kinds: `http`, `tls`, `postgres` and `tcp`. HTTP routes have an access mode: `public`, or `sso` (the default), which requires a session from the public login origin `login.<domain>`. The public admin hostname, the login host and the database hostname are served through the same edge, but with their own rules. The [front-door guide](../guides/front-door.md) explains every route kind.

## Platform PostgreSQL and application clusters

There are two PostgreSQL clusters, and they never share data or credentials.

| Cluster                        | Service        | Image basis                              | Roles                                                                                                                                                         | Network                          |
| ------------------------------ | -------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| Control plane (`ark_platform`) | `postgres`     | `postgres:17.6` with pgBackRest          | `ark_migration` owns the schema and runs migrations; `ark_runtime` is the API's and workers' login, with no DDL and no `UPDATE` or `DELETE` on `audit_events` | `control` (internal)             |
| Application                    | `app-postgres` | `pgvector/pgvector:pg17` with pgBackRest | `ark_cluster_admin` for the database worker; per database, generated owner, migration, runtime and read-only roles                                            | `database-management` (internal) |

Neither cluster publishes a host port in production. Public database traffic reaches only PgBouncer, through HAProxy on 5432, and PgBouncer admits only runtime and read-only login roles. Privileged, backup and bootstrap identities are refused on the public listener. In local development, `infra/platform/docker-compose.dev.yml` binds the two clusters to loopback ports 5433 and 5434.

## Secrets encryption

Operational secrets, such as generated database passwords, private CA keys, client certificate keys, provider tokens and restic passwords, are stored in the control-plane database only in encrypted form.

- **Algorithm.** AES-256-GCM with a random 96-bit IV per value and an authentication tag. The 256-bit key is the SHA-256 digest of `ARK_ROOT_KEY`.
- **Root key.** `ARK_ROOT_KEY` (at least 32 characters; the installer generates 32 random bytes) lives only in the host's `.env` and in the environment of the containers that seal or open secrets: `api` and the database, domain, mail and backup workers. It is never written to PostgreSQL. The edge watchdog, the agent and the proxies do not receive it.
- **Key IDs.** Every sealed value records the key ID it was sealed under, `ARK_ROOT_KEY_ID` (default `k1`). The running stack loads exactly one root key, so the ID identifies which key a value needs; it is not an automatic rotation mechanism.
- **Disclosure.** Inventory APIs return metadata, never plaintext. Generated credentials are revealed once, through a conditional atomic consume, and only to a user with access to the underlying database or mailbox and a `secret.reveal` step-up.

> [!WARNING]
> Losing or changing `ARK_ROOT_KEY` makes every sealed secret unreadable. Keep `ARK_ROOT_KEY` and `ARK_ROOT_KEY_ID` off the host; the host-loss checklist restores them before any database restore.

## MFA and step-up

Administrators authenticate with Better Auth: email and password (at least 12 characters) and TOTP.

- **MFA enrolment.** After the first sign-in, the UI requires TOTP enrolment and shows one set of recovery codes. Every administrative mutation requires **MFA assurance**: two-factor enabled, and a session created no earlier than the enrolment. A session that predates enrolment must sign in again.
- **Rate limits.** Sign-in and two-factor attempts are limited to five per minute per client address.
- **Step-up.** Privileged actions need a fresh password confirmation. `POST /api/step-up` takes the password, one of the actions `role.grant`, `secret.reveal`, `resource.delete`, `restore.overwrite`, `exposure.public`, `credential.rotate` or `platform.update`, and a hash binding the exact request. It returns a single-use grant valid for 10 minutes, which only that request can consume. Failed step-ups are throttled per user and audited.

Lost factors are recovered on the host, not in the UI: see [Recovery](../operations/recovery.md).

## Owner and platform access

Signing in is not the same as being an administrator.

- **Platform access.** The admin API accepts a session only if its user has a `platform_access` row. The first owner gets one when setup completes. The roles are `owner`, `operator` and `viewer`. Operators and viewers see and change only the projects and domains granted to them; owners see everything. Some areas are owner-only regardless: front-door routes, the ACL snippet, gate users, admin mode and platform settings.
- **Session origin.** Each session records the origin that minted it: the admin origin or the public login origin. A session is accepted only on its own origin. Admin-origin sessions are never minted for gate users, and gate sessions cannot manage admin accounts.
- **Registered hosts.** The API answers session-bearing requests only for hosts it can name: the hosts in `BETTER_AUTH_URL` and `BETTER_AUTH_TRUSTED_ORIGINS`, and the login host when the login origin is enabled. Any other `Host` gets `421` before Better Auth runs. Over HTTPS, cookies are host-only `__Host-` cookies.
- **Gate users.** Accounts created by the owner on the **Gate users** page sign in only on the login origin, to reach `sso` routes. They have no platform access.

## Endpoint, route and certificate states

Several resources share a lifecycle: their DNS must be verified, then a certificate issued, then traffic served.

### Endpoints

An endpoint is a public or private hostname for the admin UI, the database pooler, mail, the login origin or a front-door route.

| Status                  | Meaning                                                                                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `draft`                 | Created but not yet checked.                                                                                                                            |
| `awaiting_dns`          | The required records are not all verified in public DNS, or a blocker (CAA, Cloudflare proxy, unexpected AAAA, unpublished Cloudflare plan) is present. |
| `verified`              | Public DNS matches. A certificate order is queued.                                                                                                      |
| `testing`               | A publicly trusted certificate is issued (for the database endpoint: and PgBouncer has reloaded with it), and the edge has been asked to serve it.      |
| `certificate_untrusted` | The certificate is from Let's Encrypt staging or the local development fallback. It is never served by the public edge.                                 |

These are the statuses the code writes today; `shared/src/dns-plan.ts` also defines `issuing_certificate`, `provisioning`, `ready` and `error` for endpoints. A front-door route's own status (below) is what tells you whether a route is served.

### Certificates

| Status            | Meaning                                                                                      |
| ----------------- | -------------------------------------------------------------------------------------------- |
| `issued`          | Issued by Let's Encrypt production. Only `issued` certificates are served by the edge.       |
| `untrusted`       | Issued by Let's Encrypt staging or the local OpenSSL fallback.                               |
| `awaiting_reload` | A database endpoint certificate waiting for PgBouncer to reload and present its fingerprint. |

### Front-door routes

| Status                | Meaning                                                                                                              |
| --------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `draft`               | Being created. Creation moves it straight on to `awaiting_acl` once its ACL snippet is issued.                       |
| `awaiting_acl`        | The edge cannot open TCP to the pinned target: merge the route's grant from the ACL snippet.                         |
| `awaiting_dns`        | The target is reachable; public DNS for the hostname is not verified yet.                                            |
| `issuing_certificate` | DNS is verified and a certificate is being issued.                                                                   |
| `ready`               | A fresh probe from the edge namespace passed and the hostname has an issued certificate.                             |
| `identity_mismatch`   | The target no longer matches its pinned StableNodeID. It stays in this state until the owner re-confirms the target. |
| `observation_expired` | No valid generation covers the route. It is withdrawn until the next successful observation.                         |

The schema also defines `disabled` and `error`. Only `edge.observe` writes `ready`. Being `ready` and being served are separate: the owner also enables the route, with an `exposure.public` step-up.

Domain claims themselves are `awaiting_dns` until the ownership TXT record is observed, then `verified`. Individual DNS records are `pending`, `verified` or `error`, with extra withdrawal states for AAAA records being removed.

## Glossary

| Term                | Meaning                                                                                                      |
| ------------------- | ------------------------------------------------------------------------------------------------------------ |
| ACL snippet         | The generated Tailscale policy fragment (tags, host aliases, grants, tests) that the owner merges by hand.   |
| Admin mode          | How the admin UI is reached: `public` (HTTPS hostname through the edge) or `tailnet` (Tailscale Serve only). |
| Agent               | The Go Docker agent, the only holder of the Docker socket.                                                   |
| Application cluster | The `app-postgres` PostgreSQL instance holding your databases.                                               |
| Audit event         | An append-only record of who did what to which resource, linked to its operation.                            |
| Claim token         | The secret a worker receives when it claims an operation; required to heartbeat and complete it.             |
| Control plane       | Ark's own services and its `ark_platform` database.                                                          |
| Desired state       | What should exist, as recorded by the API before any worker acts.                                            |
| Domain claim        | A domain proved by the installation-bound `_ark-stack` TXT record.                                           |
| Edge                | The front door's proxies and Tailscale node: `edge-ts`, `edge-l4` (HAProxy) and `edge` (Caddy).              |
| Embedded workers    | Development mode in which the API runs the worker job handlers itself.                                       |
| Endpoint            | A hostname Ark serves or verifies, with its own exposure (`public` or private) and status.                   |
| Evidence            | JSON recorded on an operation's steps and completion that shows what a worker observed.                      |
| Gate, login gate    | The SSO check in front of `sso` HTTP routes, backed by sessions from the login origin.                       |
| Gate user           | An account that can sign in only on the login origin.                                                        |
| Generation, lease   | An observed snapshot of the edge's tailnet view and the six-minute window during which routes may use it.    |
| Login origin        | The public `login.<domain>` site that exposes only sign-in, MFA and gate endpoints.                          |
| MFA assurance       | Two-factor enabled and a session created after enrolment; required for administrative changes.               |
| Operation           | A durable unit of work with a kind, targets, payload, status, steps and evidence.                            |
| Owner               | The highest platform role; created by the setup token.                                                       |
| Pin                 | A route's or backup target's binding to a Tailscale StableNodeID.                                            |
| Platform access     | The `platform_access` row that makes a user an administrator with a role.                                    |
| Pooler              | `pgbouncer-public`, the mTLS and SCRAM PostgreSQL pooler behind 5432.                                        |
| Root key            | `ARK_ROOT_KEY`, the secret from which the AES-256-GCM key for sealed secrets is derived.                     |
| Route               | A public front-door hostname or port that forwards to a pinned tailnet target.                               |
| Setup token         | `ARK_SETUP_TOKEN`, the single-use bootstrap credential for creating the first owner.                         |
| Step-up grant       | A single-use, 10-minute authorisation for one privileged request, obtained by re-entering the password.      |
| Watchdog            | `edge-watchdog`, which withdraws routes the lease no longer allows.                                          |
| Worker              | A process that executes one family of operation kinds with its own token.                                    |
