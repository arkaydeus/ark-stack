# Repository

This page is a guided tour of the source tree for contributors: what lives in each top-level directory and its important modules, the tech stack, the coding conventions, how migrations work, how to add an API route, an operation kind or a worker job, and what the CI workflows run.

## Top-level layout

| Path                   | Contents                                                                                                                                    |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `server/`              | The Hono API, Better Auth, the Drizzle schema and migrations, and the operations coordinator                                                |
| `shared/`              | Pure TypeScript shared by the server, workers and UI: policies, planners, renderers, schemas, authorisation                                 |
| `workers/`             | Entry points of the database, domain, mail and backup workers, the edge watchdog, the HAProxy validator and the pgBackRest executor         |
| `web/`                 | The React administration UI (Vite, Tailwind)                                                                                                |
| `agent/`               | The Go Docker agent, its Compose policy and its local journal and ledger                                                                    |
| `infra/`               | Compose manifests and configuration for the platform, mail, monitoring, restore, PostgreSQL and the custom edge Caddy build                 |
| `templates/`           | Reviewed application service definitions (`templates/http-app.yml`, `templates/worker.yml`, `templates/persistent.yml`)                     |
| `scripts/`             | Operator CLIs (install, audit, maintenance, recovery, import, publishing), the docs check and site generator, and the Docker test harnesses |
| `tests/`               | Cross-cutting Bun tests: `tests/security` (static manifest and policy checks) and `tests/browser` (HTTP flows)                              |
| `e2e/`                 | Playwright browser specs                                                                                                                    |
| `assets/brand/`        | The Ark Stack icon: the supplied master (`assets/brand/ark-stack-icon.png`) and the README's 256px copy                                     |
| `docs/`                | This documentation, the runbooks, guides, design history and reviews                                                                        |
| `.github/`             | CI workflows and the Dependabot configuration                                                                                               |
| `mise.toml`            | Pinned tool versions and every project task ([Commands](../reference/commands.md))                                                          |
| `Dockerfile`           | Multi-stage build of every first-party image except the agent                                                                               |
| `docker-bake.hcl`      | The Buildx Bake plan: the twelve published image targets                                                                                    |
| `package.json`         | The Bun workspace root (`shared`, `server`, `web`, `workers`) and shared dev dependencies                                                   |
| `playwright.config.ts` | Playwright settings for `e2e/`                                                                                                              |
| `.env.example`         | The documented configuration template, copied to `.env`                                                                                     |

Root configuration files also include `bunfig.toml` (exact installs, test root at the repository root), `tsconfig.base.json` (the shared strict compiler options), `.oxlintrc.json` and `.oxfmtrc.json`.

## server

`server/` is the only process that talks to users and the only owner of desired state. Its main files:

| File                                                                                    | Role                                                                                                                                                                                                                                                                 |
| --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `server/src/index.ts`                                                                   | Process entry point: loads and checks the environment (placeholder secrets are refused), queues the startup database-ingress reconciliation, starts the off-host heartbeat sender, starts the embedded coordinator when enabled, and serves the app with `Bun.serve` |
| `server/src/app.ts`                                                                     | Every HTTP route, the middleware chain (body limit, host and origin checks, session and access loading, CSRF origin and JSON content-type checks, internal worker authentication) and the error handler                                                              |
| `server/src/coordinator.ts`                                                             | The durable operation queue: `enqueue`, `claimQueued`, `heartbeatClaim`, `runOperation` (the dispatch from operation kind to handler), the handlers themselves and the schedulers (DNS maintenance, edge observation, backups, certificate rollover)                 |
| `server/src/schema.ts`                                                                  | The Drizzle schema of the control-plane database                                                                                                                                                                                                                     |
| `server/src/auth.ts`                                                                    | Better Auth configuration: the two-factor plugin, host-only `__Host-` cookies, registered hosts and session origins                                                                                                                                                  |
| `server/src/access.ts`                                                                  | Authorisation helpers used by routes: `requireOperator`, `requireOwner`, `requireMfa`, `requirePrivileged` (single-use step-up grants), project, domain, mailbox and database scope checks, and redaction                                                            |
| `server/src/env.ts`                                                                     | Typed environment loading, including worker tokens and `embeddedWorkers`                                                                                                                                                                                             |
| `server/src/db.ts`                                                                      | The `postgres` client and Drizzle instance                                                                                                                                                                                                                           |
| `server/src/migrate.ts`                                                                 | The migration runner                                                                                                                                                                                                                                                 |
| `server/src/cli.ts`                                                                     | The local recovery CLI behind `mise run recover`                                                                                                                                                                                                                     |
| `server/src/client-ip.ts`, `server/src/origin-hosts.ts`, `server/src/session-origin.ts` | Trusted client address, registered admin and login origins, and the origin recorded on each session                                                                                                                                                                  |
| `server/src/gate-pages.ts`                                                              | Server-rendered pages of the gate login origin                                                                                                                                                                                                                       |

`server/src/modules/` holds the provider adapters and domain logic the coordinator and routes call. Grouped by area:

- **Domains, DNS and certificates**: `domain-dns.ts` (reviewed DNS plans and publication), `cloudflare-dns.ts`, `dns-verification.ts`, `certificates.ts` (lego), `ipv6-preflight.ts`.
- **Front door**: `front-routes.ts` (route lifecycle), `edge-routes.ts` and `edge-route-input.ts` (`edge.apply` input), `edge-l4.ts` (`edge.l4_apply`), `l4-routes.ts`, `edge-observe.ts` (edge observer and identity pinning), `tailnet-localapi.ts`, `tailnet-snapshot.ts`, `front-acl.ts` (tailnet policy snippets), `front-ingress.ts`, `route-pki.ts`, `route-crl.ts`, `pooler-policy.ts`.
- **Login gate**: `gate.ts` (handshake), `gate-settings.ts`, `gate-users.ts`, `gate-revocations.ts`.
- **Databases**: `database.ts` (SQL workspace and schema execution in the database worker), `pgbouncer.ts`, `pgbouncer-lock.ts`, `db-clients.ts`, `db-client-rollover.ts`, `pki.ts` and `x509.ts` (the private CA and DER primitives), `vercel-api.ts`, `vercel-integrations.ts`.
- **Mail**: `mail.ts`, `queue.ts` (Stalwart queue access).
- **Backups**: `backups.ts`, `offsite-backups.ts`, `backup-canary.ts`, `rest-canary.ts`, `backup-observe.ts`, `pg-executor-client.ts`, `s3-client.ts`, `socks5-http.ts`.
- **Services and platform**: `docker.ts`, `providers.ts` (Caddy, Stalwart, allowlist and other host adapters), `alerts.ts`, `offhost-heartbeat.ts`.

Files named `test-*.ts`, `*-test-kit.ts` and `*-fuzz-*.ts` in `server/src/modules`, and `server/src/mock-localapi.ts` and `server/src/edge-test-fixture.ts`, are test-only helpers.

## shared

`shared/` is the `@ark-stack/shared` package. Everything in it is free of I/O against Ark's own database, so the same code runs in the API, workers, scripts and tests. `shared/src/index.ts` re-exports the modules; the package also exports `./dns-review` and `./http-rate-limit` separately for the UI. Important modules:

- `shared/src/operations.ts`: operation states, allowed transitions and the `OperationKind` union.
- `shared/src/authz.ts`: roles (`owner`, `operator`, `viewer`), privileged actions, MFA assurance and last-owner protection.
- `shared/src/schemas.ts`: shared zod schemas.
- `shared/src/dns-plan.ts`, `shared/src/dns-review.ts`, `shared/src/cloudflare.ts`, `shared/src/acme.ts`: DNS planning and review.
- `shared/src/edge.ts`, `shared/src/edge-http.ts`, `shared/src/edge-l4.ts`, `shared/src/haproxy-control.ts`, `shared/src/caddy-state.ts`, `shared/src/edge-withdrawal.ts`, `shared/src/front-routes.ts`, `shared/src/front-nft.ts`, `shared/src/l4-admission.ts`: Caddy and HAProxy rendering, withdrawal and the edge watchdog, route rules and the host firewall for the front door.
- `shared/src/gate.ts`, `shared/src/gate-login.ts`: the login gate policy.
- `shared/src/pgbouncer.ts`, `shared/src/pooler-policy.ts`, `shared/src/db-clients.ts`, `shared/src/db-ingress.ts`, `shared/src/provision-sql.ts`, `shared/src/sql-guard.ts`, `shared/src/schema-browser.ts`: PostgreSQL, the public pooler and the SQL workspace.
- `shared/src/backup-targets.ts`, `shared/src/backup-plan.ts`, `shared/src/pg-backup.ts`: backups.
- `shared/src/tailnet.ts`, `shared/src/tailnet-acl.ts`, `shared/src/tailnet-observe.ts`: Tailscale.
- `shared/src/stalwart.ts`, `shared/src/mail-state.ts`, `shared/src/mail-queue.ts`, `shared/src/ses.ts`: mail.
- `shared/src/compose-policy.ts`, `shared/src/adopt.ts`, `shared/src/update-policy.ts`, `shared/src/registry.ts`: workload Compose canonicalisation, adoption, update policy and container-registry digest lookups.
- `shared/src/maintenance.ts`, `shared/src/install.ts`, `shared/src/host-firewall.ts`, `shared/src/import-inventory.ts`, `shared/src/region.ts`: install, maintenance bundles, host firewall, import and region settings.
- `shared/src/crypto.ts`, `shared/src/redact.ts`, `shared/src/hash.ts`, `shared/src/id.ts`, `shared/src/errors.ts`: encryption, redaction, hashing and IDs.

## workers

Each worker is a small entry point that imports the coordinator's `executeClaimedJob` and polls the API through `workers/src/runtime.ts`. See [Operations and workers](../operations/operations-and-workers.md) for the queue and each worker's responsibilities.

| File                               | Compose service                      | Polls for                                                                                                                                                                                                           |
| ---------------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `workers/src/database.ts`          | `database-worker`                    | `database.`, `pgbouncer.`; also serves the query-cancellation listener and runs the certificate rollover scheduler                                                                                                  |
| `workers/src/domains.ts`           | `domain-worker`                      | `domain.`, `dns.`, `certificate.`, `edge.`, `admin.`, plus separate loops for `integration.` and the IPv6 preflight; also serves the DNS review control endpoint and schedules edge observation and DNS maintenance |
| `workers/src/mail.ts`              | `mail-worker`                        | `mail.`, `mailbox.`, `ses.`                                                                                                                                                                                         |
| `workers/src/backup.ts`            | `backup-worker`                      | `backup.create` and `backup.restore_test` (concurrency 2), `backup.export` (concurrency 4); schedules backups and `backup-ts` observation                                                                           |
| `workers/src/edge-watchdog.ts`     | `edge-watchdog`                      | Nothing: it reads the edge lease every second and withdraws routes from Caddy and HAProxy when the lease or policy says so (`workers/src/proxy-watchdog.ts`, `workers/src/watchdog-config.ts`)                      |
| `workers/src/haproxy-validator.ts` | `haproxy-validator`                  | Nothing: a Unix-socket daemon that validates HAProxy configuration generations for the domain worker                                                                                                                |
| `workers/src/pg-executor.ts`       | inside `postgres` and `app-postgres` | Nothing: a fixed set of pgBackRest actions on the internal backup network                                                                                                                                           |

`workers/src/runtime.ts` is the worker contract: send `POST /api/internal/heartbeat`, ask `GET /api/internal/jobs` with an `x-ark-worker-kinds` allowlist, heartbeat each claim every 15 seconds, and complete it with redacted evidence. A failure after a mutation completed is reported as `needs_recovery` rather than as an ordinary failure.

## web

`web/` is a single-page React 19 app built with Vite and styled with Tailwind CSS 4.

- `web/src/main.tsx` mounts the app; `web/src/App.tsx` holds the sign-in, MFA and wizard gates and the navigation. Views are selected by the URL hash (`#/domains`, `#/front-routes` and so on); owner-only entries are flagged `ownerOnly`.
- `web/src/pages/Views.tsx` holds most views (overview, domains and endpoints, projects, databases, email, services, activity, backups, updates, settings). Larger views have their own files: `web/src/pages/FrontRoutes.tsx`, `web/src/pages/FrontAcl.tsx`, `web/src/pages/GateUsers.tsx`, `web/src/pages/DnsReview.tsx`, `web/src/pages/BackupTargets.tsx`, `web/src/pages/PoolerPolicy.tsx`, `web/src/pages/VercelRollover.tsx`, `web/src/pages/Auth.tsx` and `web/src/pages/Wizard.tsx`.
- `web/src/lib/utils.ts` has the `api` fetch helper (credentials included, JSON content type, `ApiError` on non-2xx) and `act` for fire-and-forget mutations that surface errors in the global banner. `web/src/lib/auth-client.ts` is the Better Auth client and `web/src/lib/types.ts` the API types.
- `web/src/components/ui` holds the small set of shadcn-style primitives (button, card, badge, input) on Radix UI. `web/src/components/brand-mark.tsx` is the icon beside the "Ark Stack" wordmark.
- `web/public/` holds the favicon, the web app manifest and the sized icons in `web/public/brand/`. The dev-only `mise run brand:icons` task (`scripts/brand-icons.ts`, Bun only) derives the committed icons and the admin theme colour from `assets/brand/ark-stack-icon.png`. The gate pages and docs site serve copies of the same icon files.

In development Vite proxies `/api` to `127.0.0.1:3000`. In production the API serves the built UI (Vite's `dist` output in `web/`) itself.

## agent

`agent/` is a Go 1.25 module whose only dependency is `gopkg.in/yaml.v3`. It is the only component that receives the Docker socket.

- `agent/main.go`: the poll loop (every 3 seconds), heartbeats and job execution. It authenticates with `ARK_AGENT_TOKEN` and receives only `service.` and `update.apply` jobs.
- `agent/policy.go`: Compose validation before any engine call (no Docker socket mounts, no privileged mode, no reserved ports, digest-pinned images, the canonical sandbox).
- `agent/docker.go`: the Engine API over the Unix socket, inventory, adoption checks and container mutations.
- `agent/ledger.go` and `agent/journal.go`: the durable ownership ledger of containers, networks and volumes, and the local recovery journal.

## infra

| Path                                                                                       | Contents                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `infra/platform/docker-compose.yml`                                                        | The production platform topology: both PostgreSQL clusters, the API, `migrate`, every worker, the agent, `pgbouncer-public`, `database-ingress`, `edge-ts`, `edge`, `edge-l4`, `edge-watchdog`, `haproxy-validator`, `backup-ts`, `tailscale` and `tailnet-gateway` |
| `infra/platform/docker-compose.dev.yml`                                                    | Loopback bindings for the two PostgreSQL clusters in development                                                                                                                                                                                                    |
| `infra/platform/Caddyfile`, `infra/platform/TailnetCaddyfile`, `infra/platform/serve.json` | Static Caddy and Tailscale Serve configuration                                                                                                                                                                                                                      |
| `infra/platform/edge-launch-guard.sh`, `infra/platform/edge-l4-launch-guard.sh`            | Launch guards that refuse to start Caddy and HAProxy without a fresh watchdog pass                                                                                                                                                                                  |
| `infra/platform/edge-errors`                                                               | Static error pages served by the edge                                                                                                                                                                                                                               |
| `infra/platform/init-control-db.sh`                                                        | Control-plane database roles on first start                                                                                                                                                                                                                         |
| `infra/platform/release.json`                                                              | The sample signed maintenance bundle                                                                                                                                                                                                                                |
| `infra/database/`                                                                          | `pg_hba.conf` and `pgbouncer.ini` for the clusters and the pooler                                                                                                                                                                                                   |
| `infra/backup/ark-postgres-entrypoint.sh`                                                  | Entrypoint of the PostgreSQL images with the pgBackRest executor                                                                                                                                                                                                    |
| `infra/edge-caddy/`                                                                        | The patch and Go test for the bounded rate-limit plugin of the custom Caddy build                                                                                                                                                                                   |
| `infra/mail/`                                                                              | The Stalwart Compose project and configuration                                                                                                                                                                                                                      |
| `infra/monitoring/`                                                                        | Prometheus, its scrape configuration and alert rules ([Monitoring](../features/monitoring.md))                                                                                                                                                                      |
| `infra/restore/docker-compose.yml`                                                         | The isolated restore project used after host loss                                                                                                                                                                                                                   |

## scripts, tests and e2e

`scripts/` mixes three kinds of file: operator CLIs wrapped by mise tasks (`scripts/install.ts`, `scripts/host-audit.ts`, `scripts/maintain.ts`, `scripts/recover-mfa.ts`, `scripts/recover-host.ts`, `scripts/import.ts`, `scripts/publish-images.ts`, `scripts/pin-edge-caddy.ts`, `scripts/edge-namespace.ts`), the modules they import (`scripts/install-*.ts`, `scripts/host-inventory.ts` and others), and the test harnesses (`scripts/test-*.ts`, `scripts/edge-test/`, `scripts/backup-test/` and the other `*-test/` folders). `scripts/check-docs.ts` is the documentation drift check, `scripts/docs-site/build.ts` builds this site from `docs/nav.json` and `scripts/brand-icons.ts` derives the icons. [Commands](../reference/commands.md) lists every script and [Testing](../development/testing.md) every harness.

## Tech stack

| Area                        | Choice                                                                  | Version (pinned)                      |
| --------------------------- | ----------------------------------------------------------------------- | ------------------------------------- |
| Runtime and package manager | Bun                                                                     | 1.4.5 (`mise.toml`, `packageManager`) |
| Language                    | TypeScript, strict                                                      | 5.9.3                                 |
| HTTP framework              | Hono                                                                    | 4.13.18                               |
| Authentication              | Better Auth with the two-factor plugin                                  | 1.7.25                                |
| ORM and migrations          | Drizzle ORM and drizzle-kit, `postgres` driver                          | 0.45.4, 0.31.11, 4.1.1                |
| Validation                  | zod                                                                     | 4.6.7                                 |
| UI                          | React, Vite, Tailwind CSS, Radix UI, lucide-react                       | 19.3.1, 8.3.8, 4.3.5                  |
| Agent                       | Go                                                                      | 1.25.1                                |
| Lint and format             | oxlint and oxfmt (oxc)                                                  | 1.93.0, 0.78.0                        |
| Browser tests               | Playwright                                                              | 1.65.1                                |
| Databases                   | PostgreSQL 17 (control plane), pgvector on PostgreSQL 17 (applications) | images pinned by digest               |
| Edge                        | Caddy 2.11.9 (custom rate-limit build), HAProxy 3.2.26, Tailscale       | images pinned by digest               |

Dependencies are recorded as exact versions (`bunfig.toml` sets `exact = true`) and all third-party images are pinned by readable version plus digest; see [Third-party image pins](../operating.md#third-party-image-pins).

## Coding conventions

- **Modules and imports.** Every package is ESM (`"type": "module"`). Relative imports include the `.ts` extension, and type-only imports use `import type` (`verbatimModuleSyntax`). Shared code is imported from `@ark-stack/shared`; the UI uses the `@/` alias for `web/src`.
- **Compiler settings.** `tsconfig.base.json` enables `strict`, `noUnusedLocals`, `noUnusedParameters` and `noFallthroughCasesInSwitch`. Each workspace and script group has its own `tsconfig.json` extending it, and `mise run typecheck` checks all of them.
- **Formatting.** oxfmt with double quotes, semicolons, trailing commas, two-space indentation and a 110-character line (`.oxfmtrc.json`). `dist/`, `server/drizzle/` and `bun.lock` are not formatted.
- **Linting.** oxlint with the `react`, `unicorn`, `typescript` and `import` plugins; correctness rules are errors and suspicious and performance rules warnings (`.oxlintrc.json`). CI denies warnings. `agent/`, `infra/` and `server/drizzle/` are ignored.
- **Validation and errors.** Routes parse input with zod; a `ZodError` becomes a 422 with a readable message. Expected failures throw Hono's `HTTPException` with a status and a sentence the UI can show; the error handler returns `{ "error": "..." }`.
- **Side effects go through operations.** Routes do not call providers, Docker or host files directly. They record desired state and `enqueue` an operation for the responsible worker, then audit it.
- **Secrets.** Secrets are encrypted with the root key, inventory APIs return metadata only, and log lines and evidence pass through `redactLogLine` and `redactValue`.
- **Comments cite the design.** Non-obvious code names the design section or ticket it implements (for example "front door §3.9.2, FD-11"), so readers can find the reasoning in `docs/design/front-door.md`.
- **Tests sit next to code** as `*.test.ts`. Database-backed tests refuse non-loopback databases and clean up what they create.
- **Docs are checked.** Pages under `docs/` must pass `mise run docs:check`, and every page must appear exactly once in `docs/nav.json` for the site build.

## Migrations

The control-plane schema is defined in `server/src/schema.ts` (Drizzle) and changed by plain SQL files in `server/drizzle/`, numbered `0000_init.sql` onwards. The numbering has gaps, and the files carry comments: many are written or edited by hand because they also backfill data or add constraints that a generated diff does not express.

`server/src/migrate.ts` is the runner. It creates an `ark_migrations` table if needed, then applies every `.sql` file in `server/drizzle` in file-name order whose name is not already recorded, recording each one as it goes. There is no down migration.

```sh
mise run db:generate   # drizzle-kit generate from server/src/schema.ts (server/drizzle.config.ts)
mise run db:migrate    # apply pending files to DATABASE_URL
```

To change the schema:

1. Edit `server/src/schema.ts`.
2. Run `mise run db:generate`, or write the next numbered SQL file by hand. Review it as SQL: it runs exactly as written on every existing installation.
3. Run `mise run db:migrate` locally, and `mise run test:upgrade` to check that an existing install upgrades in order. In production the `api` Compose service depends on the one-shot `migrate` service completing successfully, so `host:install` and signed maintenance apply pending migrations before the API starts.

`server/drizzle/` is excluded from formatting and linting.

## Adding an API route

All routes are registered in `server/src/app.ts` as `app.get`, `app.post`, `app.put`, `app.patch` or `app.delete` calls. The middleware chain already applies, in order: a 256 KiB body limit on `/api/*`; the host check (a request whose `Host` is not a registered Ark origin gets 421, and the gate login origin serves only its own paths); for every path except `/api/internal/*`, `/api/auth/*`, `GET /api/setup/status` and `GET /api/health`, a Better Auth session minted on the admin origin and a `platform_access` row (stored as `c.get("session")` and `c.get("access")`); and for mutations, a trusted `Origin` and an `application/json` content type.

A typical mutating route then:

1. Checks the role with `requireOperator(access)` or `requireOwner(access)`, and `requireMfa(session)`.
2. Parses the body with a zod schema.
3. Checks the target's scope (`requireProject`, `requireDomain`, `requireDatabaseAccess`).
4. For privileged actions, consumes a single-use step-up grant with `requirePrivileged(access, session, action, planHash)`. The UI obtains the grant from `POST /api/step-up`, bound to the request's plan hash.
5. Writes desired state and calls `enqueue({ kind, actorId, targetIds, payload })`.
6. Records `audit(actorId, action, resourceType, resourceId, detail, operationId, role)`.
7. Returns JSON, usually `{ operationId }`, which the UI follows on the Activity view.

`POST /api/services/:id/:action` is a compact example of the pattern. Add a test through the real app in `server/src` (see the existing `*.test.ts` files that sign in with Better Auth) and, if the route is documented, the docs check will verify the documented method and path against `app.ts`. The complete list of routes is in the [API reference](../reference/api.md).

## Adding an operation kind

1. Add the kind to the `OperationKind` union in `shared/src/operations.ts`. Use an existing prefix (`database.`, `domain.`, `edge.` and so on) when the kind belongs to an existing worker: prefixes decide which worker may run it.
2. Implement the handler in `server/src/coordinator.ts` and add it to `runOperation`. An unknown kind fails with `Unknown operation kind`. Handlers return evidence objects; record intermediate steps with the existing step helper and throw to fail the operation.
3. Make sure a worker identity is allowed to execute it: the `workerPrefixes` map in `server/src/app.ts` lists, per worker token, the prefixes or exact kinds it may claim, heartbeat and complete. The `module` identity (`ARK_INTERNAL_TOKEN`) and the embedded coordinator are separate paths; check both.
4. Enqueue it from a route or scheduler with `enqueue`. The idempotency key defaults to the kind, targets and payload hash, so a second request for the same work returns the in-flight operation instead of queuing a duplicate.
5. Add a coordinator test (`server/src/coordinator.test.ts` or a feature test), and update `server/src/app-boundary.test.ts` if the allowlists change.

## Adding a worker job or a worker

A worker polls only the kinds it names, and the API refuses a poll whose `x-ark-worker-kinds` list contains anything outside that worker's entry in `workerPrefixes` (403 "A valid worker job allowlist is required."). To route a new prefix to an existing worker, add it both to the worker's `runWorker(name, prefixes, executor)` call in `workers/src/` and to its `workerPrefixes` entry. Use a separate `runWorker` loop for long-running kinds so they cannot starve the rest, as the domain worker does for `integration.` and the IPv6 preflight, and the backup worker does for exports.

A new worker also needs its own token variable and identity in the `/api/internal/*` authentication middleware of `server/src/app.ts` and in `server/src/env.ts`, an entry point in `workers/src/` and a `workers/package.json` script, a Dockerfile target, a Bake target in `docker-bake.hcl` (and `imageTargets` in `scripts/check-image-plan.ts`), a Compose service, an installer-generated secret, and, if it should be monitored, a heartbeat alert. Those are deliberate review points: each worker has the narrowest network, mounts and credentials its jobs need.

## CI workflows

| Workflow                                                          | Trigger                                 | What it does                                                                                                                                                                                                                                                                                                                                        |
| ----------------------------------------------------------------- | --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.github/workflows/ci.yml` (`CI`)                                 | Every push and pull request, and weekly | Parallel jobs, gated by a final `CI` job: format, lint with warnings denied, typecheck, unit and DB-backed tests against a PostgreSQL service, Go tests with Docker integration, browser tests, every Docker harness except host hardening, the Bake plan check, a cold `--no-cache` build of every image, Dockerfile checks and Compose validation |
| `.github/workflows/publish-images.yml` (`Publish images`)         | Every push to `main`, manual dispatch   | Builds every Bake target natively for `linux/amd64` and `linux/arm64`, pushes them to GHCR and merges them into `<sha12>` and `latest` multi-platform tags that `host:install` pulls                                                                                                                                                                |
| `.github/workflows/ghcr-publish-check.yml` (`GHCR publish check`) | Manual dispatch                         | Checks the Bake plan and pushes, verifies and deletes one disposable GHCR package with the workflow token                                                                                                                                                                                                                                           |
| `.github/dependabot.yml`                                          | Weekly                                  | Grouped minor and patch updates for the Bun workspace (one root entry so `bun.lock` stays in step) and for GitHub Actions                                                                                                                                                                                                                           |

The CI jobs are described in [Testing](../development/testing.md#continuous-integration). Images for every commit on `main` are published by the `Publish images` workflow; see [Prebuilt images](../operations/maintenance-and-upgrades.md#prebuilt-images). Release tags are still published by hand with `mise run images:publish`.
