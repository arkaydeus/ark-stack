# Testing

This page describes every test suite in the repository: what each one covers, what it needs to run (Docker, a database, a tailnet, credentials), how to run a single file, what CI runs, and how the documentation check works.

## Overview

Ark's tests fall into five layers. Most of them run without any external account; only the opt-in live suites touch real providers.

| Layer                 | Runner                                   | Where                                                       | Needs                                       |
| --------------------- | ---------------------------------------- | ----------------------------------------------------------- | ------------------------------------------- |
| Unit and policy tests | `bun test`                               | `shared/src`, `workers/src`, `server/src/modules`, `tests/` | Nothing beyond Bun (some need OpenSSL 3)    |
| Database-backed tests | `bun test` with `DATABASE_URL`           | `server/src/*.test.ts`                                      | A migrated PostgreSQL                       |
| Go agent tests        | `go test`                                | `agent/*_test.go`                                           | Go; Docker for the integration test         |
| Browser tests         | Playwright (Chromium)                    | `e2e/*.spec.ts`                                             | Chromium; some need a database and Docker   |
| Docker harnesses      | `bun scripts/test-*.ts`                  | `scripts/`, `scripts/edge-test`, `scripts/backup-test`      | Docker                                      |
| Opt-in live suites    | `bun scripts/test-*-live.ts` and friends | `scripts/`, `server/src/vercel-live.test.ts`                | Real tailnet, VPS, S3 or Vercel credentials |

Test files are named `*.test.ts` and sit next to the code they test. Bun's test root is the repository root (`bunfig.toml`), so `bun test <path>` accepts any file or directory. A few server suites are split into a `*.test.ts` launcher and a `*.suite.ts` body (for example `server/src/http-route-controls.test.ts` and `server/src/http-route-controls.suite.ts`): the launcher creates its own database, migrates it and runs the suite in a child process, because the suite changes global state such as revoking every session.

## Quick reference

```sh
mise run check            # format check, lint, typecheck, unit tests
mise run test             # unit tests (needs .env and a migrated local database)
mise run test:db          # DB-backed server tests on a throwaway postgres:17.6 (Docker only)
mise run test:agent       # Go agent policy tests
mise run test:edge        # edge harnesses (Docker)
```

The full task list, with what each task needs, is in [Commands](../reference/commands.md#tests).

## Unit tests

`mise run test` runs:

```sh
bun --env-file=.env test shared server workers tests \
  scripts/publish-images.test.ts scripts/install-edge-auth.test.ts scripts/install-edge-l4.test.ts \
  scripts/edge-namespace.test.ts scripts/check-docs.test.ts ...
```

The exact file list is in `mise.toml`; it also includes the docs site generator's tests.

What the directories cover:

- **`shared/src`**: the pure planners and policies the server, workers and agent rely on: DNS plans, Compose policy and canonicalisation, the Caddy and HAProxy renderers (`edge.test.ts`, `edge-http.test.ts`, `edge-l4.test.ts`, `edge-l4-routes.test.ts`, `edge-pg5432.test.ts`), withdrawal (`edge-withdrawal.test.ts`), the login gate, PgBouncer and pooler policy, database clients, backup targets, tailnet ACL generation and observation, operation state transitions (`operations.test.ts`), region settings and install helpers. These need no database or network.
- **`server/src/modules`**: module-level tests such as the private CA (`pki.test.ts`), CSR parsing hardening (`x509-csr-malformed.test.ts`, the bounded DER fuzz in `csr-fuzz.test.ts` and the OpenSSL differential test in `csr-openssl.test.ts`), PgBouncer planning and reloads, the backup canary, providers and alerts.
- **`server/src`**: route and lifecycle tests through the real Hono app, Better Auth sessions, step-up grants and the coordinator, against `DATABASE_URL`. Examples are `coordinator.test.ts`, `front-routes.test.ts`, `l4-routes.test.ts`, `pg5432.test.ts`, `db-clients.test.ts`, `db-client-rollover.test.ts`, `offsite-backups.test.ts`, `backup-observe.test.ts`, `edge-observe.test.ts` (against a mocked LocalAPI on a real unix socket, `server/src/mock-localapi.ts`) and `app-boundary.test.ts` (worker identities and their job allowlists).
- **`workers/src`**: the worker runtime's claim, heartbeat and completion contract (`runtime.test.ts`), the HAProxy validator, the pgBackRest executor, the proxy watchdog and its configuration.
- **`tests/security`**: static checks over shipped manifests and code: that `pgbackrest expire` never runs on the VPS (`backup-no-expire.test.ts`), the edge Tailscale node's Compose shape (`edge-ts.test.ts`), the host firewall and provider rules, the PgBouncer bootstrap and public listener, authorisation and Compose policy guards (project scope, host path escapes, Docker socket mounts, Funnel disabled, owners never imported) and the tailnet ACL audit and validation script.
- **`tests/browser/flows.test.ts`**: high-risk HTTP flows through the app (setup status is public, state needs a session, and so on). It also checks the built `index.html` in the UI's `dist` folder, so build the UI first (`mise run build` or `bun run --cwd web build`).
- **`tests/ipv6-preflight-probe.test.ts`**: the external IPv6 probe.
- **The listed `scripts/*.test.ts` files**: the image publisher, the installer's edge auth-key and edge-l4 steps, the edge namespace rejoin, the docs checker, the guided setup (`scripts/host-setup.test.ts`: every step against a simulated host whose system commands are stubs, including the Tailscale SSH gate, resume after a failure, closing public SSH with rollback, the provider firewall adapters and secret redaction) and the `install.sh` bootstrap (`scripts/install-sh.test.ts`: stubbed commands on an isolated `PATH`, refusals, truncated downloads and the apt and checkout paths).

### What the unit run needs

- **`.env`.** The task passes `--env-file=.env`. Database-backed test files also load `.env` themselves when `DATABASE_URL` is unset.
- **A migrated database.** The `server` suites connect to `DATABASE_URL`. Locally, that is the dev cluster from `mise run db:up` and `mise run db:migrate`. Several suites refuse anything but a loopback host and create and drop their own uniquely named databases inside it.
- **OpenSSL 3 or newer.** PKI and CSR tests use OpenSSL as an independent verifier and never fall back to macOS LibreSSL. `server/src/modules/test-openssl.ts` looks for `ARK_OPENSSL_BIN`, `openssl` on `PATH`, then the Homebrew `openssl@3` paths, and fails with "Tests require OpenSSL 3 or newer" otherwise.
- **The built UI**, for `tests/browser/flows.test.ts`. The broad unit selection includes both the browser HTTP flows and the IPv6 PostgreSQL probe. Export a disposable, migrated connection from `mise run test:db:up` before running the selection, even when it excludes the `server/` directory.

> [!TIP]
> If you do not want the unit run to touch your dev database, use `mise run test:db` for the `server` suites instead. It needs only Docker.

## Database-backed tests on a throwaway PostgreSQL

`mise run test:db` (`scripts/test-db.ts`) gives the DB-backed tests a clean, private database. It needs only Docker: no `.env` and no `mise run db:up`.

- It starts a uniquely named `postgres:17.6` container (pinned by digest, data on tmpfs, labelled `ark-stack.test-db`) on a loopback port Docker picks.
- It applies the migrations as the owner role `ark_migration`, as production migrations do, because test cleanup deletes `audit_events` rows that the runtime role may not.
- It runs `bun test server` with fixed test-only secrets. Your `.env` is never read, and only `PATH`, `HOME`, `TMPDIR`, `TMP`, `TEMP`, `SystemRoot`, `LANG`, `LC_ALL` and `TZ` pass through from the host environment.
- It removes the container afterwards, also on failure or interruption. A cleanup failure returns a nonzero status. Only containers carrying its label are ever removed, and the shared `ark-platform` Compose project is never touched, so concurrent runs do not collide.

Pass other `bun test` arguments to run something else:

```sh
mise run test:db -- server/src/coordinator.test.ts
mise run test:db -- server/src/front-routes.test.ts -t "withdrawal"
```

To keep a database for repeated runs:

```sh
eval "$(mise run test:db:up)"          # exports DATABASE_URL and defines ark_test_db
ark_test_db server/src/coordinator.test.ts
mise run test:db:down <container>      # the exact command is printed by test:db:up
```

The `ark_test_db` helper runs `bun --no-env-file test` from the repository root under `env -i`, so follow-up tests are isolated from your shell's provider settings as well. `test:db:down` removes only a container carrying the harness label, and fails if the named container is absent.

`scripts/test-db.test.ts` tests the harness itself. Its two Docker cases (two concurrent real databases with distinct ports and data, and that inherited providers or native tools cannot leak into alert and backup tests) run only with `ARK_TEST_DB_DOCKER=1`, as CI does.

## Go agent tests

```sh
mise run test:agent               # go test ./... in agent/ (same as mise run agent:test)
mise run test:agent-integration   # the disposable Docker deployment test
```

`agent/policy_test.go` checks the Compose policy: the Docker socket and privileged mode are refused, reserved and ambiguous ports are refused, interpolation, aliases, duplicate keys and unsupported fields are refused, images must be digest-pinned, the canonical sandbox must be present, named host binds and external control resources are refused, and workload project names are validated. `agent/docker_test.go` covers adoption isolation checks and bounded, redacted log results.

`agent/integration_test.go` (`TestDisposableDockerDeploymentAndDurableLedger`) deploys, inspects, restarts and removes a pinned workload on a disposable Docker project and checks the durable ledger. It skips unless `ARK_DOCKER_INTEGRATION=1`. Run it only against a Docker daemon you can afford to have containers created on.

The custom Caddy build has its own Go test, `infra/edge-caddy/ratelimit-budget_test.go`, which the `edge-caddy-build` stage of the `Dockerfile` runs while building the patched rate-limit plugin; a failing test fails the image build.

## Browser tests

Playwright is configured in `playwright.config.ts`: specs in `e2e/`, one worker, no retries, traces kept on failure, and a base URL from `ARK_E2E_BASE_URL` (default `http://127.0.0.1:3199`). Install Chromium once with `bunx playwright install chromium`.

There are four kinds of spec:

- **UI-only specs** (`e2e/front-acl.spec.ts`, `e2e/gate-users.spec.ts`, `e2e/front-controls.spec.ts`, `e2e/dns-review.spec.ts`, `e2e/vercel-rollover.spec.ts`) start their own Vite dev server on the current `web/` source and answer the API with Playwright route stubs, including deliberately delayed responses. They need no database or API and can be run directly:

  ```sh
  bunx playwright test e2e/front-acl.spec.ts
  ```

- **Onboarding** (`e2e/onboarding.spec.ts`) needs the harness below, which supplies a setup token, owner password and domain.
- **The login gate** (`e2e/gate.spec.ts`) runs only through its own harness and is skipped in the regular run.
- **Documentation site** (`bunx playwright test e2e/docs-site.spec.ts`) starts the local static preview and exercises search failure and retry, keyboard selection, the mobile sidebar and lazy Mermaid loading. It uses controlled browser routes, so it needs Chromium and Bun but no database or CDN access.

### `test:e2e`

`mise run test:e2e` (`scripts/test-e2e.ts`) refuses a non-loopback `DATABASE_URL`, creates a uniquely named disposable database, migrates it from empty and starts the API on a random local port with generated secrets, `ARK_DNS_STUB=1` and embedded workers off. It then runs every Playwright spec. Onboarding drives Chromium through owner creation, pre-MFA denial, invalid and valid TOTP, recovery-code acknowledgement, custom-domain setup, region settings and one-time recovery-code use. The database is dropped afterwards.

### `test:e2e-gate`

`mise run test:e2e-gate` (`scripts/test-e2e-gate.ts`, FD-11) runs the real API on the host against a disposable database, and the shipped edge (`edge-ts`, Caddy behind its launch guard, HAProxy) in a disposable Compose project, with the edge watchdog and a fake tailnet upstream. Chromium reaches the edge through a local CONNECT proxy, so hostnames, SNI and `__Host-` cookies are what a browser sees in production. `e2e/gate.spec.ts` checks the login-origin redirect, password and TOTP, the host-only route cookie, the identity header the upstream receives, that a gate user created in Ark must enrol TOTP before the route opens, sign-out from the rendered pages, and that revocation closes an authenticated WebSocket. It needs Docker, a loopback `DATABASE_URL` and Chromium.

## Docker harnesses

These run real images in disposable Docker resources and clean up after themselves. None needs external credentials. Several need a disposable loopback `DATABASE_URL`: `test:e2e`, `test:e2e-gate`, `test:upgrade`, `test:pgbouncer` and the observer and database-backed checks in `test:edge`. Run them one at a time against a database from `test:db:up`:

```sh
db_setup=$(mise run test:db:up) || exit 1
eval "$db_setup"
touch .env                    # tasks that pass --env-file=.env need the file to exist
mise run test:e2e-gate        # or test:e2e, test:upgrade, test:pgbouncer, test:edge
mise run test:db:down <container>
```

| Task                     | Scripts                                                                                                                                                                                                                                                                                                                                               | What it proves                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `test:edge`              | `bun test scripts/edge-test scripts/edge-l4-guard.test.ts scripts/maintain.test.ts`, then `scripts/test-edge-config.ts`, `scripts/test-db-ingress.ts`, `scripts/test-edge-observer.ts`, `scripts/test-edge-l4.ts`, `scripts/test-edge-l4-routes.ts`, `scripts/test-edge-pg5432.ts`, `scripts/test-edge-gate.ts`, `scripts/test-edge-http-controls.ts` | Harness cleanup and image pins; every rendered and static Caddyfile validated on the pinned Caddy; header stripping, WebSockets across reloads and served certificates; public port nftables rules; LocalAPI read-only access and route withdrawal on identity change; HAProxy SNI routing, TLS-TCP and raw-TCP routes; the PostgreSQL router on 5432 with PgBouncer and Postgres routes; gate routing, Origin contract and revocation; HTTP route rate limits (429) and HTTP mTLS refusals in the TLS handshake on the custom Caddy build |
| `test:db-ingress`        | `bun test shared/src/db-ingress.test.ts`, `scripts/test-db-ingress.ts`                                                                                                                                                                                                                                                                                | The public port policies in isolated network namespaces: rule syntax, live sockets on the input and DNAT paths, reconciler acknowledgements, fail-closed recovery, counters and the Prometheus alert rules. Needs privileged containers                                                                                                                                                                                                                                                                                                    |
| `test:pgbouncer`         | `scripts/test-pgbouncer-public.ts`                                                                                                                                                                                                                                                                                                                    | The real `app-postgres` and `pgbouncer-public` services: closed bootstrap, rendered INI/HBA/userlist/CA bundle loaded by `RELOAD` over the admin socket, the mTLS matrix, SCRAM, transaction-mode prepared statements, certificate swap, reload-failure retries, database clients (connect, read-only preview, revoke) and certificate rollover. `ARK_PGBOUNCER_SMOKE_PORT` overrides the ephemeral port                                                                                                                                   |
| `test:backups`           | `tsc` on `scripts/tsconfig.backups.json`, `scripts/backup-test/provider-policies.test.ts`, `scripts/offsite-restore.test.ts`, `scripts/test-backups.ts`                                                                                                                                                                                               | Off-VPS backups (FD-21) against a pinned MinIO and the real cluster services: append-only policy classes, the emulated R2 lock recipe, the deployed backup worker, file restores and full PITR of both clusters from the bucket alone                                                                                                                                                                                                                                                                                                      |
| `test:backups-tailnet`   | `scripts/backup-test/tailnet-compose.test.ts`, `scripts/test-backups-tailnet.ts`                                                                                                                                                                                                                                                                      | Home-machine backups (FD-30) through the shipped `backup-ts` on a simulated tailnet with `rest-server --append-only --private-repos`: LocalAPI denial, identity pinning, REST only through SOCKS5, transfers stopped on identity change, two-destination health                                                                                                                                                                                                                                                                            |
| `test:host-hardening`    | `scripts/test-host-hardening.ts`                                                                                                                                                                                                                                                                                                                      | FD-20 in an isolated Ubuntu systemd guest with its own Docker daemon, nftables, Stalwart and an external scanner                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `test:ipv6-preflight`    | `mise run test:db scripts/ipv6-preflight-test/preflight.test.ts`                                                                                                                                                                                                                                                                                      | FD-27 on IPv4-only and dual-stack Docker networks with a disposable VPS, PostgreSQL and Pebble                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `test:install-bootstrap` | `scripts/test-install-bootstrap.ts`                                                                                                                                                                                                                                                                                                                   | Disposable Linux containers exercise real apt installs and reruns on Ubuntu 22.04, 24.04 and 26.04, standalone runtime refusal, the Compose-plugin repair, shared deployment locks, and fresh OpenSSH connections through nftables before and after rollback. Needs Docker with network namespace support and network access.                                                                                                                                                                                                              |
| `test:upgrade`           | `scripts/test-upgrade-migrations.ts`                                                                                                                                                                                                                                                                                                                  | A database seeded at an early schema with legacy users, accounts and sessions is upgraded through the later migrations in order; existing password hashes still sign in, legacy sessions are backfilled, and the startup nft policy is activated                                                                                                                                                                                                                                                                                           |
| `test:stalwart`          | `scripts/test-stalwart-integration.ts`                                                                                                                                                                                                                                                                                                                | Native mail lifecycle (mailboxes, aliases, devices) against a disposable Stalwart pinned by digest. The task unsets `STALWART_URL`, `STALWART_ADMIN_ADDRESS` and `STALWART_ADMIN_PASSWORD` so it never reaches a real engine                                                                                                                                                                                                                                                                                                               |

> [!NOTE]
> On Linux CI runners, the edge harnesses need the legacy IPv6 netfilter tables loaded on the host (`sudo modprobe -a ip6_tables ip6table_filter ip6table_nat ip6table_mangle`), because `tailscaled` in `edge-ts` uses the image's legacy `ip6tables` and a container cannot load kernel modules. Docker Desktop needs no extra step.

`test:pgbouncer` picks an ephemeral loopback port for the public listener unless `ARK_PGBOUNCER_SMOKE_PORT` sets one. It uses the same migrated platform test database as the unit suite, so run it after the unit run rather than at the same time. The PgBouncer runtime probes it bundles (`scripts/pgbouncer-*-probe.ts`) have their own TypeScript project, `scripts/tsconfig.pgbouncer.json`, which `mise run typecheck` and CI check.

The edge test helpers live in `scripts/edge-test/` (Compose stack, runtime cleanup, TLS and TCP echo servers, a fake gate API and upstream, image pins) and the backup helpers in `scripts/backup-test/` (MinIO, restic wrappers, the tailnet Compose fixture). The image pins every harness uses are checked by `scripts/edge-test/pins.test.ts`; the bump procedure is in [Third-party image pins](../operating.md#third-party-image-pins).

## Opt-in live suites

These need real accounts, so CI never runs them. Each prints a skip message and exits 0 unless its variables are set. Use scratch accounts, pass credentials only through the environment and revoke them afterwards.

| Suite                       | Run                                                     | Gate variable(s)                                         |
| --------------------------- | ------------------------------------------------------- | -------------------------------------------------------- |
| Edge node on a tailnet      | `mise run test:edge-tailnet`                            | `ARK_TEST_TS_EDGE_AUTHKEY`                               |
| Tailnet ACL snippet         | `mise run test:tailnet-acl`                             | `ARK_TEST_TS_POLICY_API_KEY`                             |
| Home backup on a tailnet    | `mise run test:backups-tailnet-live`                    | `ARK_TEST_TS_BACKUP_AUTHKEY`, `ARK_TEST_TS_HOME_AUTHKEY` |
| Hosted S3                   | `mise run test:backups-hosted`                          | `ARK_TEST_S3_PROVIDER` and the other `ARK_TEST_S3_*`     |
| Real VPS hardening          | `mise run test:host-hardening-live`                     | `ARK_TEST_VPS_*`                                         |
| IPv6 preflight, live        | `mise run test:ipv6-preflight-live`                     | `ARK_TEST_IPV6_*`                                        |
| One-command installer, live | `mise run test:install-live`                            | `ARK_TEST_INSTALL_*`                                     |
| Vercel scope proof          | `bun --no-env-file test server/src/vercel-live.test.ts` | `ARK_TEST_VERCEL_*`                                      |
| GHCR publishing             | the manual `GHCR publish check` workflow                | `GHCR_TOKEN`, `GHCR_USER`                                |

The complete variable lists and what each suite covers are in [Opt-in live test suites](../operating.md#opt-in-live-test-suites). Record the redacted output of a live run in the pull request or in `docs/fix1-verification.md`.

## Running a single test

| What                     | Command                                                                     |
| ------------------------ | --------------------------------------------------------------------------- |
| One pure unit file       | `bun test shared/src/edge-http.test.ts`                                     |
| One test by name         | `bun test shared/src/operations.test.ts -t "illegal operation transitions"` |
| One DB-backed file       | `mise run test:db -- server/src/coordinator.test.ts`                        |
| Repeated DB-backed runs  | `eval "$(mise run test:db:up)"`, then `ark_test_db <file>`                  |
| One Go test              | `cd agent && go test -run TestRejectsReservedPort ./...`                    |
| One UI-only browser spec | `bunx playwright test e2e/gate-users.spec.ts`                               |
| One edge harness         | `bun scripts/test-edge-l4.ts`                                               |

Add `--watch` to `bun test` to rerun on change.

## Continuous integration

`.github/workflows/ci.yml` runs one `verify` job on `ubuntu-24.04` (30-minute timeout) on every push and pull request, and weekly on Mondays at 03:17 UTC. It uses a `postgres:17.6` service container pinned by digest and fixed CI-only secrets for every required variable. It does not call mise; the steps are, in order:

1. Install Bun 1.4.2 and Go 1.25.1, `bun install --frozen-lockfile`, `touch .env`, and migrate the service database.
2. `bunx oxfmt --check .`, `bunx oxlint . --deny-warnings`, and `tsc --noEmit` for every workspace and script project.
3. `scripts/test-db.test.ts` with `ARK_TEST_DB_DOCKER=1`.
4. Install `postgresql-client` and `openssl`, build the UI, then the unit run (`bun test shared server workers tests ...`), which includes the bounded DER fuzz and the OpenSSL CSR differential tests, then the `install.sh` container check (`scripts/test-install-bootstrap.ts`).
5. `ARK_DOCKER_INTEGRATION=1 go test ./...` in `agent/`.
6. Install Chromium, `bunx playwright test e2e/vercel-rollover.spec.ts e2e/docs-site.spec.ts`, then `scripts/test-e2e.ts`, `scripts/test-upgrade-migrations.ts`, the Stalwart integration and `scripts/test-pgbouncer-public.ts`.
7. Load the legacy IPv6 netfilter tables, then every `test:edge` step, `scripts/test-db-ingress.ts`, the native IPv6 preflight (`scripts/install-docker-ipv6.test.ts` and `scripts/ipv6-preflight-test/preflight.test.ts` through `scripts/test-db.ts`), `scripts/test-e2e-gate.ts`, and both backup suites.
8. `scripts/check-image-plan.ts`, a `--no-cache` `docker buildx bake` of every image, `docker build --check` for the root and agent Dockerfiles, `docker compose config --quiet` for the platform (with and without the dev override), mail and monitoring manifests, and a `docker compose up --wait` of the two PostgreSQL services.

`.github/workflows/ghcr-publish-check.yml` is dispatched manually. It checks the Bake plan and runs `scripts/test-ghcr-publish.ts` with the workflow's token. Dependabot (`.github/dependabot.yml`) opens weekly grouped updates for the Bun workspace and for GitHub Actions.

`test:host-hardening` and the opt-in live suites are the only suites that CI does not run.

## The documentation check

`mise run docs:check` (`bun scripts/check-docs.ts`) keeps the docs honest. It reads the published pages from `docs/nav.json`, including the README, guides and nested pages, and verifies:

- relative links resolve to a file in the repository and `#anchors` to a heading in it, using GitHub's heading slugs;
- backticked repository paths exist (anything under `docs/`, `scripts/`, `server/`, `shared/`, `workers/`, `web/`, `infra/`, `tests/`, `e2e/`, `agent/`, `templates/`, `.github/`, and root files such as `mise.toml` and `Dockerfile`); a `:line` suffix, globs and `<placeholders>` are allowed;
- every `mise run <task>`, including inside code blocks, names a task in `mise.toml`;
- inline `METHOD /api/...` spans and requests in `http` code blocks are routes registered in `server/src/app.ts` (Better Auth's `/api/auth/*` is exempt);
- backticked environment variables with the `ARK_`, `TS_`, `BETTER_AUTH_`, `DNS_API_`, `GHCR_` and `STALWART_` prefixes occur in tracked source;
- ports written as `TCP n`, `UDP n`, `port n` or a backticked `:n` occur in tracked source.

The archived front-door design and first Fable review get structural checks for links, paths and tasks. The original implementation plan retains exceptions for its external source citations and proposed directory layout. Files that are not yet committed are accepted, so a new page can link to another new page in the same change.

The check also runs as a unit test: `scripts/check-docs.test.ts` tests the slug, anchor and route-matching rules and asserts that the real repository has no drift, so `mise run test` and CI fail on a broken link or a renamed endpoint. Format docs with `bunx oxfmt <file>` like code.
