# Commands

This page lists every mise task in `mise.toml`, grouped by purpose, with what each one runs and what it needs, followed by the standalone scripts that are run directly with `bun`.

## How tasks run

All project commands are mise tasks. `mise.toml` pins the toolchain (`bun` 1.4.2 and `go` 1.25.1), so `mise install` (or `mise run setup`) gives every machine the same versions. Run `mise trust` once in a fresh checkout so mise will read the file.

```sh
mise tasks              # list every task with its description
mise run <task>         # run one
mise run test:db -- server/src/coordinator.test.ts   # pass arguments to a task
```

Three details affect how a task behaves:

- **Environment.** Some tasks load the root `.env` through mise (`env = { _.file = ".env" }`): `dev`, `dev:server`, `dev:web`, `start`, `db:generate`, `db:migrate`, `db:studio`, `recover` and `host:install`. Others pass it to Bun with `bun --env-file=.env`: `test`, `test:e2e`, `test:e2e-gate`, `test:upgrade`, `recover:mfa`, `import`, `recover-host`, `maintain` and `edge:rejoin`. The disposable-database and host-hardening harnesses deliberately run with `bun --no-env-file` so a developer's real secrets never reach tests. Create `.env` with `cp .env.example .env`; `touch .env` is enough for harnesses that take their settings from shell exports.
- **Arguments.** Tasks marked `raw_args` in `mise.toml` pass every following argument through unchanged, flags included: `install`, `test:db`, `test:db:down`, `recover`, `recover:mfa`, `images:publish`, `images:pin-edge-caddy`, `host:install`, `host:audit`, `import`, `maintain`, `docs:build` and `docs:serve`. That is why `sudo mise run host:install --harden-vps` works without `--`.
- **Working directory.** `test:agent`, `test:agent-integration`, `agent:test` and `agent:build` run in `agent/`. Everything else runs from the repository root.

## Setup and dependencies

| Task      | Runs                                     | Needs                |
| --------- | ---------------------------------------- | -------------------- |
| `setup`   | `mise install` then `bun install`        | mise; network access |
| `install` | `bun install` (arguments passed through) | bun                  |

`bunfig.toml` sets `exact = true`, so `bun add` records exact versions. The repository is one Bun workspace (`shared`, `server`, `web`, `workers`) with a single root `bun.lock`; CI installs with `bun install --frozen-lockfile`.

## Local development

| Task         | Runs                                                     | Needs                                            |
| ------------ | -------------------------------------------------------- | ------------------------------------------------ |
| `dev`        | API with embedded workers and the Vite UI together       | `.env`; local PostgreSQL (`db:up`, `db:migrate`) |
| `dev:server` | Only the Hono API (and embedded workers), with `--watch` | `.env`; local PostgreSQL                         |
| `dev:web`    | Only the Vite administration UI                          | `.env`; an API on `127.0.0.1:3000` for `/api`    |
| `start`      | The API serving the built UI from the `web` build output | `.env`; `mise run build` first                   |
| `build`      | `mise run typecheck`, then `vite build` of the UI        | dependencies installed                           |

`mise run dev` runs the `web` workspace's `dev` script, which starts `bun run --cwd ../server dev` and `vite` side by side with `concurrently`. Vite listens on `port 5173` and proxies `/api` to the API on `port 3000`. With `.env.example` defaults, `ARK_EMBEDDED_WORKERS=1` runs the coordinator inside the API process and `ARK_DNS_STUB=1` accepts expected DNS records without public lookups. See [local development](../getting-started/local-development.md) for the full walkthrough.

## Local database

| Task          | Runs                                                                                                  | Needs                      |
| ------------- | ----------------------------------------------------------------------------------------------------- | -------------------------- |
| `db:up`       | `docker compose` up of `postgres` and `app-postgres` from the platform manifest plus the dev override | Docker                     |
| `db:down`     | `docker compose ... down` for the same files                                                          | Docker                     |
| `db:migrate`  | `server/src/migrate.ts`: applies pending `server/drizzle/*.sql` files                                 | `.env` with `DATABASE_URL` |
| `db:generate` | `drizzle-kit generate` from `server/src/schema.ts` into `server/drizzle`                              | `.env`                     |
| `db:studio`   | `drizzle-kit studio`                                                                                  | `.env`; a running database |

The dev override `infra/platform/docker-compose.dev.yml` binds the control-plane cluster to `127.0.0.1:5433` and the application cluster to `127.0.0.1:5434`. The production manifest has no host binding for either. Migrations are described in [Repository](../development/repository.md).

## Code quality

| Task           | Runs                                                                              |
| -------------- | --------------------------------------------------------------------------------- |
| `check`        | `format:check`, `lint`, `typecheck` and `test`, in that order                     |
| `format`       | `bunx oxfmt .`                                                                    |
| `format:check` | `bunx oxfmt --check .`                                                            |
| `lint`         | `bunx oxlint .`                                                                   |
| `lint:fix`     | `bunx oxlint --fix .`                                                             |
| `typecheck`    | `bunx tsc --noEmit` for each workspace and each `scripts/tsconfig.*.json` project |

`typecheck` covers `shared`, `server`, `web` and `workers`, plus the script projects for the image publisher (`scripts/tsconfig.publish.json`), the PgBouncer probes (`scripts/tsconfig.pgbouncer.json`), the disposable test database (`scripts/tsconfig.test-db.json`), the backup harnesses (`scripts/tsconfig.backups.json`) and the docs check and site generator (`scripts/tsconfig.docs.json`). CI runs `oxlint` with `--deny-warnings`, which `mise run lint` does not.

## Documentation

| Task         | Runs                                   | Notes                                                                     |
| ------------ | -------------------------------------- | ------------------------------------------------------------------------- |
| `docs:check` | `bun scripts/check-docs.ts`            | Fails on any documentation drift                                          |
| `docs:build` | `bun scripts/docs-site/build.ts build` | Writes the static site to `dist/docs`, or `--out dir`                     |
| `docs:serve` | `bun scripts/docs-site/build.ts serve` | Serves on `http://127.0.0.1:4321/` (or `--port n`) and rebuilds on change |

What the docs check verifies is described in [Testing](../development/testing.md).

## Tests

Each test task is described in depth, with its prerequisites, in [Testing](../development/testing.md). This table is the quick reference.

### Unit and database-backed tests

| Task                     | Runs                                                                                                      | Needs                                                                    |
| ------------------------ | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `test`                   | `bun test` over `shared`, `server`, `workers`, `tests` and selected script tests                          | `.env`; migrated local database; OpenSSL 3; built UI for `tests/browser` |
| `test:db`                | `scripts/test-db.ts`: throwaway migrated `postgres:17.6`, then `bun test server` (or the given arguments) | Docker only                                                              |
| `test:db:up`             | Starts and migrates one throwaway database and prints shell exports plus an `ark_test_db` helper          | Docker                                                                   |
| `test:db:down`           | Removes a container that `test:db:up` started (`mise run test:db:down <container>`)                       | Docker                                                                   |
| `test:agent`             | `go test ./...` in `agent/`                                                                               | Go                                                                       |
| `agent:test`             | The same as `test:agent`                                                                                  | Go                                                                       |
| `test:agent-integration` | `ARK_DOCKER_INTEGRATION=1 go test -run TestDisposableDockerDeploymentAndDurableLedger`                    | A disposable Docker daemon                                               |

### Docker harnesses

These need Docker and no external credentials.

| Task                   | Covers                                                                                                          | Also needs                                                                 |
| ---------------------- | --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `test:e2e`             | Fresh-volume browser onboarding in Chromium                                                                     | `.env`; loopback `DATABASE_URL`; Playwright Chromium                       |
| `test:e2e-gate`        | The login gate end to end through the containerised edge (FD-11)                                                | `.env`; loopback `DATABASE_URL`; Playwright Chromium                       |
| `test:upgrade`         | Schema upgrade and startup nft policy activation                                                                | `.env`; loopback `DATABASE_URL`                                            |
| `test:stalwart`        | Native mail lifecycle against a pinned Stalwart container                                                       | Unsets `STALWART_URL`, `STALWART_ADMIN_ADDRESS`, `STALWART_ADMIN_PASSWORD` |
| `test:edge`            | Edge harness, Caddy configs, HAProxy, observer, L4 routes, 5432 router, gate routing, HTTP rate limits and mTLS | Loopback `DATABASE_URL` for the observer and database-backed checks        |
| `test:db-ingress`      | Public port nftables rules, fail-closed recovery, counters and alerts                                           | Privileged containers                                                      |
| `test:pgbouncer`       | Public PgBouncer mTLS, SCRAM, reloads, database clients and rollover                                            | Loopback `DATABASE_URL` (migrated)                                         |
| `test:backups`         | Off-VPS backups against MinIO, including full PITR (FD-21)                                                      | —                                                                          |
| `test:backups-tailnet` | Home-machine backups through `backup-ts` on a simulated tailnet (FD-30)                                         | —                                                                          |
| `test:host-hardening`  | VPS hardening (FD-20) in isolated containers with an external scanner                                           | —                                                                          |
| `test:ipv6-preflight`  | IPv6 and AAAA preflight on IPv4-only and dual-stack networks (FD-27)                                            | — (runs through `test:db`)                                                 |

### Opt-in live suites

Each prints a skip message and exits 0 unless its credentials are set. CI never runs them. The required variables are listed in [Opt-in live test suites](../operating.md#opt-in-live-test-suites).

| Task                        | Against                                                             |
| --------------------------- | ------------------------------------------------------------------- |
| `test:edge-tailnet`         | A real test tailnet (`ARK_TEST_TS_EDGE_AUTHKEY`)                    |
| `test:tailnet-acl`          | Tailscale's policy validate endpoint (`ARK_TEST_TS_POLICY_API_KEY`) |
| `test:backups-tailnet-live` | A real home `rest-server` over a tailnet                            |
| `test:backups-hosted`       | AWS S3, Backblaze B2 or Cloudflare R2 (`ARK_TEST_S3_*`)             |
| `test:host-hardening-live`  | A scratch VPS and scratch tailnet                                   |
| `test:ipv6-preflight-live`  | A scratch VPS and Let's Encrypt staging                             |

## Host install and operation

| Task           | Runs                                                          | Needs                                                                  |
| -------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `host:install` | `scripts/install.ts`                                          | Docker; `.env` (created and filled if missing); root on a hardened VPS |
| `host:audit`   | `scripts/host-audit.ts`                                       | Root on the VPS; Nmap for `--external`                                 |
| `mail:up`      | `scripts/install-mail-submission.ts`                          | Docker                                                                 |
| `monitor:up`   | `docker compose -f infra/monitoring/docker-compose.yml up -d` | Docker                                                                 |
| `maintain`     | `scripts/maintain.ts`                                         | `.env`; `ARK_MAINTENANCE_TOKEN`; `ARK_RELEASE_PUBLIC_KEY`              |
| `edge:rejoin`  | `scripts/edge-namespace.ts`                                   | `.env`; Docker                                                         |

`host:install` accepts no arguments, or exactly one of `--enroll-vps` and `--harden-vps`; anything else is rejected with `Usage: host:install [--enroll-vps | --harden-vps]`. Without a flag it generates missing secrets (existing `.env` values are kept), builds the images, runs the `migrate` service and starts the platform, the pinned Stalwart engine (unless `ARK_MAIL_ENABLED=0`) and Prometheus. `--enroll-vps` only joins the VPS to the tailnet as `tag:ark-vps` from the key file named by `TS_VPS_AUTHKEY_FILE`, then exits. `--harden-vps` runs the install as a hardened host: it also installs the `ark_host` nftables baseline and the unattended-upgrades configuration. Once a host is hardened, later runs without a flag are treated as hardened too. The order of the phases is in [VPS hardening](../operating.md#vps-hardening) and [production install](../getting-started/production-install.md).

`host:audit` takes no arguments (local audit of nftables, `ss` and Docker publications), `--inventory` (print the expected inbound rules as JSON) or `--external INVENTORY.json IP [IP...]` (scan the VPS from another machine). See [Provider firewall and audit](../operating.md#provider-firewall-and-audit).

`mail:up` starts the Stalwart engine and ensures STARTTLS submission on `TCP 587`. `monitor:up` starts Prometheus with 14-day retention; see [Monitoring](../features/monitoring.md).

`maintain` takes an optional bundle path and Compose path (defaults `infra/platform/release.json` and `infra/platform/docker-compose.yml`). It verifies the Ed25519 signature against `ARK_RELEASE_PUBLIC_KEY`, the exact Compose digest and image set, journals the approval to `ARK_MAINTENANCE_JOURNAL` (default `tmp/maintenance.jsonl`) and prints the planned Compose command. It only pulls and applies when `ARK_MAINTENANCE_EXECUTE=1`. See [Maintenance and upgrades](../operations/maintenance-and-upgrades.md).

`edge:rejoin` recreates `edge` and `edge-l4` when `edge-ts` was restarted or replaced under them, so both share the live Tailscale node's network namespace again. `maintain` runs the same step.

## Recovery and import

| Task           | Runs                      | Needs                                      |
| -------------- | ------------------------- | ------------------------------------------ |
| `recover`      | `server/src/cli.ts`       | `.env` with `DATABASE_URL`                 |
| `recover:mfa`  | `scripts/recover-mfa.ts`  | `.env`; the `ARK_MFA_RECOVERY_TOKEN` value |
| `recover-host` | `scripts/recover-host.ts` | `.env`                                     |
| `import`       | `scripts/import.ts`       | `.env`; an inventory JSON file             |

`recover` has four subcommands: `help` (the default), `status` (bootstrap state, user count and whether a setup token is configured; read-only), `owners` (platform owners and their roles) and `reset-setup`, which reopens first-run setup only when no users exist and prints a suggested token.

```sh
mise run recover -- status
mise run recover:mfa -- owner@example.com RESET:owner@example.com "$ARK_MFA_RECOVERY_TOKEN"
mise run recover-host
mise run import -- inventory.json
```

`recover:mfa` needs the owner's email, the literal confirmation `RESET:<email>` and the recovery token; it revokes every session and step-up grant before re-enrollment. `recover-host` prints which recovery inputs are present (`ARK_ROOT_KEY`, `DATABASE_URL`, `BETTER_AUTH_SECRET`, `ARK_SETUP_TOKEN`), the host-loss checklist and the isolated restore manifest `infra/restore/docker-compose.yml`, and exits nonzero if the root key or database URL is missing. `import` compares an Orkmail or PgStack inventory read-only and never imports owners. See [Recovery](../operations/recovery.md).

## Images and the agent

| Task                    | Runs                                  | Needs                                                                   |
| ----------------------- | ------------------------------------- | ----------------------------------------------------------------------- |
| `images:publish`        | `scripts/publish-images.ts`           | Docker Buildx; a clean tree; `gh` login or `GHCR_TOKEN` and `GHCR_USER` |
| `images:pin-edge-caddy` | `scripts/pin-edge-caddy.ts`           | Docker; a published `ark-edge-caddy` digest                             |
| `agent:build`           | `go build -o ark-agent .` in `agent/` | Go                                                                      |

`images:publish` builds the twelve targets of the default Bake group in `docker-bake.hcl` and pushes them to GHCR. Useful arguments are `--dry-run`, `--tag <tag>`, `--no-latest`, `--platform <list>` and `--allow-dirty`. `ARK_IMAGE_REGISTRY` must be a lowercase `ghcr.io/<namespace>` prefix and `ARK_IMAGE_PLATFORMS` sets the default platforms. `images:pin-edge-caddy` takes the `edge-caddy` reference the publisher prints (`ghcr.io/<namespace>/ark-edge-caddy[:<tag>]@sha256:<digest>`) and an optional `--no-verify`. Both are covered in [Publishing images](../../README.md#publishing-images) and [Third-party image pins](../operating.md#third-party-image-pins).

## Standalone scripts

These files in `scripts/` are run directly with `bun` rather than through a task.

| Script                            | Invocation                                                                                         | Purpose                                                                                                                                                                                                                      |
| --------------------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scripts/check-image-plan.ts`     | `bun scripts/check-image-plan.ts`                                                                  | Runs `docker buildx bake --print` and fails unless the default group has exactly the expected twelve targets, each with the source label, index annotation and minimal provenance. CI runs it.                               |
| `scripts/audit-tailnet-policy.ts` | `bun scripts/audit-tailnet-policy.ts global-snippet.hujson candidate-policy.hujson`                | Offline comparison of a proposed merged tailnet policy with a freshly generated global Ark snippet, at every port boundary. No credentials or network. See [Tailnet policy snippet](../operating.md#tailnet-policy-snippet). |
| `scripts/offsite-restore.ts`      | `ARK_RESTORE_* ... bun scripts/offsite-restore.ts`                                                 | Off-VPS point-in-time restore of a PostgreSQL cluster on a separate machine with Docker. See [Off-VPS point-in-time restore](../guides/backups.md#off-vps-point-in-time-restore).                                            |
| `scripts/ipv6-preflight-probe.ts` | `bun --no-env-file scripts/ipv6-preflight-probe.ts serve` or `... run request.json [admin-origin]` | The external IPv6 preflight runner, as a managed service next to the off-host heartbeat or for one signed manual request. See [Native IPv6 and AAAA publication](../operating.md#native-ipv6-and-aaaa-publication).          |
| `scripts/test-ghcr-publish.ts`    | Run by the manually dispatched GHCR publish check workflow                                         | Pushes and deletes one uniquely named smoke package to verify GHCR publishing. Needs `GHCR_TOKEN` and `GHCR_USER`.                                                                                                           |

The opt-in Vercel suite has no task either: run `bun --no-env-file test server/src/vercel-live.test.ts` with the `ARK_TEST_VERCEL_*` variables from [Opt-in live test suites](../operating.md#opt-in-live-test-suites).

A few scripts run inside containers or are called by other tooling rather than by an operator:

- `scripts/database-ingress.ts` is the command of the `database-ingress` Compose service: it applies the host-namespace firewall for the public edge and the 5432 limits and exports counters.
- `scripts/prepare-edge-upgrade.ts` is run by `maintain` in a one-off `domain-worker` container (as root with only `CHOWN`, `FOWNER` and `DAC_OVERRIDE`) to prepare the edge configuration directories before an upgrade. It reads `ARK_EDGE_L4_DIR`, `ARK_EDGE_DIR`, `ARK_CONTAINER_UID` and `ARK_CONTAINER_GID`.
- `scripts/apply-allowlist.ts` is a helper for `ARK_ALLOWLIST_HELPER` on hosts that apply the 5432 nft policy without the `database-ingress` reconciler.
- `scripts/pgbouncer-*-probe.ts` and `scripts/pgbouncer-smoke-checks.ts` are bundled and run by `scripts/test-pgbouncer-public.ts`.
- `scripts/install-host-hardening.ts`, `scripts/install-docker-ipv6.ts`, `scripts/install-edge-auth.ts`, `scripts/install-edge-l4.ts`, `scripts/host-inventory.ts`, `scripts/host-audit-external.ts`, `scripts/host-deployment-lock.ts` and `scripts/pgbouncer-bootstrap.ts` are modules of `host:install`, `host:audit` and `maintain`. The installer also installs a bundled copy of `scripts/observe-docker-ipv6.ts` on the host as the native IPv6 observer.

## CI workflows

The `CI` workflow in `.github/workflows/ci.yml` runs on every push and pull request and weekly. It does not call mise; it runs the same commands directly. The manually dispatched `GHCR publish check` workflow in `.github/workflows/ghcr-publish-check.yml` runs `scripts/check-image-plan.ts` and `scripts/test-ghcr-publish.ts`. Both are described in [Repository](../development/repository.md) and [Testing](../development/testing.md).
