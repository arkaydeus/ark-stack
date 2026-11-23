# Local development

This page runs Ark Stack on a workstation: the API with embedded workers, the Vite admin UI and the two PostgreSQL clusters. It covers prerequisites, the `.env` file, the databases and migrations, creating the first owner, running tests, and the problems you are most likely to hit.

## What you get

A local run is a development topology, not a small production install:

| Part                    | Local development                                                                    | Production                                |
| ----------------------- | ------------------------------------------------------------------------------------ | ----------------------------------------- |
| API                     | `bun --watch` on port 3000, read from `.env`                                         | `api` container, loopback port 3000 only  |
| Admin UI                | Vite dev server on port 5173, proxying `/api` to the API                             | Built UI served by the API                |
| Workers                 | Embedded in the API process (`ARK_EMBEDDED_WORKERS=1`)                               | Separate containers with their own tokens |
| DNS checks              | Stubbed: expected records are accepted without public lookups (`ARK_DNS_STUB=1`)     | Public DNS lookups                        |
| Certificates            | Self-signed OpenSSL leaf, recorded as untrusted (`ARK_CERTIFICATE_MODE=development`) | lego and Let's Encrypt                    |
| Front door, mail, agent | Not running                                                                          | Containers                                |

Embedded workers run the same job handlers as the worker containers, inside the API. The API refuses this mode when `NODE_ENV=production`, which every Ark image sets.

## Prerequisites

- [mise](https://mise.jdx.dev), which installs the pinned toolchain from `mise.toml`: Bun 1.4.5 and Go 1.25.1.
- Docker with Compose v2, for the PostgreSQL containers and for most integration tests.
- OpenSSL on the `PATH`. The installer and the development certificate fallback call it.
- `nc` (netcat) on the `PATH` to check the published database ports.
- Free local ports 3000 (API) and 5173 (UI), and 5433 and 5434 if you use the Compose databases.

## Install the toolchain

From the repository root:

```sh
mise trust
mise run setup
```

`mise run setup` runs `mise install` and `bun install` for the workspaces (`shared`, `server`, `web`, `workers`).

## Create `.env`

Every `mise` task that runs Ark code reads the repository's `.env`. Start from the example:

```sh
cp .env.example .env
```

The example cannot be used as it is. On startup the API checks every installer-generated secret and refuses to start while one is empty or still a published example value such as `change-me-…` or `dev-setup-token`:

```text
BETTER_AUTH_SECRET still has a published example placeholder. Refuse to start until it is replaced.
```

Let the installer fill them without touching Docker:

```sh
ARK_INSTALL_SKIP_DOCKER=1 ARK_INSTALL_NONINTERACTIVE=1 mise run host:install
```

With `ARK_INSTALL_SKIP_DOCKER=1` the installer only writes files: it replaces every placeholder or empty secret in `.env` with a random value and keeps every other value, sets `.env` to mode `0600`, creates the `tmp/` directories, writes a self-signed certificate for the database endpoint, seeds the edge and PgBouncer configuration files, and prints the setup token. `ARK_INSTALL_NONINTERACTIVE=1` skips the prompt for the edge node's Tailscale key, which a local run does not need. Existing real values are never replaced, so you can run it again safely.

The installer does not rewrite the two connection URLs, which still carry the example passwords. Point them at the generated passwords:

```sh
api=$(grep '^ARK_API_DB_PASSWORD=' .env | cut -d= -f2)
app=$(grep '^ARK_APP_DB_PASSWORD=' .env | cut -d= -f2)
# Edit .env so that:
#   DATABASE_URL=postgres://ark_runtime:$api@127.0.0.1:5433/ark_platform
#   DATABASE_APP_URL=postgres://ark_cluster_admin:$app@127.0.0.1:5434/postgres
```

The generated passwords are URL-safe base64, so they need no escaping.

### Development values

These values from `.env.example` define the development behaviour. Keep them as they are for local work; [Configuration](configuration.md) describes every variable.

| Variable                                                                                                                   | Value in `.env.example`                       | Effect                                                                                                                               |
| -------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `ARK_EMBEDDED_WORKERS`                                                                                                     | `1`                                           | The API runs the worker job handlers and schedulers itself.                                                                          |
| `ARK_DNS_STUB`                                                                                                             | `1`                                           | `domain.verify` accepts the expected records without public DNS lookups.                                                             |
| `ARK_CERTIFICATE_MODE`                                                                                                     | `development`                                 | Without lego configured, certificates are 30-day self-signed OpenSSL leaves, recorded as untrusted.                                  |
| `ARK_ACME_STAGING`                                                                                                         | `1`                                           | If you do configure lego, it uses Let's Encrypt staging.                                                                             |
| `BETTER_AUTH_URL`                                                                                                          | `http://localhost:3000`                       | The admin origin. Over plain HTTP, cookies are not `__Host-` prefixed.                                                               |
| `BETTER_AUTH_TRUSTED_ORIGINS`                                                                                              | `http://localhost:5173,http://localhost:3000` | The other hosts the API answers. Any other `Host` gets `421`.                                                                        |
| `ARK_LISTEN_PORT`                                                                                                          | `3000`                                        | API port.                                                                                                                            |
| `ARK_CERT_DIR`, `ARK_EDGE_DIR`, `ARK_PGBOUNCER_DIR`, `ARK_MAIL_STATE_DIR`, `ARK_COMPOSE_DIR`, `ARK_DB_INGRESS_METRICS_DIR` | `./tmp/…`                                     | Where the embedded workers write certificates, edge and PgBouncer files, mail state and Compose artefacts. `tmp/` is ignored by git. |

The optional provider settings (`DNS_API_TOKEN`, `AWS_*`, `STALWART_*`, `ARK_ALERT_WEBHOOK`) are commented out. Leave them unset unless you are testing against a real provider.

## Start the databases

`mise run db:up` starts `postgres` and `app-postgres` from `infra/platform/docker-compose.yml` with the development override `infra/platform/docker-compose.dev.yml`, which binds them to `127.0.0.1:5433` and `127.0.0.1:5434`.

The task points Compose at the files under `infra/platform/`. Export the checkout-root `.env` so interpolation uses its values regardless of where Compose would find an env file. Compose checks required variables across the file, including variables for services the task does not start:

```sh
set -a; . ./.env; set +a
mise run db:up
```

Without the export, Compose stops with an error such as `required variable ARK_CONTROL_DB_PASSWORD is missing a value: generated by installer`.

Wait until both PostgreSQL servers report that they are accepting TCP connections. Repeat these checks if either server is still initialising:

```sh
docker compose -f infra/platform/docker-compose.yml -f infra/platform/docker-compose.dev.yml \
  exec -T postgres pg_isready -h 127.0.0.1 -U ark_migration -d ark_platform
docker compose -f infra/platform/docker-compose.yml -f infra/platform/docker-compose.dev.yml \
  exec -T app-postgres pg_isready -h 127.0.0.1 -U ark_cluster_admin -d postgres
```

Then check that the published ports answer from the host:

```sh
nc -z 127.0.0.1 5433 && nc -z 127.0.0.1 5434 && echo reachable
```

> [!WARNING]
> Both clusters join only internal Compose networks. If the servers are ready but the host check fails, use `docker port` to check the containers' port mappings. Some Docker versions, including Docker Desktop with Engine 29, omit the mappings on internal-only networks. If the mappings are missing, stop the containers with `mise run db:down` and use a [throwaway database](#alternative-a-throwaway-database) instead.

The first start initialises both data volumes. `infra/platform/init-control-db.sh` creates the `ark_runtime` login with `ARK_API_DB_PASSWORD`, and the image's entrypoint sets the owner passwords from `ARK_CONTROL_DB_PASSWORD` and `ARK_APP_DB_PASSWORD`. These passwords are set only when a volume is first created; see [Common problems](#common-problems) if you change them later.

## Apply the migrations

Migrations must run as the schema owner `ark_migration`. `DATABASE_URL` in `.env` uses the runtime role `ark_runtime`, which cannot create tables, so `mise run db:migrate` with the default `.env` fails with `permission denied for schema public`. Run the migration script with an owner URL instead (after the export above):

```sh
mise exec -- env DATABASE_URL="postgres://ark_migration:$ARK_CONTROL_DB_PASSWORD@127.0.0.1:5433/ark_platform" \
  bun run --cwd server db:migrate
```

`mise exec` puts the pinned Bun on the command's path. The `env` command passes the owner URL directly to Bun for this invocation. The script applies every pending file in `server/drizzle` in order, records it in `ark_migrations`, and prints `Platform database migrations applied.` Migration `0004` grants `ark_runtime` the table privileges it needs, so the API keeps running as the runtime role, as in production.

### Alternative: a throwaway database

`mise run test:db:up` starts a uniquely named `postgres:17.6` container on a loopback port that Docker picks, applies the migrations as `ark_migration`, and prints shell exports:

```sh
mise run test:db:up
```

Copy the printed `DATABASE_URL` and `DATABASE_APP_URL` values into `.env` (only those two; the other printed values are test-only secrets). Both URLs use the owner role of the one container, and its data is on tmpfs, so it is lost when the container is removed. Remove it with the `mise run test:db:down <container>` command that `up` prints.

## Run the stack

```sh
mise run dev
```

This starts two processes side by side: the API (`bun --watch server/src/index.ts`, restarting on change) and the Vite UI. The API logs:

```text
ARK_EMBEDDED_WORKERS is enabled; provider adapters are running inside the API process.
Ark Stack API listening on 3000
```

Open <http://localhost:5173>. Vite proxies `/api` to `127.0.0.1:3000` and keeps the `localhost:5173` host, which is a registered origin.

Other ways to run it:

| Command               | What it does                                                                                              |
| --------------------- | --------------------------------------------------------------------------------------------------------- |
| `mise run dev:server` | Only the API with embedded workers, on port 3000.                                                         |
| `mise run dev:web`    | Only the Vite UI.                                                                                         |
| `mise run build`      | Typechecks every workspace and builds the UI into `dist` under `web`.                                     |
| `mise run start`      | Serves the built UI and API on port 3000 (open <http://localhost:3000>).                                  |
| `mise run db:studio`  | Drizzle Studio against `DATABASE_URL`.                                                                    |
| `mise run db:down`    | Stops and removes the `ark-platform` Compose containers (export `.env` first). The data volumes are kept. |

## Create the first owner

1. On the sign-in page, which shows **Create the owner** while no user exists, enter a name, email, password (at least 12 characters) and the **Setup token**: the value of `ARK_SETUP_TOKEN` in `.env`, also printed by the installer.
2. Select **Create administrator**. The API checks the token, creates the user, grants it the `owner` role and closes setup. A second sign-up with the same token is refused with `Administrator setup is closed or the token is invalid.`
3. Enrol TOTP MFA: confirm your password, add the shown secret to an authenticator, save the recovery codes, and enter a six-digit code.
4. Complete the domain wizard.

[First run and domain wizard](first-run.md) describes each screen in full. Locally, a few things differ:

- With `ARK_DNS_STUB=1`, `domain.verify` accepts the planned records without looking them up, so endpoints move past `awaiting_dns` immediately.
- Certificates are self-signed, so endpoints end in `certificate_untrusted`. The public edge never serves them, and nothing is reachable through a front door because no edge runs.
- Mail, SES, Cloudflare and Docker operations need their providers. Without them, the corresponding operations fail or wait and record why.

`mise run recover -- status` prints the bootstrap state (whether setup is complete, the number of users, whether a setup token is configured) without changing anything. `mise run recover -- reset-setup` reopens setup only when no users exist.

## Running tests

Most tests need no `.env` and no running stack. A short map; [Testing](../development/testing.md) explains every suite.

| Command               | Needs                                                    | Covers                                                                                                          |
| --------------------- | -------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `mise run check`      | `.env` file                                              | Format check, lint, typecheck and the unit tests.                                                               |
| `mise run test`       | `.env` file                                              | Bun unit tests for `shared`, `server`, `workers`, `tests` and scripts.                                          |
| `mise run test:db`    | Docker                                                   | DB-backed server tests on a throwaway migrated PostgreSQL, always removed.                                      |
| `mise run test:agent` | Go                                                       | Docker agent policy tests.                                                                                      |
| `mise run test:e2e`   | A loopback database from `mise run test:db:up`, Chromium | Real-browser owner creation, MFA, wizard and recovery-code use in a disposable database it creates and removes. |
| `mise run test:edge`  | Docker                                                   | Caddy, HAProxy, watchdog, nftables and login-gate harnesses.                                                    |
| `mise run docs:check` | nothing                                                  | Links, anchors, paths, tasks, endpoints, env vars and ports in the docs.                                        |

`mise run test:db` deliberately ignores `.env` and uses fixed test-only secrets. For the browser tests, load a throwaway database into your shell with `eval "$(mise run test:db:up)"` first, and install Chromium once with `bunx playwright install chromium`.

## Common problems

**The API exits with "… still has a published example placeholder."** A generated secret in `.env` is empty or an example value. Run `ARK_INSTALL_SKIP_DOCKER=1 ARK_INSTALL_NONINTERACTIVE=1 mise run host:install` to fill it, or set it by hand. `ARK_EDGE_GATE_TOKEN` and `ARK_EDGE_WATCHDOG_TOKEN` may be empty, but not example values.

**`mise run db:up` fails with "required variable … is missing a value".** Compose did not see `.env`. Export it first (`set -a; . ./.env; set +a`), or run the same Compose command with `--env-file .env`.

**Connection refused on 5433 or 5434.** Check `docker port <container>` for the `postgres` and `app-postgres` containers. If no port is published, your Docker version does not publish ports for containers on internal networks; use [a throwaway database](#alternative-a-throwaway-database).

**`mise run db:migrate` fails with "permission denied for schema public".** It ran as `ark_runtime`. Run the migration with the owner URL shown in [Apply the migrations](#apply-the-migrations).

**"password authentication failed for user ark_runtime".** `DATABASE_URL` does not carry `ARK_API_DB_PASSWORD`, or the password changed after the volume was created. Fix the URL, or re-apply the runtime password with the same command the installer uses: `docker compose -f infra/platform/docker-compose.yml exec -T postgres sh /docker-entrypoint-initdb.d/10-runtime.sh` (with `.env` exported). Owner passwords set by the image apply only to a new volume; to start over, remove the containers and their volumes with `docker compose -f infra/platform/docker-compose.yml -f infra/platform/docker-compose.dev.yml down -v`, which deletes all local data.

**The UI shows `{"error":"This host is not a registered Ark origin."}` (HTTP 421).** The browser's host is not in `BETTER_AUTH_URL` or `BETTER_AUTH_TRUSTED_ORIGINS`. Host names and ports must match exactly: `127.0.0.1:5173` is not `localhost:5173`. Use the configured host or add yours to `BETTER_AUTH_TRUSTED_ORIGINS` and restart the API.

**"Administrator setup is closed or the token is invalid."** Either the token does not match `ARK_SETUP_TOKEN`, or an owner already exists. `mise run recover -- status` shows which.

**"Refresh your assured session" after enrolling MFA.** The session predates MFA enrolment. Sign out and sign in again with a TOTP or recovery code.

**Endpoints stay `certificate_untrusted`.** Expected locally: development certificates are never trusted. See [Certificates](../features/certificates.md) for the production path.

**Port 3000 or 5173 is in use.** Stop the other process. `ARK_LISTEN_PORT` moves the API, but the Vite proxy in `web/vite.config.ts` targets port 3000.
