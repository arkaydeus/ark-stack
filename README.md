# Ark Stack

Single-host infrastructure control plane: Better Auth administration, guided domains and certificates, PostgreSQL and Stalwart management, and a policy-enforcing Docker agent.

The running stack uses **PostgreSQL**. Tooling is **mise**, **bun**, **oxc**, and **Drizzle**. Server and UI are TypeScript.

## Prerequisites

- [mise](https://mise.jdx.dev)
- Docker, for the platform database and later service projects

```bash
mise trust
mise run setup
cp .env.example .env
mise run db:up
mise run db:migrate
mise run dev
```

Open http://localhost:5173. Create the first owner with `ARK_SETUP_TOKEN` from `.env`, then enroll MFA and complete the domain wizard.

Useful commands:

| Command                           | Purpose                                     |
| --------------------------------- | ------------------------------------------- |
| `mise run check`                  | format, lint, typecheck, test               |
| `mise run test`                   | bun unit tests                              |
| `mise run test:agent`             | Go agent policy tests                       |
| `mise run test:agent-integration` | disposable effective Docker/ledger test     |
| `mise run test:e2e`               | disposable real-browser signup/MFA/wizard   |
| `mise run test:upgrade`           | schema and host nft policy upgrade (Docker) |
| `mise run test:stalwart`          | disposable native Stalwart lifecycle test   |
| `mise run test:edge`              | Caddy, edge, observer and harness tests     |
| `mise run test:edge-tailnet`      | opt-in edge node checks on a real tailnet   |
| `mise run edge:rejoin`            | put `edge` back in a restarted `edge-ts`    |
| `mise run test:pgbouncer`         | PgBouncer mTLS/SCRAM and DB client tests    |
| `mise run recover -- status`      | local lockout / bootstrap inspection        |
| `mise run recover:mfa -- …`       | token- and confirmation-gated MFA reset     |
| `mise run host:install`           | build and start the complete host topology  |
| `mise run images:publish`         | build and push all images to GHCR           |
| `mise run import -- file`         | read-only Orkmail/PgStack inventory compare |
| `mise run recover-host`           | host-loss checklist                         |
| `mise run db:studio`              | Drizzle Studio                              |

## Publishing images

`mise run images:publish` builds all eight Bake targets for `linux/amd64`, tags them with the first 12 characters of HEAD and `latest`, and prints immutable digest references after pushing.

Set both `GHCR_TOKEN` and `GHCR_USER` to use an explicit token without a GitHub CLI login. Otherwise, log in with `gh` and grant its token package access using `gh auth refresh -h github.com -s write:packages`. Login and push use a temporary Docker configuration, removed on success or failure; the existing Docker context and Buildx builder are preserved.

```bash
mise run images:publish -- --dry-run
mise run images:publish -- --tag v0.1.0 --no-latest
mise run images:publish -- --platform linux/amd64,linux/arm64
```

`ARK_IMAGE_REGISTRY` defaults to `ghcr.io/arkaydeus` and accepts only lowercase `ghcr.io/<namespace>` prefixes; other registry hosts are rejected before login. `ARK_IMAGE_PLATFORMS` changes the default platforms, and `--platform` overrides it.

Publishing requires a clean tree unless `--allow-dirty` is supplied. Dirty builds append `-dirty` to both automatic and explicit tags and the revision label, omit `latest`, and reject `--tag latest`. Dry runs allow dirty trees and print these same tags and labels without accessing credentials.

CI checks the resolved Bake plan for repository source annotations and minimal provenance on every target, and builds every target with `--no-cache` to exercise the filtered build context. Publisher command tests and its dedicated TypeScript check run in CI and the normal local test/typecheck tasks.

The manually dispatched **GHCR publish check** workflow uses the repository's Actions token to push a tiny image inheriting Bake's common settings. It verifies the pushed index annotation, SLSA provenance and GitHub package repository linkage, then deletes its uniquely named smoke package and temporary Docker configuration. Run it in `arkaydeus/ark-stack`, whose source URL is configured in Bake; it requires permission to create and delete packages. It does not publish release tags.

## Layout

```
web/        React administration UI
server/     Hono API, Better Auth, Drizzle, operations coordinator
shared/     Policy, DNS planning, authz, and schemas
workers/    Database, mail, backup, and domain worker entrypoints
agent/      Go Docker agent and local recovery journal
infra/      Platform Compose, database, mail, and monitoring
templates/  Reviewed application service definitions
```

Public administration and public database endpoints are independent. Tailnet-only admin mode does not publish a public dashboard route.

Local and live-integration evidence is recorded in [`docs/fix1-verification.md`](docs/fix1-verification.md). Public DNS, ACME, external CIDR, SES, off-host receiver, and fresh-host restore checks are deployment acceptance gates rather than unit-test substitutes.
