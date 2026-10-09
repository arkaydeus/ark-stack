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
| `mise run test:upgrade`           | representative additive schema upgrade      |
| `mise run test:stalwart`          | disposable native Stalwart lifecycle test   |
| `mise run test:edge`              | generated/static Caddy validation           |
| `mise run recover -- status`      | local lockout / bootstrap inspection        |
| `mise run recover:mfa -- …`       | token- and confirmation-gated MFA reset     |
| `mise run host:install`           | build and start the complete host topology  |
| `mise run images:publish`         | build and push all images to GHCR           |
| `mise run import -- file`         | read-only Orkmail/PgStack inventory compare |
| `mise run recover-host`           | host-loss checklist                         |
| `mise run db:studio`              | Drizzle Studio                              |

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
