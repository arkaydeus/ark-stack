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

| Command                      | Purpose                                     |
| ---------------------------- | ------------------------------------------- |
| `mise run check`             | format, lint, typecheck, test               |
| `mise run test`              | bun unit tests                              |
| `mise run test:agent`        | Go agent policy tests                       |
| `mise run recover -- status` | local lockout / bootstrap inspection        |
| `mise run host:install`      | generate secrets, start Postgres, migrate   |
| `mise run import -- file`    | read-only Orkmail/PgStack inventory compare |
| `mise run recover-host`      | host-loss checklist                         |
| `mise run db:studio`         | Drizzle Studio                              |

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
