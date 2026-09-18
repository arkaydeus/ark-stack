# Ark Stack agent guide

## Repository

Ark Stack is a single-host infrastructure control plane. The server and web UI
are TypeScript; the host policy agent is Go. PostgreSQL is the system database.
Use the pinned `mise` and Bun tasks instead of substituting package managers or
ad-hoc commands.

Important paths:

- `server/`: Hono API, Better Auth, Drizzle, and the operations coordinator.
- `web/`: React administration UI.
- `shared/`: authorization, policy, DNS, crypto, and shared schemas.
- `workers/`: database, mail, backup, domain, and off-host workers.
- `agent/`: Go Docker policy agent and recovery journal.
- `infra/`: Compose, edge, database, mail, and monitoring configuration.
- `docs/implementation-plan.md`: product and security requirements.
- `docs/architecture.md`: implemented system boundaries.

## Working agreements

- Preserve unrelated user changes and keep edits scoped to the request.
- Do not commit credentials. Use `.env` only for local secrets; it is ignored.
- Treat authentication, authorization, secret reveal, public exposure, Docker,
  migrations, backups, and recovery paths as security-sensitive.
- Do not run destructive Docker, database, DNS, mail, or recovery operations
  against a live environment unless the user explicitly requests that action.
- Add or update tests for changed behavior. Start with the narrow owning suite;
  use `mise run check` for repository-wide verification when proportionate.
- Use `mise run test:agent` for Go policy changes. Integration and end-to-end
  tasks may require Docker and should only be run when relevant.
- Keep public API and operational behavior consistent with the requirements in
  `docs/implementation-plan.md` and the checks in `docs/security-review.md`.

Useful commands:

```bash
mise run check
mise run test
mise run test:agent
mise run test:e2e
```

## AgentHQ

The repository-scoped AgentHQ skill is
`.agents/skills/agenthq/SKILL.md`. Use it whenever a request mentions AgentHQ,
`agenthq.top`, an AgentHQ intray, a ticket such as `PROJ-123`, a project board,
wiki, or agent diary.

AgentHQ credentials are runtime secrets. Never place an `ahq_...` key in this
file, source control, logs, ticket comments, or a diary entry. AgentHQ reads are
safe for lookup tasks; create, update, comment, status, document, diary, and
intray-read operations are external writes and require the user's request to
authorize them.
