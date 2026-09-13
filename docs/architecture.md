# Architecture

See [implementation-plan.md](implementation-plan.md) for the full design. This note records the first implementation.

- One TypeScript API (`server/`) owns identity, authorization, desired state, and the durable operation queue.
- PostgreSQL is the control-plane database. Application clusters are separate records and must never share that instance.
- Workers are separate processes with independent tokens. Local development sets `ARK_EMBEDDED_WORKERS=1` so the API coordinator executes adapters in-process.
- The Docker agent is a small Go service. Only it should receive the host Docker socket. Compose input is validated before any engine call.
- Secrets use AES-256-GCM with a key ID. The root key is not stored in PostgreSQL. Inventory APIs return metadata, not plaintext.
- Better Auth `baseURL` and `trustedOrigins` come from the configured admin origin. Client `Host` headers do not choose the cookie domain.
- Application PostgreSQL is provisioned with owner/migration/runtime/readonly roles, PUBLIC revoked, optional pgvector, and public-pooler admission rules that refuse privileged roles.
- Certificates are issued with a pinned lego client when configured, otherwise a local OpenSSL leaf written to a per-hostname volume. HTTP-01 challenges are served at `/.well-known/acme-challenge/:token`.
- The Docker agent talks to the Engine API over the unix socket, redacts inspect labels, and runs Compose with a fixed argument vector after policy validation.
- Mail desired-state documents keep inbound ready independent of SES. Outbound stays paused until relay credentials exist.
- Backups record upload, integrity, and restore-test as three statuses. Restore tests are isolated and disable reconciliation, outbound mail, and public ingress.
- Cloudflare publishes only a reviewed DNS diff and refuses ambiguous same-name updates. SES uses SigV4 and the documented SMTP password derivation. Stalwart applies an upsert plan and never enables open relay. Outbound stays paused until SES is ready.
- Public PgBouncer mappings and userlists are generated from admitted runtime roles. Mode changes rewrite Caddy/Serve, revoke sessions, and keep Tailscale Funnel disabled.
- The installer writes host secrets without overwriting existing values. Import is a read-only inventory compare and never promotes legacy users to owners.
