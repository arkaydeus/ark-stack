Application PostgreSQL is a separate cluster from the platform control database. Public traffic terminates on PgBouncer. Every network client must present a certificate from one of Ark's private database-client CAs (`client_tls_sslmode = verify-full`, TLS 1.3 only) and then log in with SCRAM as its own login role. Mappings and role admission are explicit, with no wildcard mapping. Privileged, backup and bootstrap identities are denied on the public listener (`docs/design/front-door.md` §3.10.2).

The `pgbouncer-public` Compose service runs `/usr/bin/pgbouncer` directly on the generated `/var/lib/ark/pgbouncer/pgbouncer.ini`; the image's own entrypoint, which builds a config from environment variables, is bypassed. It runs as uid 1000, the owner of Ark's mode-0600 files, because every capability is dropped. `tests/security/pgbouncer-public.test.ts` enforces that shape and a PgBouncer version of at least 1.25.2 (CVE-2026-6664).

The database worker writes four files to `tmp/pgbouncer`, each replaced atomically:

- `pgbouncer.ini`, rendered by `pgbouncerConfig` (template: `pgbouncer.ini` here);
- `pg_hba.conf`, from `pgbouncerHba` (template: `pg_hba.conf` here). It is ordered and first match wins: the console administrator `ark_pgbouncer_admin` is accepted only on the local socket and rejected on every network transport;
- `userlist.txt`, one line per admitted client login role, plus the administrator's SCRAM verifier;
- `client-ca-bundle.pem`, the current, pending and retiring CA generations of active database clients.

It then runs `RELOAD` on PgBouncer's admin console over a unix socket. The socket lives in the `ark_pgbouncer_socket` tmpfs volume (uid 1000, mode 0700), which is mounted only into `pgbouncer-public` and `database-worker`. The worker has no Docker CLI and no Docker socket. Every reload checks for a pending database endpoint certificate, including reloads with no certificate payload. It verifies the pending fingerprint before marking the certificate as serving or clearing the reload alert. A failure is retried; if it persists, the critical `pgbouncer-reload` alert is raised and the certificate is not marked as serving.

When the last client is removed, the worker writes `expose=0` and waits for a running host ingress to acknowledge listener closure before rendering or reloading. Failures retain that closed flag. With no admitted client, PgBouncer maps nothing, is not routed publicly (`expose` is `0`), and its CA bundle holds only a freshly generated deny-all CA whose key was discarded. The bundle is never empty or unset, so an empty client set can never mean "accept any certificate". The installer writes this closed configuration on a fresh install, replaces the legacy permissive placeholder and any pre-mTLS configuration, preserves a current configuration, and keeps the administrator verifier in step with `ARK_PGBOUNCER_ADMIN_PASSWORD`.

`mise run test:pgbouncer` (`scripts/test-pgbouncer-public.ts`) starts the pinned PgBouncer against a disposable `app-postgres` and runs these checks:

- the closed bootstrap and the admin socket;
- the exact rendered INI, HBA and CA bundle, loaded with `RELOAD` by a database-worker stand-in container;
- the V-8 mTLS matrix, and the administrator's restriction to the socket;
- `max_user_client_connections`, and postgres.js prepared statements in transaction mode, run in the pinned Linux Bun worker image;
- a server certificate swap verified with `openssl s_client`, and simulated reload failures.

CI runs it with a host `psql` client (`postgresql-client` on Linux) and OpenSSL 1.1.1 or newer with PostgreSQL STARTTLS support. On macOS the test can use Homebrew OpenSSL instead of system LibreSSL; `ARK_OPENSSL_BIN` selects an explicit binary. Usage errors fail the TLS-version check. A real TLS-1.2-enabled listener provides a negative control.

PgBouncer also joins a dedicated `database-loopback` bridge so Docker publishes `127.0.0.1:15432`, the host database-ingress relay target. Application PostgreSQL stays on the internal `database-management` bridge. The smoke test requires the loopback-only publication and connects through that host port; a missing binding fails the check.

Relative local `ARK_CERT_DIR` values (including the installer default `./tmp/certs`) are resolved to absolute paths before configuration rendering. Production container paths remain absolute.

The smoke test defaults to port 15432, matching production. On a shared developer host where that port is busy, use `ARK_PGBOUNCER_SMOKE_PORT=0 mise run test:pgbouncer` to request a disposable loopback port (Compose 2.24.4+). The test still requires a loopback-only binding and verified TLS through the published host port.
