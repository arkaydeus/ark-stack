// Database-worker stand-in for scripts/test-pgbouncer-public.ts (FD-16).
//
// The smoke test bundles this file with Bun.build and runs it in the pinned Bun runtime image as
// uid 1000, attached only to the admin socket volume and the internal database-management network,
// like database-worker. It drives the production module: RELOAD over the unix socket, then the
// served-fingerprint check, with the same retry logic the coordinator uses. No Docker CLI or
// Docker socket is available to it, and it reports that too.
//
//   probe.js show <COMMAND>          run one console command (RELOAD or SHOW ...)
//   probe.js reload [fingerprint]    RELOAD, and verify the served fingerprint when given
//   probe.js clients <role>          console client IDs of one login role (SHOW CLIENTS)
//   probe.js kill <role>             KILL_CLIENT every session of one login role (FD-17 revoke)
import { existsSync } from "node:fs";

import {
  PgbouncerReloadError,
  killRoleClients,
  pgbouncerAdminCommand,
  roleClientIds,
  reloadAndVerify,
  reloadPgbouncerAdmin,
  servedCertificateFingerprint,
} from "../server/src/modules/pgbouncer.ts";

const [mode, argument] = process.argv.slice(2);
const socket = {
  socketDir: process.env.ARK_PGBOUNCER_SOCKET_DIR ?? "/var/run/pgbouncer",
  password: process.env.ARK_PGBOUNCER_ADMIN_PASSWORD ?? "",
};
const environment = {
  dockerCli: Bun.which("docker"),
  dockerSocket: existsSync("/var/run/docker.sock"),
  uid: process.getuid?.(),
};

function report(value: Record<string, unknown>) {
  console.log(JSON.stringify({ ...value, environment }));
}

try {
  if (mode === "show") {
    const rows = await pgbouncerAdminCommand(argument ?? "", socket);
    report({ ok: true, command: argument, rows: [...rows] });
  } else if (mode === "reload") {
    const result = await reloadAndVerify({
      reload: () => reloadPgbouncerAdmin(socket),
      expectedFingerprint: argument || undefined,
      servedFingerprint: () =>
        servedCertificateFingerprint({
          host: process.env.ARK_PGBOUNCER_TLS_HOST ?? "pgbouncer-public",
          port: 5432,
        }),
      attempts: Number(process.env.ARK_PGBOUNCER_RELOAD_ATTEMPTS ?? 3),
      delayMs: Number(process.env.ARK_PGBOUNCER_RELOAD_RETRY_MS ?? 500),
    });
    report({ ok: true, ...result });
  } else if (mode === "clients") {
    report({ ok: true, ids: await roleClientIds(argument ?? "", socket) });
  } else if (mode === "kill") {
    report({ ok: true, ...(await killRoleClients(argument ?? "", socket)) });
  } else {
    throw new Error(`unknown probe mode ${mode}`);
  }
} catch (error) {
  report({
    ok: false,
    error: error instanceof Error ? error.message : String(error),
    attempts: error instanceof PgbouncerReloadError ? error.attempts : undefined,
    failures: error instanceof PgbouncerReloadError ? error.failures : undefined,
  });
  process.exitCode = 1;
}
