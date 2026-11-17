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
//   probe.js retire <spec.json>      FD-28: wait until `startAt`, then retire one generation with
//                                    the production retireGeneration (DISABLE, write the reduced
//                                    files into /pgbouncer and RELOAD, drain the role and pre-auth
//                                    logins, ENABLE) and report the measured timeline
import { existsSync } from "node:fs";

import {
  PgbouncerReloadError,
  RetirementError,
  killRoleClients,
  pgbouncerAdminCommand,
  roleClientIds,
  reloadAndVerify,
  reloadPgbouncerAdmin,
  retireGeneration,
  servedCertificateFingerprint,
  socketAdmin,
  writePgbouncerFiles,
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
  } else if (mode === "retire") {
    const spec = JSON.parse(await Bun.file(argument ?? "").text()) as {
      database: string;
      role: string;
      /** Epoch ms to start at; omitted means now (an emergency removal). */
      startAt?: number;
      /** Absolute deadline (epoch ms), or `deadlineAfterStartMs` relative to the actual start. */
      deadline?: number;
      deadlineAfterStartMs?: number;
      files: Record<string, string>;
      databaseMapped: boolean;
      loginTimeoutSeconds: number;
    };
    const wait = (spec.startAt ?? 0) - Date.now();
    if (wait > 0) await Bun.sleep(wait);
    const startAt = spec.startAt ?? Date.now();
    const result = await retireGeneration({
      database: spec.database,
      role: spec.role,
      deadline: new Date(spec.deadline ?? startAt + (spec.deadlineAfterStartMs ?? 5_000)),
      admin: socketAdmin(socket),
      apply: async () => {
        await writePgbouncerFiles(process.env.ARK_PGBOUNCER_DIR ?? "/pgbouncer", spec.files);
        await reloadPgbouncerAdmin(socket);
        return { databaseMapped: spec.databaseMapped };
      },
      loginTimeoutSeconds: spec.loginTimeoutSeconds,
    });
    report({ ok: true, startedLateMs: result.startedAt - startAt, ...result });
  } else {
    throw new Error(`unknown probe mode ${mode}`);
  }
} catch (error) {
  report({
    ok: false,
    error: error instanceof Error ? error.message : String(error),
    timeline: error instanceof RetirementError ? error.timeline : undefined,
    attempts: error instanceof PgbouncerReloadError ? error.attempts : undefined,
    failures: error instanceof PgbouncerReloadError ? error.failures : undefined,
  });
  process.exitCode = 1;
}
