import { chmod, mkdir } from "node:fs/promises";
import { join } from "node:path";

import {
  PGBOUNCER_ADMIN_USER,
  PGBOUNCER_FILES,
  pgbouncerHba,
  scramSha256Verifier,
  scramVerifierMatches,
} from "@ark-stack/shared";

import { planPgbouncer, renderPgbouncerFiles, writePgbouncerFiles } from "../server/src/modules/pgbouncer.ts";

// Recognize only the old installer placeholder, never an operator's live config.
const legacyBootstrap = `[databases]

[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 5432
auth_type = any
client_tls_sslmode = disable
server_tls_sslmode = disable
admin_users =
`;

/** The closed §3.10.2 configuration: no mapping, no client, and a deny-all client CA bundle. */
export function closedPgbouncerFiles(adminPassword?: string) {
  const plan = planPgbouncer({
    databases: [],
    clients: [],
    certificates: [],
    cas: [],
    now: new Date(),
    host: "app-postgres",
  });
  return renderPgbouncerFiles({ plan, adminPassword });
}

const adminLine = new RegExp(`^"${PGBOUNCER_ADMIN_USER}" "([^"]*)"$`);

/**
 * Seed or upgrade `tmp/pgbouncer` for the installer.
 *
 * - Missing config, the legacy permissive placeholder, or any configuration written before the
 *   mTLS layout (no `auth_type = hba`) is replaced by the closed configuration. The database
 *   worker rewrites it from active database clients on its next `pgbouncer.reload`.
 * - A current configuration is preserved. Missing companion files are added (the HBA, and a
 *   deny-all CA bundle), and the console administrator's verifier is (re)written when it is
 *   missing or no longer matches `adminPassword`, so the worker can always reach the console.
 */
export async function seedPgbouncerBootstrap(directory: string, options: { adminPassword?: string } = {}) {
  await mkdir(directory, { recursive: true });
  const configPath = join(directory, PGBOUNCER_FILES.config);
  const config = Bun.file(configPath);
  const exists = await config.exists();
  const text = exists ? await config.text() : "";
  const replace = !exists || text.trim() === legacyBootstrap.trim() || !/^auth_type = hba$/m.test(text);
  const closed = closedPgbouncerFiles(options.adminPassword);
  if (replace) {
    await writePgbouncerFiles(directory, closed);
  } else {
    const missing: Record<string, string> = {};
    for (const name of [PGBOUNCER_FILES.hba, PGBOUNCER_FILES.caBundle, PGBOUNCER_FILES.userlist]) {
      if (!(await Bun.file(join(directory, name)).exists())) missing[name] = closed[name]!;
    }
    if (!missing[PGBOUNCER_FILES.hba]) {
      const hba = await Bun.file(join(directory, PGBOUNCER_FILES.hba)).text();
      if (hba !== pgbouncerHba()) missing[PGBOUNCER_FILES.hba] = pgbouncerHba();
    }
    if (options.adminPassword && !missing[PGBOUNCER_FILES.userlist]) {
      const lines = (await Bun.file(join(directory, PGBOUNCER_FILES.userlist)).text())
        .split("\n")
        .filter(Boolean);
      const current = lines.map((line) => adminLine.exec(line)?.[1]).find((value) => value !== undefined);
      if (!current || !scramVerifierMatches(options.adminPassword, current)) {
        const users = lines.filter((line) => !adminLine.test(line));
        users.push(`"${PGBOUNCER_ADMIN_USER}" "${scramSha256Verifier(options.adminPassword)}"`);
        missing[PGBOUNCER_FILES.userlist] = users.join("\n");
      }
    }
    if (Object.keys(missing).length) await writePgbouncerFiles(directory, missing);
  }
  for (const name of Object.values(PGBOUNCER_FILES)) await chmod(join(directory, name), 0o600);
}
