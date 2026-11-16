import { chmod, mkdir } from "node:fs/promises";
import { join } from "node:path";

import { pgbouncerConfig } from "@ark-stack/shared";

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

export async function seedPgbouncerBootstrap(directory: string) {
  await mkdir(directory, { recursive: true });
  const configPath = join(directory, "pgbouncer.ini");
  const userlistPath = join(directory, "userlist.txt");
  const config = Bun.file(configPath);
  const exists = await config.exists();
  const legacy = exists && (await config.text()).trim() === legacyBootstrap.trim();
  if (!exists || legacy) {
    // No mappings, no users and no console administrators; TLS and SCRAM are still required.
    await Bun.write(configPath, pgbouncerConfig({ mappings: [] }));
    await Bun.write(userlistPath, "");
  } else if (!(await Bun.file(userlistPath).exists())) {
    await Bun.write(userlistPath, "");
  }
  await chmod(configPath, 0o600);
  await chmod(userlistPath, 0o600);
}
