import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { pgbouncerConfig } from "@ark-stack/shared";
import { seedPgbouncerBootstrap } from "../../scripts/pgbouncer-bootstrap.ts";

describe("installer PgBouncer bootstrap", () => {
  test("requires TLS and SCRAM with no admitted databases, users or console admins", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ark-bootstrap-test-"));
    try {
      await seedPgbouncerBootstrap(directory);
      const config = await Bun.file(join(directory, "pgbouncer.ini")).text();
      expect(config).toContain("[databases]\n\n");
      expect(config).toContain("auth_type = scram-sha-256\n");
      expect(config).toContain("auth_file = /var/lib/ark/pgbouncer/userlist.txt\n");
      expect(config).toContain("client_tls_sslmode = require\n");
      expect(config).toContain("client_tls_key_file = /var/lib/ark/certs/database/privkey.pem\n");
      expect(config).toContain("admin_users =\n");
      expect(await Bun.file(join(directory, "userlist.txt")).text()).toBe("");
      for (const name of ["pgbouncer.ini", "userlist.txt"]) {
        expect((await stat(join(directory, name))).mode & 0o777).toBe(0o600);
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("upgrades the old permissive placeholder and preserves a provisioned config", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ark-bootstrap-test-"));
    try {
      await Bun.write(
        join(directory, "pgbouncer.ini"),
        `[databases]\n\n[pgbouncer]\nlisten_addr = 0.0.0.0\nlisten_port = 5432\nauth_type = any\nclient_tls_sslmode = disable\nserver_tls_sslmode = disable\nadmin_users =\n`,
      );
      await Bun.write(join(directory, "userlist.txt"), '"stale" "password"');
      await seedPgbouncerBootstrap(directory);
      expect(await Bun.file(join(directory, "pgbouncer.ini")).text()).toBe(pgbouncerConfig({ mappings: [] }));
      expect(await Bun.file(join(directory, "userlist.txt")).text()).toBe("");
      const provisioned = pgbouncerConfig({ mappings: [{ database: "orders", host: "app-postgres" }] });
      await Bun.write(join(directory, "pgbouncer.ini"), provisioned);
      await Bun.write(join(directory, "userlist.txt"), '"orders_runtime" "password"');
      await seedPgbouncerBootstrap(directory);
      expect(await Bun.file(join(directory, "pgbouncer.ini")).text()).toBe(provisioned);
      expect(await Bun.file(join(directory, "userlist.txt")).text()).toBe('"orders_runtime" "password"');
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
