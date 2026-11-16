import { describe, expect, test } from "bun:test";
import { X509Certificate } from "node:crypto";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PGBOUNCER_FILES, pgbouncerConfig, pgbouncerHba, scramVerifierMatches } from "@ark-stack/shared";
import { seedPgbouncerBootstrap } from "../../scripts/pgbouncer-bootstrap.ts";

async function withDirectory(action: (directory: string) => Promise<void>) {
  const directory = await mkdtemp(join(tmpdir(), "ark-bootstrap-test-"));
  try {
    await action(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

const read = (directory: string, name: string) => Bun.file(join(directory, name)).text();
const adminVerifier = (userlist: string) =>
  /^"ark_pgbouncer_admin" "(SCRAM-SHA-256\$[^"]+)"$/m.exec(userlist)?.[1] ?? "";

describe("installer PgBouncer bootstrap", () => {
  test("writes the closed mTLS configuration: no database, no client, a deny-all CA bundle", async () => {
    await withDirectory(async (directory) => {
      await seedPgbouncerBootstrap(directory, { adminPassword: "console-secret" });
      expect(await read(directory, PGBOUNCER_FILES.config)).toBe(
        pgbouncerConfig({ mappings: [], users: [] }),
      );
      expect(await read(directory, PGBOUNCER_FILES.hba)).toBe(pgbouncerHba());
      const userlist = await read(directory, PGBOUNCER_FILES.userlist);
      expect(userlist.split("\n")).toHaveLength(1);
      expect(scramVerifierMatches("console-secret", adminVerifier(userlist))).toBe(true);
      expect(userlist).not.toContain("console-secret");
      const bundle = await read(directory, PGBOUNCER_FILES.caBundle);
      expect(bundle.match(/BEGIN CERTIFICATE/g)).toHaveLength(1);
      expect(new X509Certificate(bundle).subject).toContain("Ark db-client CA deny-all");
      for (const name of Object.values(PGBOUNCER_FILES)) {
        expect((await stat(join(directory, name))).mode & 0o777).toBe(0o600);
      }
    });
  });

  test("without an admin password the userlist admits nobody", async () => {
    await withDirectory(async (directory) => {
      await seedPgbouncerBootstrap(directory);
      expect(await read(directory, PGBOUNCER_FILES.userlist)).toBe("");
    });
  });

  test("replaces the legacy placeholder and pre-mTLS configs, and preserves a current one", async () => {
    await withDirectory(async (directory) => {
      for (const old of [
        `[databases]\n\n[pgbouncer]\nlisten_addr = 0.0.0.0\nlisten_port = 5432\nauth_type = any\nclient_tls_sslmode = disable\nserver_tls_sslmode = disable\nadmin_users =\n`,
        // The FD-01 generator's output: TLS `require`, SCRAM, no admin socket.
        `[databases]\norders = host=app-postgres dbname=orders\n\n[pgbouncer]\nauth_type = scram-sha-256\nclient_tls_sslmode = require\nadmin_users =\n`,
      ]) {
        await Bun.write(join(directory, PGBOUNCER_FILES.config), old);
        await Bun.write(join(directory, PGBOUNCER_FILES.userlist), '"stale" "password"');
        await seedPgbouncerBootstrap(directory, { adminPassword: "console-secret" });
        expect(await read(directory, PGBOUNCER_FILES.config)).toBe(
          pgbouncerConfig({ mappings: [], users: [] }),
        );
        expect(await read(directory, PGBOUNCER_FILES.userlist)).not.toContain("stale");
      }

      const provisioned = pgbouncerConfig({
        mappings: [{ database: "orders", host: "app-postgres" }],
        users: [{ name: "orders_shop_production", maxUserConnections: 20, maxUserClientConnections: 300 }],
      });
      await Bun.write(join(directory, PGBOUNCER_FILES.config), provisioned);
      await Bun.write(join(directory, PGBOUNCER_FILES.userlist), '"orders_shop_production" "password"');
      await Bun.write(
        join(directory, PGBOUNCER_FILES.caBundle),
        "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
      );
      await seedPgbouncerBootstrap(directory, { adminPassword: "console-secret" });
      expect(await read(directory, PGBOUNCER_FILES.config)).toBe(provisioned);
      expect(await read(directory, PGBOUNCER_FILES.caBundle)).toContain("AA==");
      const userlist = await read(directory, PGBOUNCER_FILES.userlist);
      expect(userlist).toStartWith('"orders_shop_production" "password"\n');
      expect(scramVerifierMatches("console-secret", adminVerifier(userlist))).toBe(true);

      // A rotated admin password replaces the verifier; re-running is otherwise a no-op.
      await seedPgbouncerBootstrap(directory, { adminPassword: "rotated-secret" });
      const rotated = await read(directory, PGBOUNCER_FILES.userlist);
      expect(rotated.match(/ark_pgbouncer_admin/g)).toHaveLength(1);
      expect(scramVerifierMatches("rotated-secret", adminVerifier(rotated))).toBe(true);
      await seedPgbouncerBootstrap(directory, { adminPassword: "rotated-secret" });
      expect(await read(directory, PGBOUNCER_FILES.userlist)).toBe(rotated);
    });
  });
});
