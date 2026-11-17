import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  NODE_POSTGRES_SNIPPET,
  clientGroupRole,
  clientRoleName,
  clientRoleSql,
  databaseClientGuide,
  databaseClientInput,
  defaultClientRoleKind,
  revokedClientRoleSql,
} from "./db-clients.ts";
import { platformRegions, regionProfiles } from "./region.ts";

const design = readFileSync(join(import.meta.dir, "..", "..", "docs", "design", "front-door.md"), "utf8");

describe("database client naming (§3.10.3)", () => {
  test("one login role per client: <db>_<client>_<env>", () => {
    expect(clientRoleName("appdb", "storefront", "preview")).toBe("appdb_storefront_preview");
    expect(clientRoleName("app_db", "storefront", "production")).toBe("app_db_storefront_production");
    expect(clientGroupRole("appdb", "readonly")).toBe("appdb_readonly");
  });

  test("names that could collide, look privileged or exceed 63 characters are refused", () => {
    expect(() => clientRoleName("appdb", "store_front", "preview")).toThrow(/Client names/);
    expect(() => clientRoleName("appdb", "Storefront", "preview")).toThrow(/Client names/);
    expect(() => clientRoleName("appdb", "storefront", "pre-view")).toThrow(/Environments/);
    // db `a_b` owns `a_b_runtime`; client `b` of db `a` in "runtime" must not take that name.
    for (const environment of ["runtime", "readonly", "owner", "migration", "backup", "monitor"]) {
      expect(() => clientRoleName("a", "b", environment)).toThrow(/reserved/);
    }
    expect(() => clientRoleName("a".repeat(41), "storefronts", "production")).toThrow(/63-character/);
  });

  test("R5: preview and other environments default to readonly, production to runtime", () => {
    expect(defaultClientRoleKind("production")).toBe("runtime");
    expect(defaultClientRoleKind("preview")).toBe("readonly");
    expect(defaultClientRoleKind("staging")).toBe("readonly");
  });
});

describe("client role SQL", () => {
  test("creates a least-privilege login role IN ROLE its group", () => {
    const [create] = clientRoleSql({
      role: "appdb_storefront_preview",
      group: "appdb_readonly",
      password: "pw",
      connectionLimit: 5,
      exists: false,
    });
    expect(create).toBe(
      'CREATE ROLE "appdb_storefront_preview" WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5 PASSWORD $ark$pw$ark$ IN ROLE "appdb_readonly"',
    );
    expect(
      clientRoleSql({ role: "r", group: "g", password: "pw", connectionLimit: 1, exists: true }),
    ).toEqual([
      'ALTER ROLE "r" WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 1 PASSWORD $ark$pw$ark$',
      'GRANT "g" TO "r"',
    ]);
    expect(revokedClientRoleSql("r", "new")).toEqual(['ALTER ROLE "r" WITH NOLOGIN PASSWORD $ark$new$ark$']);
  });
});

describe("issue request", () => {
  test("accepts names, an optional role kind and a PEM CSR of at most 16 KiB", () => {
    expect(databaseClientInput.parse({ name: "storefront", environment: "preview" })).toEqual({
      name: "storefront",
      environment: "preview",
    });
    const pem = "-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE REQUEST-----\n";
    expect(databaseClientInput.parse({ name: "a", environment: "b", csrPem: pem }).csrPem).toBe(pem);
    expect(() => databaseClientInput.parse({ name: "a", environment: "b", csrPem: "MIIB" })).toThrow(/PEM/);
    expect(() =>
      databaseClientInput.parse({ name: "a", environment: "b", csrPem: `${pem}${" ".repeat(16 * 1024)}` }),
    ).toThrow(/16 KiB/);
    expect(() => databaseClientInput.parse({ name: "a", environment: "b", extra: 1 })).toThrow();
    expect(() => databaseClientInput.parse({ name: "a", environment: "b", roleKind: "owner" })).toThrow();
  });
});

describe("Vercel guide (§3.12)", () => {
  test("the node-postgres module is §3.12's block verbatim, with attachDatabasePool", () => {
    const section = design.slice(design.indexOf("### 3.12 Vercel-side guide"));
    const block = /\*\*node-postgres\. Recommended[^\n]*\n\n```ts\n([\s\S]+?)```/.exec(section)?.[1];
    expect(block).toBeDefined();
    expect(NODE_POSTGRES_SNIPPET).toBe(block!);
    expect(NODE_POSTGRES_SNIPPET).toContain('import { Pool } from "pg";');
    expect(NODE_POSTGRES_SNIPPET).toContain("attachDatabasePool(pool);");
  });

  test("regions follow the platform region preset (iad1 for us-east)", () => {
    for (const region of platformRegions) {
      const guide = databaseClientGuide({
        host: "db.example.com",
        database: "appdb",
        role: "appdb_storefront_production",
        environment: "production",
        roleKind: "runtime",
        region,
      });
      expect(guide.vercelJson).toEqual({ regions: [regionProfiles[region].vercelRegion] });
    }
    expect(
      databaseClientGuide({
        host: "h",
        database: "d",
        role: "r",
        environment: "production",
        roleKind: "runtime",
        region: "us-east",
      }).vercelJsonSnippet,
    ).toBe('{"regions":["iad1"]}');
  });

  test("placeholders without secrets; base64 single-line values with them", () => {
    const placeholders = databaseClientGuide({
      host: "db.example.com",
      database: "appdb",
      role: "appdb_storefront_preview",
      environment: "preview",
      roleKind: "readonly",
      region: "us-east",
    });
    expect(placeholders.env.map((item) => item.name)).toEqual([
      "ARK_DB_HOST",
      "ARK_DB_NAME",
      "ARK_DB_USER",
      "ARK_DB_PASSWORD",
      "ARK_DB_CLIENT_CERT_B64",
      "ARK_DB_CLIENT_KEY_B64",
    ]);
    expect(placeholders.env.find((item) => item.name === "ARK_DB_PASSWORD")?.value).toMatch(/^</);
    expect(placeholders.commands).toContain(
      "vercel env add ARK_DB_USER preview          # appdb_storefront_preview, read-only",
    );
    expect(placeholders.commands).toContain(
      "base64 -i client.key | tr -d '\\n' | vercel env add ARK_DB_CLIENT_KEY_B64 preview --sensitive",
    );
    const cert = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    const filled = databaseClientGuide({
      host: "db.example.com",
      database: "appdb",
      role: "appdb_storefront_production",
      environment: "production",
      roleKind: "runtime",
      region: "eu-central",
      secrets: { password: "pw", certPem: cert, keyPem: "KEY" },
    });
    const values = Object.fromEntries(filled.env.map((item) => [item.name, item]));
    expect(values.ARK_DB_CLIENT_CERT_B64?.value).toBe(Buffer.from(cert).toString("base64"));
    expect(values.ARK_DB_CLIENT_CERT_B64?.value).not.toContain("\n");
    expect(values.ARK_DB_CLIENT_KEY_B64).toEqual({
      name: "ARK_DB_CLIENT_KEY_B64",
      value: "S0VZ",
      sensitive: true,
    });
    expect(values.ARK_DB_PASSWORD?.sensitive).toBe(true);
    expect(values.ARK_DB_HOST?.sensitive).toBe(false);
    expect(filled.vercelRegion).toBe("fra1");
  });
});
