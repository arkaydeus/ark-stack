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
  databaseClientRolloverGuide,
  clientRolloverStatus,
  defaultClientRoleKind,
  earlyRolloverInput,
  revokedClientRoleSql,
  rolloverAlertLevel,
  rolloverAlertTitle,
  rolloverDue,
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

const rolloverCert = (
  id: string,
  rolloverState: string,
  status = "issued",
  supersededBy: string | null = null,
) => ({
  id,
  status,
  rolloverState,
  supersededBy,
});

describe("automatic rollover (§3.10.4, FD-28)", () => {
  const DAY = 86_400_000;
  const notAfter = new Date("2027-04-01T00:00:00Z");
  const before = (days: number, ms = 0) => new Date(notAfter.getTime() - days * DAY + ms);

  test("the successor is due from T−30", () => {
    expect(rolloverDue(notAfter, before(31))).toBe(false);
    expect(rolloverDue(notAfter, before(30, -1))).toBe(false);
    expect(rolloverDue(notAfter, before(30))).toBe(true);
    expect(rolloverDue(notAfter, before(1))).toBe(true);
  });

  test("the pending alert is info at T−30, warning at T−14, critical at T−7 and after expiry", () => {
    expect(rolloverAlertLevel(notAfter, before(31))).toBeNull();
    expect(rolloverAlertLevel(notAfter, before(30))).toBe("info");
    expect(rolloverAlertLevel(notAfter, before(15))).toBe("info");
    expect(rolloverAlertLevel(notAfter, before(14))).toBe("warning");
    expect(rolloverAlertLevel(notAfter, before(8))).toBe("warning");
    expect(rolloverAlertLevel(notAfter, before(7))).toBe("critical");
    expect(rolloverAlertLevel(notAfter, before(-3))).toBe("critical");
    expect(rolloverAlertTitle({ role: "a_b_production", notAfter, now: before(14) })).toMatch(
      /expires in 14 day\(s\)/,
    );
    expect(rolloverAlertTitle({ role: "a_b_production", notAfter, now: before(-1), needsCsr: true })).toMatch(
      /expired .* before its successor was delivered\. submit a CSR/,
    );
  });

  test("client rollover status: none → pending → delivered → retired", () => {
    expect(clientRolloverStatus([rolloverCert("n", "current")])).toBe("none");
    expect(
      clientRolloverStatus([rolloverCert("n", "current", "issued", "n1"), rolloverCert("n1", "pending")]),
    ).toBe("pending");
    expect(
      clientRolloverStatus([rolloverCert("n", "superseded", "issued", "n1"), rolloverCert("n1", "current")]),
    ).toBe("delivered");
    expect(
      clientRolloverStatus([rolloverCert("n", "retired", "expired", "n1"), rolloverCert("n1", "current")]),
    ).toBe("retired");
  });

  test("the guided rollover step changes only the certificate and key values (§3.12)", () => {
    const placeholder = databaseClientRolloverGuide({ environment: "production" });
    expect(placeholder.env.map((item) => item.name)).toEqual([
      "ARK_DB_CLIENT_CERT_B64",
      "ARK_DB_CLIENT_KEY_B64",
    ]);
    expect(placeholder.commands).toBe(
      [
        "# Reveal the new bundle once in Ark (step-up), then:",
        "base64 -i client-next.crt | tr -d '\\n' | vercel env add ARK_DB_CLIENT_CERT_B64 production --sensitive --force",
        "base64 -i client-next.key | tr -d '\\n' | vercel env add ARK_DB_CLIENT_KEY_B64 production --sensitive --force",
        "vercel deploy --prod        # or redeploy from the dashboard",
        '# Then press "Confirm rollover" in Ark.',
        "",
      ].join("\n"),
    );
    // §3.12's manual rollover block, as documented.
    for (const line of placeholder.commands.trim().split("\n").slice(1, 3)) expect(design).toContain(line);
    const real = databaseClientRolloverGuide({
      environment: "preview",
      secrets: { certPem: "CERT", keyPem: "KEY" },
    });
    expect(real.env.map((item) => Buffer.from(item.value, "base64").toString())).toEqual(["CERT", "KEY"]);
    expect(real.commands).toContain("vercel deploy        #");
    expect(earlyRolloverInput.safeParse({}).success).toBe(true);
    expect(earlyRolloverInput.safeParse({ csrPem: "nope" }).success).toBe(false);
    expect(earlyRolloverInput.safeParse({ extra: 1 }).success).toBe(false);
  });
});
