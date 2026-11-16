// FD-16: the §3.10.2 PgBouncer INI/HBA renderers and the client CA bundle selection.
import { describe, expect, test } from "bun:test";
import { join } from "node:path";

import {
  PGBOUNCER_ADMIN_USER,
  pgbouncerConfig,
  pgbouncerHba,
  pgbouncerUserlist,
  renderClientCaBundle,
  scramSha256Verifier,
  scramVerifierMatches,
  selectClientCaBundle,
  type BundleCa,
  type BundleCertificate,
  type BundleClient,
} from "./pgbouncer.ts";

const root = join(import.meta.dir, "..", "..");

/** The literal fenced block that follows `marker` in the design document. */
async function designBlock(fence: "ini" | "text", marker: string) {
  const doc = await Bun.file(join(root, "docs", "design", "front-door.md")).text();
  const section = doc.slice(doc.indexOf("#### 3.10.2 PgBouncer configuration"));
  const from = section.indexOf(marker);
  const start = section.indexOf(`\`\`\`${fence}\n`, from) + fence.length + 4;
  return section.slice(start, section.indexOf("```\n", start));
}

/** The §3.10.2 example: one public database and two client login roles. */
const designExample = {
  mappings: [{ database: "appdb", host: "app-postgres" }],
  users: [
    { name: "appdb_storefront_production", maxUserConnections: 20, maxUserClientConnections: 300 },
    { name: "appdb_storefront_preview", maxUserConnections: 5, maxUserClientConnections: 100 },
  ],
  certificateDir: "/var/lib/ark/certs/db.example.com",
};

describe("§3.10.2 PgBouncer configuration", () => {
  test("renders the design document's INI exactly", async () => {
    expect(pgbouncerConfig(designExample)).toBe(await designBlock("ini", "changes as follows"));
  });

  test("renders the design document's ordered pg_hba.conf exactly", async () => {
    expect(pgbouncerHba()).toBe(await designBlock("text", "Render this complete, ordered"));
  });

  test("the checked-in templates are the closed (no client) rendering", async () => {
    expect(await Bun.file(join(root, "infra", "database", "pgbouncer.ini")).text()).toBe(
      pgbouncerConfig({ mappings: [], users: [] }),
    );
    expect(await Bun.file(join(root, "infra", "database", "pg_hba.conf")).text()).toBe(pgbouncerHba());
  });

  test("uses only standalone comments, verify-full, TLS 1.3 and the admin socket", () => {
    const config = pgbouncerConfig(designExample);
    for (const line of config.split("\n")) {
      if (!line || line.startsWith(";") || /^\[[a-z]+\]$/.test(line)) continue;
      expect(line).toMatch(/^[a-z_]+ = [^;#]+$/);
    }
    const settings = new Map(
      config
        .split("\n")
        .filter((line) => line.includes(" = ") && !line.startsWith(";"))
        .map((line) => line.split(" = ") as [string, string]),
    );
    expect(settings.get("auth_type")).toBe("hba");
    expect(settings.get("client_tls_sslmode")).toBe("verify-full");
    expect(settings.get("client_tls_protocols")).toBe("tlsv1.3");
    expect(settings.get("client_tls_ca_file")).toBe("/var/lib/ark/pgbouncer/client-ca-bundle.pem");
    expect(settings.get("unix_socket_dir")).toBe("/var/run/pgbouncer");
    expect(settings.get("admin_users")).toBe(PGBOUNCER_ADMIN_USER);
    expect(settings.get("max_prepared_statements")).toBe("200");
  });

  test("the HBA admits the administrator only on the local socket", () => {
    const rules = pgbouncerHba()
      .trim()
      .split("\n")
      .map((line) => line.split(/\s+/));
    const firstMatch = (type: "local" | "host" | "hostssl", database: string, user: string) =>
      rules
        .find(
          ([kind, db, role]) =>
            (kind === type || (kind === "host" && type === "hostssl")) &&
            (db === "all" || db === database) &&
            (role === "all" || role === user),
        )
        ?.at(-1);
    expect(firstMatch("local", "pgbouncer", PGBOUNCER_ADMIN_USER)).toBe("scram-sha-256");
    expect(firstMatch("hostssl", "pgbouncer", PGBOUNCER_ADMIN_USER)).toBe("reject");
    expect(firstMatch("hostssl", "appdb", PGBOUNCER_ADMIN_USER)).toBe("reject");
    expect(firstMatch("local", "appdb", "appdb_storefront_production")).toBe("reject");
    expect(firstMatch("hostssl", "appdb", "appdb_storefront_production")).toBe("scram-sha-256");
    expect(firstMatch("host", "appdb", "appdb_storefront_production")).toBe("reject");
  });

  test("refuses the administrator, privileged roles and unsafe values in the INI", () => {
    for (const name of [PGBOUNCER_ADMIN_USER, "appdb_owner", "appdb_migration"]) {
      expect(() =>
        pgbouncerConfig({
          mappings: [],
          users: [{ name, maxUserConnections: 1, maxUserClientConnections: 1 }],
        }),
      ).toThrow(/never be admitted/);
    }
    expect(() =>
      pgbouncerConfig({
        mappings: [],
        users: [{ name: "x\nadmin_users = y", maxUserConnections: 1, maxUserClientConnections: 1 }],
      }),
    ).toThrow(/Invalid/);
    expect(() => pgbouncerConfig({ mappings: [{ database: "app db", host: "app-postgres" }] })).toThrow(
      /Invalid/,
    );
    expect(() => pgbouncerConfig({ mappings: [{ database: "appdb", host: "pg ; x" }] })).toThrow(/Invalid/);
    expect(() => pgbouncerConfig({ mappings: [], certificateDir: "/certs ; x" })).toThrow(/Invalid/);
  });

  test("the userlist carries the administrator's SCRAM verifier, never a colliding role", () => {
    const verifier = scramSha256Verifier("console-secret");
    const list = pgbouncerUserlist(
      [
        { name: "appdb_storefront_production", password: 'pa"ss' },
        { name: "appdb_owner", password: "b" },
        { name: PGBOUNCER_ADMIN_USER, password: "plaintext-collision" },
      ],
      { adminVerifier: verifier },
    );
    expect(list.split("\n")).toEqual([
      `"appdb_storefront_production" "pa""ss"`,
      `"${PGBOUNCER_ADMIN_USER}" "${verifier}"`,
    ]);
    expect(list).not.toContain("console-secret");
    expect(list).not.toContain("plaintext-collision");
    expect(() => pgbouncerUserlist([], { adminVerifier: "plaintext" })).toThrow(/SCRAM/);
  });

  test("SCRAM verifiers have the PostgreSQL shape and verify only their password", () => {
    const verifier = scramSha256Verifier("console-secret");
    expect(verifier).toMatch(
      /^SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]{24}\$[A-Za-z0-9+/=]{44}:[A-Za-z0-9+/=]{44}$/,
    );
    expect(scramVerifierMatches("console-secret", verifier)).toBe(true);
    expect(scramVerifierMatches("other", verifier)).toBe(false);
    expect(scramVerifierMatches("console-secret", "console-secret")).toBe(false);
  });
});

// ---- Bundle selection --------------------------------------------------------------------------

const DAY = 86_400_000;
const now = new Date("2026-11-16T12:00:00Z");
const pem = (id: string) =>
  `-----BEGIN CERTIFICATE-----\n${Buffer.from(`ca:${id}`).toString("base64")}\n-----END CERTIFICATE-----\n`;
const ca = (id: string, overrides: Partial<BundleCa> = {}): BundleCa => ({
  id,
  purpose: "db-client",
  status: "active",
  certPem: pem(id),
  notAfter: new Date(now.getTime() + 1000 * DAY),
  ...overrides,
});
const cert = (id: string, caId: string, overrides: Partial<BundleCertificate> = {}): BundleCertificate => ({
  id,
  caId,
  status: "issued",
  rolloverState: "current",
  supersededBy: null,
  notAfter: new Date(now.getTime() + 60 * DAY),
  ...overrides,
});
const client = (id: string, caId: string, status = "active"): BundleClient => ({ id, caId, status });
const select = (clients: BundleClient[], certificates: BundleCertificate[], cas: BundleCa[]) =>
  selectClientCaBundle({ clients, certificates, cas, now });
const byCa = (result: ReturnType<typeof select>) =>
  Object.fromEntries(result.generations.map((item) => [item.caId, item.role]));

describe("client CA bundle generation", () => {
  test("includes current, linked pending and retiring generations of an active client", () => {
    // Rollover N-1 -> N (promoted, N-1 retiring until its deadline) and N -> N+1 (pending).
    const certificates = [
      cert("c0", "ca0", {
        rolloverState: "superseded",
        supersededBy: "c1",
        notAfter: new Date(now.getTime() + DAY),
      }),
      cert("c1", "ca1", { supersededBy: "c2" }),
      cert("c2", "ca2", { rolloverState: "pending", notAfter: new Date(now.getTime() + 90 * DAY) }),
    ];
    const result = select([client("dbc_a", "ca1")], certificates, [ca("ca0"), ca("ca1"), ca("ca2")]);
    expect(byCa(result)).toEqual({ ca1: "current", ca2: "pending", ca0: "retiring" });
    expect(result.admittedClientIds).toEqual(["dbc_a"]);
    expect(renderClientCaBundle(result.generations)).toBe(`${pem("ca1")}${pem("ca2")}${pem("ca0")}`);
  });

  test("follows certificates, not just the current ca_id pointer", () => {
    // The pointer still names the predecessor generation while the successor is current: both
    // are found through superseded_by, and a stale pointer whose certificates are revoked
    // contributes nothing.
    const certificates = [
      cert("c1", "ca1", { rolloverState: "superseded", supersededBy: "c2" }),
      cert("c2", "ca2"),
    ];
    expect(byCa(select([client("dbc_a", "ca1")], certificates, [ca("ca1"), ca("ca2")]))).toEqual({
      ca1: "retiring",
      ca2: "current",
    });
    const revokedPointer = [
      cert("c1", "ca1", { status: "revoked", supersededBy: "c2" }),
      cert("c2", "ca2", { rolloverState: "pending" }),
    ];
    expect(byCa(select([client("dbc_a", "ca1")], revokedPointer, [ca("ca1"), ca("ca2")]))).toEqual({
      ca2: "pending",
    });
  });

  test("excludes revoked clients, even when another client shares the CA", () => {
    const certificates = [
      cert("a1", "caA", { supersededBy: "a2" }),
      cert("a2", "caA2", { rolloverState: "pending" }),
    ];
    const result = select(
      [client("dbc_a", "caA", "revoked"), client("dbc_b", "caB")],
      [...certificates, cert("b1", "caB")],
      [ca("caA"), ca("caA2"), ca("caB")],
    );
    expect(byCa(result)).toEqual({ caB: "current" });
    expect(result.admittedClientIds).toEqual(["dbc_b"]);
    const shared = select(
      [client("dbc_a", "caS", "revoked"), client("dbc_b", "caS")],
      [cert("s1", "caS")],
      [ca("caS")],
    );
    expect(shared.generations).toEqual([]);
    expect(shared.excluded).toContainEqual({ caId: "caS", reason: "CA linked to a revoked client" });
  });

  test("excludes revoked generations: revoked certificates and revoked CAs", () => {
    const result = select(
      [client("dbc_a", "ca1"), client("dbc_b", "caB")],
      [
        cert("c1", "ca1", { status: "revoked", supersededBy: "c2" }),
        cert("c2", "ca2", { rolloverState: "pending" }),
        cert("b1", "caB"),
      ],
      [ca("ca1"), ca("ca2"), ca("caB", { status: "revoked" })],
    );
    expect(byCa(result)).toEqual({ ca2: "pending" });
    expect(result.excluded).toEqual(
      expect.arrayContaining([
        { caId: "ca1", reason: "certificate revoked" },
        { caId: "caB", reason: "CA revoked" },
      ]),
    );
  });

  test("excludes generations past their retirement deadline (not_after + 5 s)", () => {
    const at = (offset: number) => new Date(now.getTime() + offset);
    const certificates = [
      cert("c0", "ca0", { rolloverState: "superseded", supersededBy: "c1", notAfter: at(-5_000) }),
      cert("c1", "ca1", { rolloverState: "superseded", supersededBy: "c2", notAfter: at(-4_000) }),
      cert("c2", "ca2"),
    ];
    const result = select([client("dbc_a", "ca2")], certificates, [ca("ca0"), ca("ca1"), ca("ca2")]);
    // ca0's deadline (now - 5 s + 5 s) has passed; ca1 is still inside its 5-second drain.
    expect(byCa(result)).toEqual({ ca2: "current", ca1: "retiring" });
    expect(result.excluded).toContainEqual({ caId: "ca0", reason: "past retirement deadline" });
    expect(
      select([client("dbc_a", "ca2")], [cert("c2", "ca2", { status: "expired" })], [ca("ca2")]).generations,
    ).toEqual([]);
  });

  test("excludes CAs of another purpose and expired CAs; empty bundles are refused", () => {
    const result = select(
      [client("dbc_a", "caT"), client("dbc_b", "caX")],
      [cert("t1", "caT"), cert("x1", "caX")],
      [ca("caT", { purpose: "tcp-client" }), ca("caX", { notAfter: new Date(now.getTime() - 1) })],
    );
    expect(result.generations).toEqual([]);
    expect(result.admittedClientIds).toEqual([]);
    expect(() => renderClientCaBundle(result.generations)).toThrow(/empty/);
    expect(() =>
      renderClientCaBundle([{ certPem: "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----" }]),
    ).toThrow(/PEM certificates only/);
  });
});
