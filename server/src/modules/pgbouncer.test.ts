// FD-16: PgBouncer plan, files and reload/verify retries (no database, no Docker).
import { describe, expect, test } from "bun:test";
import { X509Certificate, generateKeyPairSync } from "node:crypto";
import { mkdtemp, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PGBOUNCER_FILES } from "@ark-stack/shared";

import {
  PgbouncerReloadError,
  RetirementError,
  assertDrainedByDeadline,
  denyAllCaPem,
  normalizeFingerprint,
  killRoleClients,
  pgbouncerAdminCommand,
  planPgbouncer,
  roleClientIds,
  reloadAndVerify,
  renderPgbouncerFiles,
  retireGeneration,
  writePgbouncerFiles,
  type PlanClient,
} from "./pgbouncer.ts";
import * as x509 from "./x509.ts";

const DAY = 86_400_000;
const now = new Date("2026-11-16T12:00:00Z");

/** A real Ark-shaped CA and a client certificate under it, for OpenSSL verification. */
function caPem(name: string) {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = x509.spkiDer(privateKey);
  const keyId = x509.keyIdentifier(spki);
  const subject = x509.name([{ type: "CN", value: `Ark db-client CA ${name}` }]);
  const tbs = x509.sequence(
    x509.explicit(0, x509.integer(2)),
    x509.integer(1),
    x509.ecdsaWithSha256(),
    subject,
    x509.sequence(x509.time(new Date(now.getTime() - DAY)), x509.time(new Date(now.getTime() + 1000 * DAY))),
    subject,
    spki,
    x509.explicit(
      3,
      x509.sequence(
        x509.extension(x509.OID.basicConstraints, true, x509.basicConstraintsValue(true, 0)),
        x509.extension(x509.OID.keyUsage, true, x509.keyUsageValue(["keyCertSign", "cRLSign"])),
        x509.extension(x509.OID.subjectKeyIdentifier, false, x509.subjectKeyIdentifierValue(keyId)),
        x509.extension(x509.OID.authorityKeyIdentifier, false, x509.authorityKeyIdentifierValue(keyId)),
      ),
    ),
  );
  return x509.toPem("CERTIFICATE", x509.signStructure(tbs, privateKey));
}

const databases = [
  { id: "mdb_app", name: "appdb", exposure: "public" },
  { id: "mdb_other", name: "otherdb", exposure: "public" },
  { id: "mdb_private", name: "privdb", exposure: "private" },
];
const cas = ["caA", "caB", "caP"].map((id) => ({
  id,
  purpose: "db-client",
  status: "active",
  certPem: caPem(id),
  notAfter: new Date(now.getTime() + 1000 * DAY),
}));
const certificates = cas.map((item) => ({
  id: `cert_${item.id}`,
  caId: item.id,
  status: "issued",
  rolloverState: "current",
  supersededBy: null,
  notAfter: new Date(now.getTime() + 60 * DAY),
}));
const client = (
  id: string,
  databaseId: string,
  caId: string,
  role: string,
  extra: Partial<PlanClient> = {},
) => ({
  id,
  databaseId,
  environment: "production",
  status: "active",
  caId,
  role: { name: role, connectionLimit: 20, password: `pw-${role}` },
  ...extra,
});

describe("planPgbouncer", () => {
  test("with zero admitted clients: not routed, no mapping, and a deny-all bundle, never empty", () => {
    for (const clients of [
      [],
      [client("dbc_rev", "mdb_app", "caA", "appdb_shop_production", { status: "revoked" })],
      [client("dbc_priv", "mdb_private", "caP", "privdb_shop_production")],
      [
        client("dbc_nopw", "mdb_app", "caA", "appdb_shop_production", {
          role: { name: "appdb_shop_production", connectionLimit: 1, password: null },
        }),
      ],
    ]) {
      const plan = planPgbouncer({ databases, clients, certificates, cas, now, host: "app-postgres" });
      expect(plan.routed).toBe(false);
      expect(plan.mappings).toEqual([]);
      expect(plan.users).toEqual([]);
      expect(plan.credentials).toEqual([]);
      const bundle = plan.caBundle.match(/-----BEGIN CERTIFICATE-----/g) ?? [];
      expect(bundle.length).toBe(1);
      const deny = new X509Certificate(plan.caBundle);
      expect(deny.subject).toContain("Ark db-client CA deny-all");
      expect(deny.ca).toBe(true);
      for (const item of cas) expect(plan.caBundle).not.toContain(item.certPem.trim());
      const files = renderPgbouncerFiles({ plan });
      expect(files[PGBOUNCER_FILES.config]).toContain(
        "[databases]\n; per admitted public database\n\n[users]",
      );
      expect(files[PGBOUNCER_FILES.caBundle]!.trim().length).toBeGreaterThan(0);
    }
  });

  test("each deny-all CA is fresh and its key is never returned", () => {
    const a = denyAllCaPem(now);
    const b = denyAllCaPem(now);
    expect(a).not.toBe(b);
    expect(a).not.toContain("PRIVATE KEY");
    expect(new X509Certificate(a).checkIssued(new X509Certificate(a))).toBe(true);
  });

  test("admits active clients of public databases and maps only their databases", () => {
    const plan = planPgbouncer({
      databases,
      clients: [
        client("dbc_a", "mdb_app", "caA", "appdb_shop_production"),
        client("dbc_b", "mdb_app", "caB", "appdb_shop_preview", { environment: "preview" }),
        client("dbc_p", "mdb_private", "caP", "privdb_shop_production"),
      ],
      certificates,
      cas,
      now,
      host: "app-postgres",
    });
    expect(plan.routed).toBe(true);
    expect(plan.mappings).toEqual([{ database: "appdb", host: "app-postgres" }]);
    expect(plan.users).toEqual([
      { name: "appdb_shop_preview", maxUserConnections: 20, maxUserClientConnections: 100 },
      { name: "appdb_shop_production", maxUserConnections: 20, maxUserClientConnections: 300 },
    ]);
    expect(plan.admittedClientIds).toEqual(["dbc_b", "dbc_a"]);
    expect(plan.caBundle).toContain(cas[0]!.certPem.trim());
    expect(plan.caBundle).toContain(cas[1]!.certPem.trim());
    expect(plan.caBundle).not.toContain(cas[2]!.certPem.trim());
    const files = renderPgbouncerFiles({ plan, adminPassword: "console-secret" });
    expect(files[PGBOUNCER_FILES.userlist]).toContain('"appdb_shop_production" "pw-appdb_shop_production"');
    expect(files[PGBOUNCER_FILES.userlist]).toContain('"ark_pgbouncer_admin" "SCRAM-SHA-256$');
    expect(files[PGBOUNCER_FILES.userlist]).not.toContain("console-secret");
    expect(files[PGBOUNCER_FILES.config]).toContain(
      "appdb = host=app-postgres dbname=appdb pool_size=10 max_db_connections=30 max_db_client_connections=500\n",
    );
    expect(files[PGBOUNCER_FILES.config]).not.toContain("privdb");
  });
});

describe("writePgbouncerFiles", () => {
  test("replaces every file atomically with mode 0600", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ark-pgbouncer-files-"));
    try {
      const plan = planPgbouncer({
        databases: [],
        clients: [],
        certificates: [],
        cas: [],
        now,
        host: "app-postgres",
      });
      const written = await writePgbouncerFiles(dir, renderPgbouncerFiles({ plan }));
      expect(written.files).toEqual([
        PGBOUNCER_FILES.caBundle,
        PGBOUNCER_FILES.hba,
        PGBOUNCER_FILES.userlist,
        PGBOUNCER_FILES.config,
      ]);
      expect((await readdir(dir)).toSorted()).toEqual(Object.values(PGBOUNCER_FILES).toSorted());
      for (const name of Object.values(PGBOUNCER_FILES)) {
        expect((await stat(join(dir, name))).mode & 0o777).toBe(0o600);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("reloadAndVerify", () => {
  const delays: number[] = [];
  const sleep = async (ms: number) => {
    delays.push(ms);
  };

  test("a failing reload is retried with backoff and never reported as success", async () => {
    delays.length = 0;
    let calls = 0;
    const error = await reloadAndVerify({
      reload: async () => {
        calls += 1;
        throw new Error("connect ENOENT /var/run/pgbouncer/.s.PGSQL.5432");
      },
      attempts: 3,
      delayMs: 100,
      sleep,
    }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(PgbouncerReloadError);
    expect((error as PgbouncerReloadError).attempts).toBe(3);
    expect((error as PgbouncerReloadError).failures).toHaveLength(3);
    expect(calls).toBe(3);
    expect(delays).toEqual([100, 200]);
  });

  test("a reload that keeps serving the old certificate fails; a later match succeeds", async () => {
    delays.length = 0;
    const served = ["AA:BB", "AA:BB", "CC:DD"];
    const result = await reloadAndVerify({
      reload: async () => undefined,
      servedFingerprint: async () => served.shift()!,
      expectedFingerprint: "ccdd",
      attempts: 3,
      delayMs: 10,
      sleep,
    });
    expect(result.attempts).toBe(3);
    expect(result.fingerprint).toBe("ccdd");
    expect(result.failures[0]).toMatch(/served certificate aabb is not the renewed ccdd/);
    const stale = await reloadAndVerify({
      reload: async () => undefined,
      servedFingerprint: async () => "aa:bb",
      expectedFingerprint: "CC:DD",
      attempts: 2,
      sleep,
    }).catch((caught: unknown) => caught);
    expect(stale).toBeInstanceOf(PgbouncerReloadError);
    expect(normalizeFingerprint("AB:CD:EF")).toBe("abcdef");
  });

  test("the console client refuses anything but RELOAD, SHOW, KILL_CLIENT <id> and the FD-28 fence", async () => {
    for (const command of [
      "SHUTDOWN",
      "KILL appdb",
      "DISABLE",
      "DISABLE appdb; SHUTDOWN",
      "ENABLE Appdb",
      "PAUSE appdb",
      "SET client_login_timeout = 0",
      "SET client_login_timeout = 1; SHUTDOWN",
      "SET max_client_conn = 1",
      "RELOAD; SHUTDOWN",
      "set x = 1",
      "KILL_CLIENT",
      "KILL_CLIENT 0",
      "KILL_CLIENT 1; SHUTDOWN",
      "KILL_CLIENT abc",
      "KILL_CLIENT 12345678901234567890",
    ]) {
      await expect(pgbouncerAdminCommand(command, { password: "x" })).rejects.toThrow(/Refusing/);
    }
  });

  test("revocation kills only a valid login role, never the console administrator", async () => {
    await expect(roleClientIds("bad role'; --", { password: "x" })).rejects.toThrow(/Invalid PgBouncer role/);
    await expect(killRoleClients("ark_pgbouncer_admin", { password: "x" })).rejects.toThrow(/administrator/);
  });
});

// ---- FD-28 generation retirement (fence, reload, role and pre-auth drain, reopen) ---------------

const stamp = (ms: number) =>
  new Date(ms)
    .toISOString()
    .replace("T", " ")
    .replace(/\.\d+Z$/, " UTC");

/** A console that behaves like PgBouncer 1.26's: SHOW CLIENTS omits pre-auth (login) clients. */
function fakeConsole(input: {
  clients: Array<{ id: string; user: string }>;
  logins?: Array<{ connectAt: number }>;
  clock: { now: number };
  /** Role whose sessions KILL_CLIENT cannot close (a stuck socket). */
  stuckRole?: string;
}) {
  const commands: string[] = [];
  let clients = [...input.clients];
  let logins = [...(input.logins ?? [])];
  let loginTimeout = 10;
  let disabled = false;
  const admin = async (command: string) => {
    commands.push(command);
    // The janitor closes logins older than client_login_timeout (it runs every ~1/3 s).
    logins = logins.filter((item) => input.clock.now - item.connectAt <= loginTimeout * 1000);
    if (command.startsWith("DISABLE ")) disabled = true;
    else if (command.startsWith("ENABLE ")) disabled = false;
    else if (command.startsWith("SET client_login_timeout = ")) loginTimeout = Number(command.split("= ")[1]);
    else if (command === "SHOW CLIENTS") return clients.map((item) => ({ ...item, state: "active" }));
    else if (command === "SHOW SOCKETS")
      return [
        ...clients.map((item) => ({ ...item, state: "cl_active", connect_time: stamp(0) })),
        ...logins.map((item, index) => ({
          id: String(900 + index),
          user: "",
          state: "cl_login",
          connect_time: stamp(item.connectAt),
        })),
      ];
    else if (command.startsWith("KILL_CLIENT ")) {
      const id = command.split(" ")[1];
      clients = clients.filter((item) => item.id !== id || item.user === input.stuckRole);
    }
    return [];
  };
  return { admin, commands, state: () => ({ clients, logins, disabled, loginTimeout }) };
}

async function refusingConsole(): Promise<never> {
  throw new Error("must not be called");
}

describe("retireGeneration (§3.10.4 step 4)", () => {
  const start = Date.parse("2027-04-01T00:00:00Z");

  test("fences, reloads, kills the role and waits out pre-reload logins, then reopens by the deadline", async () => {
    const clock = { now: start };
    const pgb = fakeConsole({
      clients: [
        { id: "11", user: "appdb_shop_production" },
        { id: "12", user: "appdb_shop_production" },
        { id: "13", user: "appdb_other_production" },
      ],
      // A handshake completed with the old certificate just before the reload, still logging in.
      logins: [{ connectAt: start - 400 }],
      clock,
    });
    let applied = false;
    const result = await retireGeneration({
      database: "appdb",
      role: "appdb_shop_production",
      deadline: new Date(start + 5_000),
      admin: pgb.admin,
      apply: async () => {
        expect(pgb.commands).toEqual(["DISABLE appdb"]); // fenced before the reduced bundle loads
        applied = true;
        clock.now += 15;
      },
      clock: () => clock.now,
      sleep: async (ms) => {
        clock.now += Math.max(ms, 340);
      },
    });
    expect(applied).toBe(true);
    expect(pgb.commands[0]).toBe("DISABLE appdb");
    expect(pgb.commands[1]).toBe("SET client_login_timeout = 1");
    expect(pgb.commands).toContain("KILL_CLIENT 11");
    expect(pgb.commands).toContain("KILL_CLIENT 12");
    expect(pgb.commands).not.toContain("KILL_CLIENT 13");
    expect(pgb.commands.slice(-2)).toEqual(["SET client_login_timeout = 10", "ENABLE appdb"]);
    expect(pgb.state()).toMatchObject({ disabled: false, loginTimeout: 10, logins: [] });
    expect(pgb.state().clients).toEqual([{ id: "13", user: "appdb_other_production" }]);
    expect(result.killedRoleClients).toBe(2);
    expect(result.preAuthWaited).toBe(1);
    expect(result.withinDeadline).toBe(true);
    expect(result.fencedAt).toBeLessThanOrEqual(result.reloadedAt);
    expect(result.drainedAt).toBeLessThan(start + 5_000);
    expect(result.reopenedAt).toBeGreaterThanOrEqual(result.drainedAt);
  });

  test("logins that start after the reload do not hold the fence", async () => {
    const clock = { now: start };
    const pgb = fakeConsole({ clients: [], clock });
    const result = await retireGeneration({
      database: "appdb",
      role: "appdb_shop_production",
      deadline: new Date(start + 5_000),
      admin: async (command) => {
        if (command === "SHOW SOCKETS")
          return [{ id: "1", user: "", state: "cl_login", connect_time: "2027-04-01 00:00:03 UTC" }];
        return pgb.admin(command);
      },
      apply: async () => undefined,
      clock: () => clock.now,
      sleep: async (ms) => {
        clock.now += ms;
      },
    });
    expect(result.preAuthWaited).toBe(0);
    expect(result.iterations).toBe(1);
  });

  test("a session that survives KILL_CLIENT fails the deadline and leaves the fence in place", async () => {
    const clock = { now: start };
    const pgb = fakeConsole({
      clients: [{ id: "21", user: "appdb_shop_production" }],
      clock,
      stuckRole: "appdb_shop_production",
    });
    const failure = await retireGeneration({
      database: "appdb",
      role: "appdb_shop_production",
      deadline: new Date(start + 5_000),
      admin: pgb.admin,
      apply: async () => undefined,
      clock: () => clock.now,
      sleep: async () => {
        clock.now += 500;
      },
    }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(RetirementError);
    expect((failure as Error).message).toMatch(/missed its deadline: 1 session/);
    expect((failure as RetirementError).timeline.withinDeadline).toBe(false);
    expect((failure as RetirementError).timeline.reloadedAt).toBe(start);
    expect(pgb.commands).not.toContain("ENABLE appdb");
    expect(pgb.state().disabled).toBe(true);
  });

  test("ENABLE is best-effort when the database left [databases] with the reload", async () => {
    const clock = { now: start };
    const pgb = fakeConsole({ clients: [], clock });
    const result = await retireGeneration({
      database: "appdb",
      role: "appdb_shop_production",
      deadline: new Date(start + 5_000),
      admin: async (command) => {
        if (command.startsWith("ENABLE")) throw new Error("no such database: appdb");
        return pgb.admin(command);
      },
      apply: async () => ({ databaseMapped: false }),
      clock: () => clock.now,
    });
    expect(result.reopenSkipped).toBe("database no longer mapped");
  });

  test("refuses the administrator and malformed names before touching the console", async () => {
    const base = { deadline: new Date(start), admin: refusingConsole, apply: async () => undefined };
    await expect(
      retireGeneration({ ...base, database: "appdb", role: "ark_pgbouncer_admin" }),
    ).rejects.toThrow(/administrator/);
    await expect(retireGeneration({ ...base, database: "appdb", role: "bad role" })).rejects.toThrow(
      /Invalid/,
    );
    await expect(retireGeneration({ ...base, database: "app db", role: "appdb_x_y" })).rejects.toThrow(
      /Invalid/,
    );
  });

  test("expiry without a drain is a failure", () => {
    const deadline = new Date(start + 5_000);
    expect(() =>
      assertDrainedByDeadline({ role: "r", deadline, observedAt: new Date(start + 6_000), sessions: 1 }),
    ).toThrow(/still open after the retirement deadline/);
    expect(
      assertDrainedByDeadline({ role: "r", deadline, observedAt: new Date(start + 6_000), sessions: 0 }),
    ).toBe(true);
    expect(() =>
      assertDrainedByDeadline({ role: "r", deadline, observedAt: new Date(start + 1_000), sessions: 0 }),
    ).toThrow(/has not passed/);
  });
});
