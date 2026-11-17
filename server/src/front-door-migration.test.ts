// Runtime tests of the front-door migration (docs/design/front-door.md §3.1, FD-04).
//
// Each case builds a disposable schema inside DATABASE_URL's database (no CREATE DATABASE
// privilege needed), applies the existing migrations through 0012, and then runs either the
// literal §3.1 SQL from the design document or the shipped 0013 migration. The region columns
// that §3.1 lists ship separately in 0014 (FD-03), which is checked here as well.

import { afterAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { join } from "node:path";

import { parseEnvFile } from "@ark-stack/shared";
import { SQL } from "drizzle-orm";
import { getTableConfig, PgDialect, type PgTable } from "drizzle-orm/pg-core";
import postgres from "postgres";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const schema = await import("./schema.ts");

const root = join(import.meta.dir, "..", "..");
const migrationsDir = join(root, "server", "drizzle");
const design = await Bun.file(join(root, "docs", "design", "front-door.md")).text();
// The first ```sql block of the design is §3.1's migration.
const literalSql = `${/```sql\n([\s\S]*?)\n```/.exec(design)?.[1] ?? ""}\n`;
const migration0013 = await Bun.file(join(migrationsDir, "0013_front_door.sql")).text();
const migration0014 = await Bun.file(join(migrationsDir, "0014_region.sql")).text();
// FD-03 owns the region columns, so 0013 ships §3.1 without these two lines.
const REGION_LINES = [
  "  ADD COLUMN region text NOT NULL DEFAULT 'us-east',",
  '  ADD COLUMN vps_region_label text,               -- free text: "Hetzner ash", "DO nyc3"; recorded only',
];

const migrationFiles = (await readdir(migrationsDir)).filter((file) => file.endsWith(".sql")).toSorted();
const through = (last: string) => migrationFiles.filter((file) => file.slice(0, 4) <= last);

const url = process.env.DATABASE_URL;
if (!url) throw new Error("DATABASE_URL is required for the front-door migration tests.");
const admin = postgres(url, { max: 1, onnotice: () => {} });
const created: string[] = [];

afterAll(async () => {
  for (const name of created) await admin.unsafe(`DROP SCHEMA IF EXISTS "${name}" CASCADE`);
  await admin.end();
});

type Sql = ReturnType<typeof postgres>;

/** A connection whose search_path is a fresh, empty schema. */
async function scratch(label: string): Promise<Sql> {
  const name = `fd_${label}_${crypto.randomUUID().replaceAll("-", "").slice(0, 10)}`;
  if (!/^fd_[a-z0-9]+_[a-f0-9]{10}$/.test(name)) throw new Error("Unsafe scratch schema name.");
  await admin.unsafe(`CREATE SCHEMA "${name}"`);
  created.push(name);
  const db = postgres(url as string, { max: 1, onnotice: () => {}, connection: { search_path: name } });
  return db;
}

async function apply(db: Sql, files: string[]) {
  for (const file of files) await db.unsafe(await Bun.file(join(migrationsDir, file)).text());
}

async function seedUser(db: Sql, id = "legacy") {
  await db`INSERT INTO "user" (id, name, email) VALUES (${id}, 'Legacy', ${`${id}@example.com`})`;
}

async function insertSessionWithoutOrigin(db: Sql, id: string) {
  await db`
    INSERT INTO session (id, expires_at, token, user_id)
    VALUES (${id}, now() + interval '1 day', ${`${id}-token`}, 'legacy')
  `;
}

/** Fresh: through 0012 on an empty schema. Upgrade: an install from 0003 with live data, upgraded. */
async function prepare(kind: "fresh" | "upgrade") {
  const db = await scratch(kind);
  if (kind === "fresh") {
    await apply(db, through("0012"));
    await seedUser(db);
    return db;
  }
  await apply(db, through("0003"));
  await seedUser(db);
  await insertSessionWithoutOrigin(db, "legacy-session");
  await db`
    INSERT INTO domain_claims (id, name, ownership_token) VALUES ('dom_legacy', 'legacy.example', 'tok')
  `;
  await db`INSERT INTO platform_settings (id) VALUES ('default') ON CONFLICT DO NOTHING`;
  await apply(
    db,
    migrationFiles.filter((file) => file.slice(0, 4) > "0003" && file.slice(0, 4) <= "0012"),
  );
  // Sessions created after 0012 but before 0013 have no origin either.
  await insertSessionWithoutOrigin(db, "pre-0013-session");
  return db;
}

async function expectSessionOriginContract(db: Sql, legacySessions: string[]) {
  const sessions = await db`SELECT id, origin FROM session ORDER BY id`;
  expect(sessions.map((row) => [row.id, row.origin])).toEqual(
    legacySessions.toSorted().map((id) => [id, "admin"]),
  );
  await expect(insertSessionWithoutOrigin(db, "missing-origin")).rejects.toThrow(
    /null value in column "origin"/,
  );
  // Assimilate Postgres.js's lazy Query before passing it to Bun's promise matcher.
  await expect(
    Promise.resolve(db`INSERT INTO session (id, expires_at, token, user_id, origin)
       VALUES ('bad-origin', now() + interval '1 day', 'bad-origin-token', 'legacy', 'public')`),
  ).rejects.toThrow(/session_origin_check/);
  await db`INSERT INTO session (id, expires_at, token, user_id, origin)
           VALUES ('gate-session', now() + interval '1 day', 'gate-token', 'legacy', 'gate')`;
  const [column] = await db`
    SELECT is_nullable, column_default FROM information_schema.columns
    WHERE table_schema = current_schema() AND table_name = 'session' AND column_name = 'origin'
  `;
  expect(column).toEqual({ is_nullable: "NO", column_default: null });
}

async function foreignKeys(db: Sql) {
  const rows = await db`
    SELECT con.conrelid::regclass::text AS source, con.confrelid::regclass::text AS target
    FROM pg_constraint con
    JOIN pg_namespace ns ON ns.oid = con.connamespace
    WHERE con.contype = 'f' AND ns.nspname = current_schema()
  `;
  return new Set(rows.map((row) => `${row.source}->${row.target}`));
}

const EXPECTED_FOREIGN_KEYS = [
  "tailnet_nodes->tailnet_snapshots",
  "private_cas->secrets",
  "front_routes->endpoints",
  "front_routes->private_cas",
  'front_routes->"user"',
  "front_route_access->front_routes",
  'front_route_access->"user"',
  "gate_handoffs->front_routes",
  "gate_handoffs->session",
  "gate_sessions->front_routes",
  "gate_sessions->session",
  "client_certificates->private_cas",
  "client_certificates->client_certificates",
  "client_certificates->secrets",
  "database_clients->managed_databases",
  "database_clients->database_roles",
  "database_clients->private_cas",
  "vercel_integrations->database_clients",
  "vercel_integrations->secrets",
  "backup_targets->secrets",
];

describe("§3.1 literal SQL from the design document", () => {
  test("the design block is present and creates private_cas before front_routes", () => {
    expect(literalSql).toContain("CREATE TABLE front_routes");
    expect(literalSql.indexOf("CREATE TABLE private_cas")).toBeLessThan(
      literalSql.indexOf("CREATE TABLE front_routes"),
    );
    expect(literalSql).not.toMatch(/origin text[^;]*DEFAULT/);
  });

  for (const kind of ["fresh", "upgrade"] as const) {
    test(`runs after 0012 on a ${kind} schema: FKs, origin backfill and no-default origin`, async () => {
      const db = await prepare(kind);
      try {
        await db.unsafe(literalSql);
        const fks = await foreignKeys(db);
        for (const fk of EXPECTED_FOREIGN_KEYS) expect(fks).toContain(fk);
        await expectSessionOriginContract(
          db,
          kind === "upgrade" ? ["legacy-session", "pre-0013-session"] : [],
        );
        if (kind === "upgrade") {
          const [settings] = await db`SELECT region FROM platform_settings WHERE id = 'default'`;
          expect(settings?.region).toBe("us-east");
        }
      } finally {
        await db.end();
      }
    });
  }
});

describe("0013_front_door.sql", () => {
  test("is the literal §3.1 SQL without the FD-03 region columns", () => {
    for (const line of REGION_LINES) expect(literalSql).toContain(`${line}\n`);
    const expected = REGION_LINES.reduce((text, line) => text.replace(`${line}\n`, ""), literalSql);
    const body = migration0013.slice(migration0013.indexOf("\n\n") + 2);
    const header = migration0013.slice(0, migration0013.indexOf("\n\n"));
    expect(header.split("\n").every((line) => line.startsWith("--"))).toBe(true);
    expect(body).toBe(expected);
  });

  for (const kind of ["fresh", "upgrade"] as const) {
    test(`applies after 0012 on a ${kind} schema`, async () => {
      const db = await prepare(kind);
      try {
        await apply(db, ["0013_front_door.sql"]);
        const fks = await foreignKeys(db);
        for (const fk of EXPECTED_FOREIGN_KEYS) expect(fks).toContain(fk);
        await expectSessionOriginContract(
          db,
          kind === "upgrade" ? ["legacy-session", "pre-0013-session"] : [],
        );
        if (kind === "upgrade") {
          const [settings] = await db`SELECT * FROM platform_settings WHERE id = 'default'`;
          expect(settings).toMatchObject({
            pooler_source_cidrs: [],
            pooler_allow_internet: false,
            ipv6_status: "unchecked",
            gate_login_mode: "disabled",
            sni_extra_ports: [],
            tcp_port_range_start: 20000,
            tcp_port_range_end: 20049,
          });
          expect(settings).not.toHaveProperty("region");
          const [domain] = await db`SELECT aaaa_enabled FROM domain_claims WHERE id = 'dom_legacy'`;
          expect(domain?.aaaa_enabled).toBe(true);
        }
      } finally {
        await db.end();
      }
    });
  }
});

describe("0014_region.sql", () => {
  test("adds exactly the two §3.1 region lines that 0013 left out", () => {
    for (const line of REGION_LINES) expect(migration0014).toContain(`${line}\n`);
    expect(migration0014).toContain("ALTER TABLE platform_settings");
  });

  for (const kind of ["fresh", "upgrade"] as const) {
    test(`applies after 0013 on a ${kind} schema with region = us-east`, async () => {
      const db = await prepare(kind);
      try {
        await apply(db, ["0013_front_door.sql", "0014_region.sql"]);
        // Earlier migrations seed the singleton row; a fresh install reads it straight back.
        await db`INSERT INTO platform_settings (id) VALUES ('default') ON CONFLICT DO NOTHING`;
        const [settings] = await db`
          SELECT region, vps_region_label FROM platform_settings WHERE id = 'default'
        `;
        expect(settings).toEqual({ region: "us-east", vps_region_label: null });
        const columns = await db`
          SELECT column_name, is_nullable, column_default FROM information_schema.columns
          WHERE table_schema = current_schema() AND table_name = 'platform_settings'
            AND column_name IN ('region', 'vps_region_label')
          ORDER BY column_name
        `;
        expect(columns.map((row) => [row.column_name, row.is_nullable, row.column_default])).toEqual([
          ["region", "NO", "'us-east'::text"],
          ["vps_region_label", "YES", null],
        ]);

        await db`UPDATE platform_settings SET region = 'eu-central', vps_region_label = 'Hetzner fsn1'`;
        await expect(Promise.resolve(db`UPDATE platform_settings SET region = 'ap-south'`)).rejects.toThrow(
          /platform_settings_region_check/,
        );
        await expect(
          Promise.resolve(db`UPDATE platform_settings SET vps_region_label = ${"x".repeat(65)}`),
        ).rejects.toThrow(/platform_settings_vps_region_label_check/);
        await expect(Promise.resolve(db`UPDATE platform_settings SET vps_region_label = ''`)).rejects.toThrow(
          /platform_settings_vps_region_label_check/,
        );
      } finally {
        await db.end();
      }
    });
  }
});

describe("0017_db_ingress_limits.sql", () => {
  for (const kind of ["fresh", "upgrade"] as const) {
    test(`applies on a ${kind} schema with the §3.11 defaults and bounded limits`, async () => {
      const db = await prepare(kind);
      try {
        await apply(
          db,
          through("0017").filter((file) => file.slice(0, 4) > "0012"),
        );
        await db`INSERT INTO platform_settings (id) VALUES ('default') ON CONFLICT DO NOTHING`;
        const [settings] = await db`
          SELECT db_ingress_max_connections, db_ingress_rate_per_second, db_ingress_rate_burst
          FROM platform_settings WHERE id = 'default'
        `;
        // An existing install gets the same generous defaults as a fresh one (shared/src/db-ingress.ts).
        expect(settings).toEqual({
          db_ingress_max_connections: 128,
          db_ingress_rate_per_second: 30,
          db_ingress_rate_burst: 60,
        });
        await db`
          UPDATE platform_settings
          SET db_ingress_max_connections = 65535, db_ingress_rate_per_second = 1, db_ingress_rate_burst = 1
        `;
        for (const assignment of [
          db`UPDATE platform_settings SET db_ingress_max_connections = 0`,
          db`UPDATE platform_settings SET db_ingress_max_connections = 65536`,
          db`UPDATE platform_settings SET db_ingress_rate_per_second = 0`,
          db`UPDATE platform_settings SET db_ingress_rate_per_second = 10001, db_ingress_rate_burst = 20000`,
          db`UPDATE platform_settings SET db_ingress_rate_per_second = 50, db_ingress_rate_burst = 49`,
          db`UPDATE platform_settings SET db_ingress_rate_burst = 100001`,
        ]) {
          await expect(Promise.resolve(assignment)).rejects.toThrow(
            /platform_settings_db_ingress_limits_check/,
          );
        }
        await expect(
          Promise.resolve(db`UPDATE platform_settings SET db_ingress_rate_burst = NULL`),
        ).rejects.toThrow(/null value/);
      } finally {
        await db.end();
      }
    });
  }
});

describe("front_routes constraints", () => {
  let db: Sql;
  let routeSeq = 0;

  async function route(values: {
    kind: string;
    endpoint: string;
    listenPort: number;
    compatPort?: number | null;
    targetPort?: number;
  }) {
    routeSeq += 1;
    await db`
      INSERT INTO front_routes (id, kind, endpoint_id, listen_port, compat_port, target_input,
        target_node_stable_id, target_ip, target_port)
      VALUES (${`rt_${routeSeq}`}, ${values.kind}, ${values.endpoint}, ${values.listenPort},
        ${values.compatPort ?? null}, 'home.tail1234.ts.net', 'nHome', '100.101.102.103',
        ${values.targetPort ?? 3000})
    `;
    return `rt_${routeSeq}`;
  }

  test("set up a fresh schema through 0013", async () => {
    db = await prepare("fresh");
    await apply(db, ["0013_front_door.sql"]);
    await db`
      INSERT INTO endpoints (id, kind, hostname) VALUES
        ('ep_www', 'route', 'www.example.com'),
        ('ep_mqtt', 'route', 'mqtt.example.com'),
        ('ep_ssh', 'route', 'ssh.example.com')
    `;
  });

  test("a hostname cannot carry both an HTTP route and a TLS-TCP route on 443", async () => {
    const id = await route({ kind: "http", endpoint: "ep_www", listenPort: 443 });
    await expect(route({ kind: "tls", endpoint: "ep_www", listenPort: 443 })).rejects.toThrow(
      /front_routes_endpoint_listener/,
    );
    await expect(route({ kind: "http", endpoint: "ep_www", listenPort: 443 })).rejects.toThrow(
      /front_routes_endpoint_listener/,
    );
    const [defaults] = await db`SELECT * FROM front_routes WHERE id = ${id}`;
    expect(defaults).toMatchObject({
      access_mode: "sso",
      bypass_paths: [],
      source_cidrs: [],
      allow_internet: false,
      enabled: false,
      status: "draft",
    });
  });

  test("one route per (hostname, listener), with different listeners allowed", async () => {
    await route({ kind: "postgres", endpoint: "ep_www", listenPort: 5432, compatPort: 20010 });
    await expect(route({ kind: "postgres", endpoint: "ep_www", listenPort: 5432 })).rejects.toThrow(
      /front_routes_endpoint_listener/,
    );
    await route({ kind: "tls", endpoint: "ep_mqtt", listenPort: 443 });
    await route({ kind: "tls", endpoint: "ep_mqtt", listenPort: 8883 });
    await expect(route({ kind: "tls", endpoint: "ep_mqtt", listenPort: 8883 })).rejects.toThrow(
      /front_routes_endpoint_listener/,
    );
  });

  test("raw-TCP ports and compat ports are unique across hostnames", async () => {
    await route({ kind: "tcp", endpoint: "ep_ssh", listenPort: 20001 });
    await expect(route({ kind: "tcp", endpoint: "ep_mqtt", listenPort: 20001 })).rejects.toThrow(
      /front_routes_dedicated_port/,
    );
    await route({ kind: "tcp", endpoint: "ep_ssh", listenPort: 20002 });
    await expect(
      route({ kind: "postgres", endpoint: "ep_mqtt", listenPort: 5432, compatPort: 20010 }),
    ).rejects.toThrow(/front_routes_compat_port/);
  });

  test("kind, target port, access mode and TLS mode are checked", async () => {
    await expect(route({ kind: "udp", endpoint: "ep_ssh", listenPort: 20003 })).rejects.toThrow(
      /front_routes_kind_check/,
    );
    await expect(
      route({ kind: "tcp", endpoint: "ep_ssh", listenPort: 20004, targetPort: 0 }),
    ).rejects.toThrow(/front_routes_target_port_check/);
    await expect(
      Promise.resolve(db`UPDATE front_routes SET access_mode = 'open' WHERE id = 'rt_1'`),
    ).rejects.toThrow(/front_routes_access_mode_check/);
    await expect(
      Promise.resolve(db`UPDATE front_routes SET tls_mode = 'none' WHERE id = 'rt_1'`),
    ).rejects.toThrow(/front_routes_tls_mode_check/);
  });

  test("endpoints in use cannot be deleted, and tailnet nodes need a snapshot", async () => {
    await expect(Promise.resolve(db`DELETE FROM endpoints WHERE id = 'ep_www'`)).rejects.toThrow(
      /foreign key/,
    );
    await expect(
      Promise.resolve(db`INSERT INTO tailnet_nodes (source, generation, stable_id, dns_name, host_name, observed_at)
         VALUES ('edge', 'g1', 'nHome', 'home.tail1234.ts.net', 'home', now())`),
    ).rejects.toThrow(/foreign key/);
    await expect(
      Promise.resolve(db`INSERT INTO tailnet_snapshots (source, generation, completed_at, valid_until)
         VALUES ('vps', 'g1', now(), now() + interval '6 minutes')`),
    ).rejects.toThrow(/tailnet_snapshots_source_check/);
    await db.end();
  });
});

// Let PostgreSQL normalize both versions: IN, BETWEEN, casts and parentheses can have
// different spellings in Drizzle and SQL while representing the same expression.
const dialect = new PgDialect();
const identifier = (name: string) => `"${name.replaceAll('"', '""')}"`;
const expression = (value: SQL) => dialect.sqlToQuery(value.inlineParams()).sql;

async function expectMirrorExpressions(db: Sql, config: ReturnType<typeof getTableConfig>) {
  for (const check of config.checks) {
    await db.unsafe(
      `ALTER TABLE ${identifier(config.name)} ADD CONSTRAINT fd_mirror_check CHECK (${expression(check.value)})`,
    );
    try {
      const rows = await db`
        SELECT conname, pg_get_expr(conbin, conrelid) AS expression FROM pg_constraint
        WHERE conrelid = ${config.name}::regclass AND conname IN (${check.name}, 'fd_mirror_check')
      `;
      expect(rows.find((row) => row.conname === check.name)?.expression, check.name).toBe(
        rows.find((row) => row.conname === "fd_mirror_check")?.expression,
      );
    } finally {
      await db.unsafe(`ALTER TABLE ${identifier(config.name)} DROP CONSTRAINT fd_mirror_check`);
    }
  }
  for (const { config: index } of config.indexes) {
    const columns = index.columns
      .map((column) => {
        if (column instanceof SQL) return expression(column);
        if (!("name" in column) || !column.name) throw new Error("Expected a named index column.");
        const { order, nulls, opClass } = column.indexConfig ?? {};
        return `${identifier(column.name)}${opClass ? ` ${identifier(opClass)}` : ""} ${order ?? "asc"} NULLS ${nulls ?? (order === "desc" ? "first" : "last")}`;
      })
      .join(", ");
    await db.unsafe(
      `CREATE ${index.unique ? "UNIQUE " : ""}INDEX fd_mirror_index ON ${identifier(config.name)} USING ${identifier(index.method ?? "btree")} (${columns})${index.where ? ` WHERE ${expression(index.where)}` : ""}`,
    );
    try {
      const rows = await db`
        SELECT rel.relname, idx.indisunique, am.amname,
          ARRAY(SELECT pg_get_indexdef(idx.indexrelid, n, true)
                FROM generate_series(1, idx.indnkeyatts) n) AS columns,
          pg_get_expr(idx.indpred, idx.indrelid) AS predicate
        FROM pg_index idx JOIN pg_class rel ON rel.oid = idx.indexrelid
        JOIN pg_am am ON am.oid = rel.relam
        WHERE idx.indrelid = ${config.name}::regclass
          AND rel.relname IN (${index.name!}, 'fd_mirror_index')
      `;
      const shape = (name: string) => {
        const row = rows.find((candidate) => candidate.relname === name);
        return (
          row && {
            unique: row.indisunique,
            method: row.amname,
            columns: row.columns,
            predicate: row.predicate,
          }
        );
      };
      expect(shape(index.name!), index.name).toEqual(shape("fd_mirror_index"));
    } finally {
      await db.unsafe("DROP INDEX fd_mirror_index");
    }
  }
}

describe("Drizzle schema mirrors the migration", () => {
  const tables: PgTable[] = [
    schema.session,
    schema.platformSettings,
    schema.domainClaims,
    schema.tailnetSnapshots,
    schema.tailnetNodes,
    schema.privateCas,
    schema.frontRoutes,
    schema.frontRouteAccess,
    schema.gateHandoffs,
    schema.gateSessions,
    schema.clientCertificates,
    schema.databaseClients,
    schema.vercelIntegrations,
    schema.backupTargets,
    schema.backupExports,
    schema.backupSources,
    schema.tailnetAclSnippets,
  ];

  test("columns, nullability, defaults, checks, indexes and keys match a fresh migrate", async () => {
    const db = await scratch("drizzle");
    try {
      // Every migration, not just 0013: later tickets add the region columns (0014),
      // client_certificates.cert_pem (0015), tailnet_acl_snippets (0016) and database ingress limits
      // (0017). Migrations are tracked by full filename, and schema.ts
      // mirrors the latest state.
      await apply(db, migrationFiles);
      for (const table of tables) {
        const config = getTableConfig(table);
        const columns = await db`
          SELECT column_name, is_nullable, column_default IS NOT NULL AS has_default
          FROM information_schema.columns
          WHERE table_schema = current_schema() AND table_name = ${config.name}
          ORDER BY column_name
        `;
        expect({
          table: config.name,
          columns: columns.map((row) => [row.column_name, row.is_nullable === "NO", row.has_default]),
        }).toEqual({
          table: config.name,
          columns: config.columns
            .map((column): [string, boolean, boolean] => [column.name, column.notNull, column.hasDefault])
            .toSorted(([a], [b]) => (a < b ? -1 : 1)),
        });

        const constraints = await db`
          SELECT con.conname, con.contype
          FROM pg_constraint con
          JOIN pg_class rel ON rel.oid = con.conrelid
          JOIN pg_namespace ns ON ns.oid = rel.relnamespace
          WHERE ns.nspname = current_schema() AND rel.relname = ${config.name}
        `;
        const names = new Set(constraints.map((row) => row.conname));
        for (const item of config.checks) expect(names).toContain(item.name);
        for (const item of config.uniqueConstraints) expect(names).toContain(item.getName() ?? "");
        for (const item of config.primaryKeys) expect(names).toContain(item.getName());
        const checkCount = constraints.filter((row) => row.contype === "c").length;
        expect({ table: config.name, checks: checkCount }).toEqual({
          table: config.name,
          checks: config.checks.length,
        });
        const foreignKeyCount = constraints.filter((row) => row.contype === "f").length;
        expect({ table: config.name, foreignKeys: foreignKeyCount }).toEqual({
          table: config.name,
          foreignKeys: config.foreignKeys.length,
        });

        const indexes = await db`
          SELECT indexname, indexdef FROM pg_indexes
          WHERE schemaname = current_schema() AND tablename = ${config.name}
        `;
        for (const item of config.indexes) {
          const found = indexes.find((row) => row.indexname === item.config.name);
          expect(found, `${config.name}.${item.config.name}`).toBeDefined();
          expect(found?.indexdef.includes("UNIQUE")).toBe(item.config.unique);
          expect(found?.indexdef.includes(" WHERE ")).toBe(Boolean(item.config.where));
        }
        await expectMirrorExpressions(db, config);
      }
    } finally {
      await db.end();
    }
  });

  test("mirror comparison detects wrong index columns, predicates and check expressions", async () => {
    const db = await scratch("mirror");
    try {
      await apply(db, through("0013"));
      const config = getTableConfig(schema.frontRoutes);
      const index = config.indexes[0]!;
      const check = config.checks[0]!;
      for (const change of [
        { ...index.config, columns: index.config.columns.toReversed() },
        { ...index.config, where: new SQL(["kind = 'tcp'"]) },
      ]) {
        await expect(
          expectMirrorExpressions(db, { ...config, checks: [], indexes: [{ ...index, config: change }] }),
        ).rejects.toThrow();
      }
      await expect(
        expectMirrorExpressions(db, {
          ...config,
          indexes: [],
          checks: [{ ...check, value: new SQL(["kind IN ('http', 'tls')"]) }],
        }),
      ).rejects.toThrow();
    } finally {
      await db.end();
    }
  });
});
