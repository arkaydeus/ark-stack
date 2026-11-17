import { mkdir } from "node:fs/promises";
import { join } from "node:path";

import {
  authQuerySql,
  buildProvisionPlan,
  clientRoleSql,
  revokedClientRoleSql,
  classifySql,
  generatePassword,
  groupSchemaRows,
  rotateRoleSql,
  schemaBrowserSql,
  schemaSizeSql,
  terminateRoleSessionsSql,
  type DatabaseRoleKind,
} from "@ark-stack/shared";
import postgres from "postgres";

import { loadEnv } from "../env.ts";

const env = loadEnv();
const MAX_QUERY_ROWS = 200;
// Worker completion bodies are capped at 256 KiB; leave headroom for the
// signed operation envelope and JSON expansion while retaining a hard result
// ceiling below the product-wide 1 MiB maximum.
const MAX_QUERY_BYTES = 192 * 1024;
const MAX_CONCURRENT_PER_SCOPE = 2;
const activeQueries = new Map<
  string,
  { actorId: string; database: string; pid: number; cancelUrl: string }
>();

export function appAdminUrl() {
  return process.env.DATABASE_APP_URL ?? "";
}

export async function provisionApplicationDatabase(input: {
  name: string;
  withPgvector: boolean;
  withTestDatabase: boolean;
  passwords?: Record<DatabaseRoleKind, string>;
}) {
  const passwords =
    input.passwords ??
    ({
      owner: generatePassword(),
      migration: generatePassword(),
      runtime: generatePassword(),
      readonly: generatePassword(),
    } as Record<DatabaseRoleKind, string>);
  const plan = buildProvisionPlan({ ...input, passwords });
  const url = appAdminUrl();
  if (!url) {
    return { plan, executed: false, passwords, status: "awaiting_cluster" as const };
  }
  const admin = postgres(url, { max: 1, onnotice: () => undefined });
  try {
    for (const statement of plan.statements) {
      const createDatabase = /^CREATE DATABASE\s+"([^"]+)"$/i.exec(statement);
      if (createDatabase) {
        const exists = await admin`SELECT 1 FROM pg_database WHERE datname = ${createDatabase[1]}`;
        if (exists.length) continue;
      }
      const createRole = /^CREATE ROLE\s+"([^"]+)"\s+/i.exec(statement);
      if (createRole) {
        const exists = await admin`SELECT 1 FROM pg_roles WHERE rolname = ${createRole[1]}`;
        if (exists.length) continue;
      }
      await admin.unsafe(statement);
    }
    const target = postgres({
      ...connectionFromUrl(url),
      database: plan.database,
      max: 1,
      onnotice: () => undefined,
    });
    try {
      for (const statement of plan.extensionStatements) {
        await target.unsafe(statement);
      }
      await target.unsafe(authQuerySql());
    } finally {
      await target.end();
    }
    if (plan.testDatabase) {
      const testTarget = postgres({
        ...connectionFromUrl(url),
        database: plan.testDatabase,
        max: 1,
        onnotice: () => undefined,
      });
      try {
        for (const statement of plan.extensionStatements) await testTarget.unsafe(statement);
      } finally {
        await testTarget.end();
      }
    }
    await verifyProvisionedRoles(url, plan, passwords);
  } finally {
    await admin.end();
  }
  const dir = process.env.ARK_PGBOUNCER_DIR;
  if (dir) {
    await mkdir(dir, { recursive: true });
    await Bun.write(
      join(dir, `${plan.database}.ini`),
      `[databases]\n${plan.database} = host=app-postgres dbname=${plan.database}\n`,
    );
  }
  return { plan, executed: true, passwords, status: "ready" as const };
}

async function verifyProvisionedRoles(
  url: string,
  plan: ReturnType<typeof buildProvisionPlan>,
  passwords: Record<DatabaseRoleKind, string>,
) {
  const roleName = (kind: DatabaseRoleKind) => {
    const role = plan.roles.find((item) => item.kind === kind);
    if (!role) throw new Error(`Provisioning plan omitted the ${kind} role.`);
    return role.name;
  };
  const connect = (database: string, kind: Exclude<DatabaseRoleKind, "owner">) =>
    postgres({
      ...connectionFromUrl(url),
      database,
      username: roleName(kind),
      password: passwords[kind],
      max: 1,
      connect_timeout: 8,
      onnotice: () => undefined,
    });
  const migration = connect(plan.database, "migration");
  const runtime = connect(plan.database, "runtime");
  const readonly = connect(plan.database, "readonly");
  try {
    await migration.unsafe('DROP TABLE IF EXISTS "__ark_role_probe"');
    await migration.unsafe('CREATE TABLE "__ark_role_probe" (id serial PRIMARY KEY, value text NOT NULL)');
    const inserted = await runtime<{ id: number }[]>`
      INSERT INTO "__ark_role_probe" (value) VALUES ('verified') RETURNING id
    `;
    if (!inserted[0]?.id) throw new Error("Runtime role could not insert into a sequence-backed table.");
    const selected = await readonly<{ value: string }[]>`
      SELECT value FROM "__ark_role_probe" WHERE id = ${inserted[0].id}
    `;
    if (selected[0]?.value !== "verified") throw new Error("Readonly role could not read provisioned data.");
    let runtimeDdlDenied = false;
    try {
      await runtime.unsafe('CREATE TABLE "__ark_runtime_must_not_create" (id integer)');
    } catch {
      runtimeDdlDenied = true;
    }
    if (!runtimeDdlDenied) {
      await runtime.unsafe('DROP TABLE IF EXISTS "__ark_runtime_must_not_create"');
      throw new Error("Runtime role unexpectedly retained schema DDL permission.");
    }
  } finally {
    await migration.unsafe('DROP TABLE IF EXISTS "__ark_role_probe"').catch(() => undefined);
    await Promise.all([migration.end(), runtime.end(), readonly.end()]);
  }
  if (plan.testDatabase) {
    const testMigration = connect(plan.testDatabase, "migration");
    try {
      await testMigration.unsafe('CREATE TABLE "__ark_test_probe" (id serial PRIMARY KEY)');
      await testMigration.unsafe('DROP TABLE "__ark_test_probe"');
    } finally {
      await testMigration.end();
    }
  }
}

export async function executeWorkspaceQuery(input: {
  executionId: string;
  actorId: string;
  database: string;
  username: string;
  password: string;
  sql: string;
  readOnly: boolean;
}) {
  classifySql(input.sql, input.readOnly);
  const url = appAdminUrl();
  if (!url) throw new Error("DATABASE_APP_URL is not configured.");
  const concurrent = [...activeQueries.values()].filter(
    (item) => item.actorId === input.actorId && item.database === input.database,
  ).length;
  if (concurrent >= MAX_CONCURRENT_PER_SCOPE) {
    throw new Error("The per-user database query concurrency limit has been reached.");
  }
  const client = postgres({
    ...connectionFromUrl(url),
    database: input.database,
    username: input.username,
    password: input.password,
    max: 1,
    connect_timeout: 8,
    idle_timeout: 5,
  });
  try {
    await client`SET statement_timeout = 8000`;
    await client`SET lock_timeout = 4000`;
    await client`SET idle_in_transaction_session_timeout = 8000`;
    if (input.readOnly) await client`SET default_transaction_read_only = on`;
    const [{ pid }] = await client<{ pid: number }[]>`SELECT pg_backend_pid()::int AS pid`;
    activeQueries.set(input.executionId, {
      actorId: input.actorId,
      database: input.database,
      pid,
      cancelUrl: url,
    });
    const rows: Record<string, unknown>[] = [];
    let bytes = 0;
    let truncated = false;
    await client.unsafe(input.sql).cursor(50, (batch) => {
      for (const row of batch as Record<string, unknown>[]) {
        const size = Buffer.byteLength(
          JSON.stringify(row, (_, value) => (typeof value === "bigint" ? value.toString() : value)),
        );
        if (rows.length >= MAX_QUERY_ROWS || bytes + size > MAX_QUERY_BYTES) {
          truncated = true;
          return client.CLOSE;
        }
        rows.push(row);
        bytes += size;
      }
      if (rows.length >= MAX_QUERY_ROWS) {
        truncated = true;
        return client.CLOSE;
      }
    });
    return { rows, truncated, rowLimit: MAX_QUERY_ROWS, byteLimit: MAX_QUERY_BYTES, bytes };
  } finally {
    activeQueries.delete(input.executionId);
    await client.end();
  }
}

export async function cancelWorkspaceQuery(input: {
  executionId: string;
  actorId: string;
  database: string;
}) {
  const active = activeQueries.get(input.executionId);
  if (!active || active.actorId !== input.actorId || active.database !== input.database) return false;
  const admin = postgres(active.cancelUrl, { max: 1, connect_timeout: 5 });
  try {
    const [result] = await admin<{ cancelled: boolean }[]>`
      SELECT pg_cancel_backend(${active.pid}) AS cancelled
    `;
    return Boolean(result?.cancelled);
  } finally {
    await admin.end();
  }
}

function connectionFromUrl(url: string) {
  const parsed = new URL(url);
  const sslmode = parsed.searchParams.get("sslmode");
  const ssl: false | "require" | "allow" | "prefer" | "verify-full" | undefined =
    sslmode === "disable"
      ? false
      : sslmode === "require" || sslmode === "allow" || sslmode === "prefer" || sslmode === "verify-full"
        ? sslmode
        : sslmode === "verify-ca"
          ? "verify-full"
          : undefined;
  return {
    host: parsed.hostname,
    port: Number(parsed.port || 5432),
    database: parsed.pathname.replace(/^\//, "") || "postgres",
    username: decodeURIComponent(parsed.username),
    password: decodeURIComponent(parsed.password),
    ...(ssl !== undefined ? { ssl } : {}),
  };
}

export async function inspectDatabaseSchema(input: { database: string; username: string; password: string }) {
  const rowsResult = await executeWorkspaceQuery({
    ...input,
    executionId: crypto.randomUUID(),
    actorId: "schema-browser",
    sql: schemaBrowserSql,
    readOnly: true,
  });
  const rows = rowsResult.rows as Array<{
    schema: string;
    table: string;
    column: string;
    type: string;
    nullable?: string;
  }>;
  const sizesResult = await executeWorkspaceQuery({
    ...input,
    executionId: crypto.randomUUID(),
    actorId: "schema-browser",
    sql: schemaSizeSql,
    readOnly: true,
  });
  return { schemas: groupSchemaRows(rows), sizes: sizesResult.rows };
}

export async function rotateRolePassword(input: { role: string; password: string; database?: string }) {
  const url = appAdminUrl();
  if (!url) throw new Error("DATABASE_APP_URL is not configured.");
  const admin = postgres(url, { max: 1, onnotice: () => undefined });
  try {
    await admin.unsafe(rotateRoleSql(input.role, input.password));
    if (input.database) await admin.unsafe(terminateRoleSessionsSql(input.role, input.database));
  } finally {
    await admin.end();
  }
}

/** True when a role of this name exists in the application cluster. */
export async function appRoleExists(role: string) {
  const url = appAdminUrl();
  if (!url) throw new Error("DATABASE_APP_URL is not configured.");
  const admin = postgres(url, { max: 1, onnotice: () => undefined });
  try {
    const rows = await admin`SELECT 1 FROM pg_roles WHERE rolname = ${role}`;
    return rows.length > 0;
  } finally {
    await admin.end();
  }
}

/**
 * Create a database client's login role `IN ROLE` its group, or bring an Ark-owned role left by
 * an interrupted issue to the planned password, limit and membership (FD-17, §3.10.3). Runs in
 * one transaction on the application cluster.
 */
export async function applyClientRole(input: {
  role: string;
  group: string;
  password: string;
  connectionLimit: number;
}) {
  const url = appAdminUrl();
  if (!url) throw new Error("DATABASE_APP_URL is not configured.");
  const admin = postgres(url, { max: 1, onnotice: () => undefined });
  try {
    await admin.begin(async (tx) => {
      const group = await tx`SELECT 1 FROM pg_roles WHERE rolname = ${input.group}`;
      if (!group.length)
        throw new Error(`Group role ${input.group} is missing; provision the database first.`);
      const exists = (await tx`SELECT 1 FROM pg_roles WHERE rolname = ${input.role}`).length > 0;
      for (const statement of clientRoleSql({ ...input, exists })) await tx.unsafe(statement);
    });
  } finally {
    await admin.end();
  }
}

/**
 * Revocation on the cluster: a new random password the client never sees, NOLOGIN, and every
 * backend of the role terminated (PgBouncer's server connections included).
 */
export async function revokeClientRole(input: { role: string; password: string }) {
  const url = appAdminUrl();
  if (!url) throw new Error("DATABASE_APP_URL is not configured.");
  const admin = postgres(url, { max: 1, onnotice: () => undefined });
  try {
    const exists = await admin`SELECT 1 FROM pg_roles WHERE rolname = ${input.role}`;
    if (exists.length) {
      for (const statement of revokedClientRoleSql(input.role, input.password)) await admin.unsafe(statement);
    }
    await admin.unsafe(terminateRoleSessionsSql(input.role));
    return { existed: exists.length > 0 };
  } finally {
    await admin.end();
  }
}

export { env };
