import { mkdir } from "node:fs/promises";
import { join } from "node:path";

import {
  authQuerySql,
  buildProvisionPlan,
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

export function appAdminUrl() {
  return process.env.DATABASE_APP_URL ?? "";
}

export async function provisionApplicationDatabase(input: {
  name: string;
  withPgvector: boolean;
  withTestDatabase: boolean;
}) {
  const passwords = {
    owner: generatePassword(),
    migration: generatePassword(),
    runtime: generatePassword(),
    readonly: generatePassword(),
  } as Record<DatabaseRoleKind, string>;
  const plan = buildProvisionPlan({ ...input, passwords });
  const url = appAdminUrl();
  if (!url) {
    return { plan, executed: false, passwords, status: "awaiting_cluster" as const };
  }
  const admin = postgres(url, { max: 1, onnotice: () => undefined });
  try {
    for (const statement of plan.statements) {
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

export async function executeWorkspaceQuery(input: {
  database: string;
  username: string;
  password: string;
  sql: string;
  readOnly: boolean;
}) {
  classifySql(input.sql, input.readOnly);
  const url = appAdminUrl();
  if (!url) throw new Error("DATABASE_APP_URL is not configured.");
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
    const rows = (await client.unsafe(input.sql)) as Record<string, unknown>[];
    return rows.slice(0, 200);
  } finally {
    await client.end();
  }
}

function connectionFromUrl(url: string) {
  const parsed = new URL(url);
  return {
    host: parsed.hostname,
    port: Number(parsed.port || 5432),
    database: parsed.pathname.replace(/^\//, "") || "postgres",
    username: decodeURIComponent(parsed.username),
    password: decodeURIComponent(parsed.password),
  };
}

export async function inspectDatabaseSchema(input: { database: string; username: string; password: string }) {
  const rows = (await executeWorkspaceQuery({
    ...input,
    sql: schemaBrowserSql,
    readOnly: true,
  })) as Array<{ schema: string; table: string; column: string; type: string; nullable?: string }>;
  const sizes = await executeWorkspaceQuery({
    ...input,
    sql: schemaSizeSql,
    readOnly: true,
  });
  return { schemas: groupSchemaRows(rows), sizes };
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

export { env };
