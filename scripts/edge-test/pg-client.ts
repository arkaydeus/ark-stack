// Test-only PostgreSQL client for `scripts/test-edge-pg5432.ts` (FD-26). Runs in the pinned Bun image on
// the client network (so HAProxy sees this container's own address), with a throwaway node_modules that
// holds node-postgres 8.23.1 and postgres.js 4.1.1. Prints one JSON line:
// `{ ok, version?, database?, error?, ms }`.
//
//   bun pg-client.ts '<spec JSON>'
//   spec: { driver: "pg" | "postgres", host, port, servername?, direct, user, password, database,
//           cert?, key? }   (PEM strings; server certificates are not verified here, the SNI is the test)
import { Client, type ClientConfig } from "pg";
import postgres from "postgres";

type Spec = {
  driver: "pg" | "postgres";
  host: string;
  port: number;
  servername?: string;
  direct: boolean;
  user: string;
  password: string;
  database: string;
  cert?: string;
  key?: string;
};

const spec = JSON.parse(process.argv[2] ?? "{}") as Spec;
const started = Date.now();
const query = "SELECT current_database() AS database, current_setting('server_version_num') AS version";
const ssl = {
  rejectUnauthorized: false,
  ...(spec.servername ? { servername: spec.servername } : {}),
  ...(spec.cert ? { cert: spec.cert, key: spec.key } : {}),
};

async function viaPg() {
  const client = new Client({
    host: spec.host,
    port: spec.port,
    user: spec.user,
    password: spec.password,
    database: spec.database,
    ssl,
    connectionTimeoutMillis: 8_000,
    ...(spec.direct ? { sslnegotiation: "direct" } : {}),
  } as ClientConfig);
  await client.connect();
  try {
    return (await client.query(query)).rows[0] as { database: string; version: string };
  } finally {
    await client.end();
  }
}

async function viaPostgresJs() {
  const sql = postgres({
    host: spec.host,
    port: spec.port,
    user: spec.user,
    pass: spec.password,
    database: spec.database,
    ssl,
    connect_timeout: 8,
    max: 1,
    // Transaction pooling through PgBouncer: no named prepared statements needed for this check.
    prepare: false,
    ...(spec.direct ? { sslnegotiation: "direct" } : {}),
  } as Parameters<typeof postgres>[0]);
  try {
    const [row] = await sql.unsafe(query);
    return row as { database: string; version: string };
  } finally {
    await sql.end({ timeout: 2 });
  }
}

try {
  const row = spec.driver === "postgres" ? await viaPostgresJs() : await viaPg();
  console.log(JSON.stringify({ ok: true, ...row, ms: Date.now() - started }));
} catch (error) {
  console.log(JSON.stringify({ ok: false, error: (error as Error).message, ms: Date.now() - started }));
}
process.exit(0);
