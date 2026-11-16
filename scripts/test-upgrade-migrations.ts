import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { spawn } from "node:child_process";

import postgres from "postgres";

const sourceUrl = process.env.DATABASE_URL;
if (!sourceUrl) throw new Error("DATABASE_URL is required for the upgrade migration test.");
const parsed = new URL(sourceUrl);
if (!["127.0.0.1", "localhost", "::1"].includes(parsed.hostname)) {
  throw new Error("Upgrade migration tests refuse a non-loopback PostgreSQL endpoint.");
}
const root = join(import.meta.dir, "..");
const databaseName = `ark_upgrade_${crypto.randomUUID().replaceAll("-", "").slice(0, 12)}`;
if (!/^ark_upgrade_[a-f0-9]{12}$/.test(databaseName)) throw new Error("Unsafe disposable database name.");
const databaseUrl = new URL(sourceUrl);
databaseUrl.pathname = `/${databaseName}`;
const admin = postgres(sourceUrl, { max: 1 });

function runMigration() {
  return new Promise<void>((resolve, reject) => {
    const child = spawn("bun", ["server/src/migrate.ts"], {
      cwd: root,
      env: { ...process.env, DATABASE_URL: databaseUrl.toString() },
      stdio: "inherit",
    });
    child.once("exit", (code) =>
      code === 0 ? resolve() : reject(new Error(`upgrade migration process exited ${code}`)),
    );
  });
}

try {
  await admin.unsafe(`CREATE DATABASE "${databaseName}"`);
  const target = postgres(databaseUrl.toString(), { max: 1 });
  try {
    await target.unsafe(`
      CREATE TABLE ark_migrations (
        id text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);
    const files = (await readdir(join(root, "server", "drizzle")))
      .filter((file) => /^000[0-3]_.*\.sql$/.test(file))
      .toSorted();
    for (const file of files) {
      await target.unsafe(await Bun.file(join(root, "server", "drizzle", file)).text());
      await target`INSERT INTO ark_migrations (id) VALUES (${file})`;
    }
  } finally {
    await target.end();
  }
  await runMigration();
  const verified = postgres(databaseUrl.toString(), { max: 1 });
  try {
    const migration = await verified`SELECT 1 FROM ark_migrations WHERE id = '0010_worker_heartbeats.sql'`;
    const stateful = await verified`
      SELECT 1 FROM information_schema.columns
      WHERE table_name = 'services' AND column_name = 'stateful'
    `;
    if (!migration.length || !stateful.length)
      throw new Error("Representative upgrade did not reach the current schema.");
    const accountIssuer = await verified`
      SELECT 1 FROM information_schema.columns
      WHERE table_name = 'account' AND column_name = 'issuer'
    `;
    const accountIssuerIndex = await verified`
      SELECT 1 FROM pg_indexes WHERE indexname = 'account_issuer_account_id_idx'
    `;
    if (accountIssuer.length || accountIssuerIndex.length)
      throw new Error("Upgrade left the legacy Better Auth account.issuer column or index behind.");
  } finally {
    await verified.end();
  }
} finally {
  await admin`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ${databaseName} AND pid <> pg_backend_pid()`;
  const exists = await admin`SELECT 1 FROM pg_database WHERE datname = ${databaseName}`;
  if (exists.length) await admin.unsafe(`DROP DATABASE "${databaseName}"`);
  await admin.end();
}
