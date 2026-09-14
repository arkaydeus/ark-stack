import { readdir } from "node:fs/promises";
import { join } from "node:path";

import { sql } from "./db.ts";

const folder = new URL("../drizzle", import.meta.url).pathname;

await sql`CREATE TABLE IF NOT EXISTS ark_migrations (
  id text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
)`;

const appliedRows = (await sql.unsafe("SELECT id FROM ark_migrations")) as Array<{ id: string }>;
const applied = new Set(appliedRows.map((row) => row.id));
const files = (await readdir(folder)).filter((name) => name.endsWith(".sql")).toSorted();

for (const file of files) {
  if (applied.has(file)) continue;
  await sql.file(join(folder, file));
  await sql`INSERT INTO ark_migrations (id) VALUES (${file})`;
  console.log(`applied ${file}`);
}

await sql.end();
console.log("Platform database migrations applied.");
