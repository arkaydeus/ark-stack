import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";

import * as schema from "./schema.ts";

const url = process.env.DATABASE_URL;
if (!url) throw new Error("DATABASE_URL is required. Ark Stack runs against PostgreSQL.");

export const sql = postgres(url, { max: 10, idle_timeout: 20, connect_timeout: 15 });
export const db = drizzle(sql, { schema });

export type DbTransaction = Parameters<Parameters<typeof db.transaction>[0]>[0];
