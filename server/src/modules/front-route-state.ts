import { and, eq, sql } from "drizzle-orm";

import { frontRoutes } from "../schema.ts";

// PostgreSQL changes xmin whenever a row is written, including by lifecycle workers. Capture it
// with the snapshot and compare it in the write, so work delayed by a probe or grant cannot undo
// newer state. It is a short-lived concurrency token, never a persisted application revision.
export const routeVersion = sql<string>`${frontRoutes}.xmin::text`;

export function currentRoute(id: string, version: string) {
  return and(eq(frontRoutes.id, id), sql`${routeVersion} = ${version}`);
}
