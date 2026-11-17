// All production pooler readers/writers share this lock, including the fence/drain sequence.
// The local queue avoids exhausting the SQL pool with advisory-lock waiters. PostgreSQL makes
// it effective across workers; a transaction releases it on errors or process death.
import { AsyncLocalStorage } from "node:async_hooks";

import { sql } from "../db.ts";

const held = new AsyncLocalStorage<boolean>();
let tail: Promise<unknown> = Promise.resolve();

export function withPgbouncerLock<T>(work: () => Promise<T>): Promise<T> {
  if (held.getStore()) return work();
  const next = tail.then(() =>
    sql.begin(async (connection) => {
      await connection`SELECT pg_advisory_xact_lock(hashtextextended('ark:pgbouncer-config', 0))`;
      return held.run(true, work);
    }),
  ) as Promise<T>;
  tail = next.catch(() => undefined);
  return next;
}
