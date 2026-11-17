// A Vercel app stand-in for scripts/test-pgbouncer-public.ts (FD-17).
//
// The smoke test writes Ark's §3.12 node-postgres module (NODE_POSTGRES_SNIPPET, shared/src/
// db-clients.ts) to `lib/db.ts`, bundles it with the real `pg` and `@vercel/functions`, and runs
// this probe in the pinned Linux Bun image with the env vars from the client's one-time reveal
// (ARK_DB_HOST, ARK_DB_USER, ARK_DB_PASSWORD, ARK_DB_CLIENT_CERT_B64, …). The module is used
// unmodified; only NODE_EXTRA_CA_CERTS trusts the test server certificate, standing in for the
// publicly trusted Let's Encrypt certificate production serves.
//
//   probe.js connect   one query on a fresh pool connection; reports user, TLS version, attach
//   probe.js write     SELECT, INSERT, UPDATE and DELETE on the probe table; reports each outcome
//   probe.js hold      check out one client, print {"ready":true}, wait for SIGUSR1, then query
//                      the same client again and report whether the session survived
//   probe.js stream    FD-28: check out one client, print {"ready":true}, then query it every
//                      100 ms until the session fails or ARK_PROBE_STOP_AT (epoch ms) passes, and
//                      report the last successful query and the moment the session failed
import type { Pool, PoolClient } from "pg";

const { pool } = (await import(process.env.ARK_PROBE_DB_MODULE ?? "/probe/vercel/db.js")) as { pool: Pool };
const mode = process.argv[2];

function failure(error: unknown) {
  const value = error as { message?: string; code?: string };
  return { ok: false, code: value?.code ?? null, error: value?.message ?? String(error) };
}

async function tlsVersion(client: PoolClient) {
  const stream = (client as unknown as { connection?: { stream?: { getProtocol?: () => string | null } } })
    .connection?.stream;
  return stream?.getProtocol?.() ?? null;
}

try {
  if (mode === "connect") {
    const client = await pool.connect();
    try {
      const { rows } = await client.query("SELECT current_user AS user, current_database() AS database");
      console.log(
        JSON.stringify({
          ok: true,
          user: rows[0].user,
          database: rows[0].database,
          tls: await tlsVersion(client),
          // attachDatabasePool registers a release listener on the pool (§3.12).
          attached: pool.listenerCount("release") > 0,
        }),
      );
    } finally {
      client.release();
    }
  } else if (mode === "write") {
    const run = async (sql: string) =>
      pool.query(sql).then(
        (result) => ({ ok: true, rows: result.rowCount }),
        (error: unknown) => failure(error),
      );
    console.log(
      JSON.stringify({
        ok: true,
        select: await run("SELECT count(*) FROM fd17_items"),
        insert: await run("INSERT INTO fd17_items (value) VALUES ('probe')"),
        update: await run("UPDATE fd17_items SET value = 'updated'"),
        delete: await run("DELETE FROM fd17_items WHERE value = 'updated'"),
      }),
    );
  } else if (mode === "hold") {
    const client = await pool.connect();
    const errors: string[] = [];
    let ended = false;
    client.on("error", (error) => errors.push(error.message));
    client.on("end", () => {
      ended = true;
    });
    const before = await client.query("SELECT current_user AS user");
    console.log(JSON.stringify({ ready: true, user: before.rows[0].user }));
    await new Promise((resolve) => process.once("SIGUSR1", resolve));
    const existing = await client.query("SELECT current_user AS user").then(
      (result) => ({ ok: true, user: result.rows[0].user }),
      (error: unknown) => failure(error),
    );
    console.log(JSON.stringify({ done: true, existing, ended, errors }));
    // pool.end() waits for checked-out clients, so hand this one back (destroyed) first.
    client.release(true);
  } else if (mode === "stream") {
    const client = await pool.connect();
    let failedAt: number | null = null;
    let lastOk: number | null = null;
    let queries = 0;
    let error: string | null = null;
    client.on("error", (cause) => {
      failedAt ??= Date.now();
      error ??= cause.message;
    });
    const before = await client.query("SELECT current_user AS user");
    console.log(JSON.stringify({ ready: true, user: before.rows[0].user, at: Date.now() }));
    const stopAt = Number(process.env.ARK_PROBE_STOP_AT ?? Date.now() + 60_000);
    while (failedAt === null && Date.now() < stopAt) {
      try {
        await client.query("SELECT 1");
        lastOk = Date.now();
        queries++;
      } catch (cause) {
        failedAt ??= Date.now();
        error ??= (cause as Error).message;
        break;
      }
      await Bun.sleep(100);
    }
    console.log(
      JSON.stringify({ done: true, user: before.rows[0].user, lastOk, failedAt, error, queries, stopAt }),
    );
    client.release(true);
  } else {
    throw new Error(`unknown probe mode ${mode}`);
  }
} catch (error) {
  console.log(JSON.stringify(failure(error)));
  process.exitCode = 1;
} finally {
  await Promise.race([pool.end().catch(() => undefined), Bun.sleep(5_000)]);
}
process.exit();
