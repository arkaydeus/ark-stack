import { expect, test } from "bun:test";
import postgres from "postgres";

import { appAdminUrl, executeWorkspaceQuery } from "./database.ts";

function query(sql: string) {
  const url = new URL(appAdminUrl());
  return executeWorkspaceQuery({
    executionId: crypto.randomUUID(),
    actorId: "workspace-test",
    database: url.pathname.slice(1),
    username: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    sql,
    readOnly: true,
  });
}

async function expectConnectionClosed(pid: number) {
  const observer = postgres(appAdminUrl(), { max: 1 });
  try {
    const deadline = Date.now() + 2_000;
    while (true) {
      const [activity] = await observer`SELECT 1 FROM pg_stat_activity WHERE pid = ${pid}::int`;
      if (!activity) return;
      if (Date.now() >= deadline) throw new Error("Workspace query connection stayed open.");
      await Bun.sleep(20);
    }
  } finally {
    await observer.end();
  }
}

test("workspace serializes unzoned timestamps in the worker's timezone", async () => {
  const previousTimezone = process.env.TZ;
  process.env.TZ = "Europe/London";
  try {
    const { rows } = await query(`
      SELECT timestamp '2026-07-01 12:00:00' AS unzoned,
             timestamptz '2026-07-01 12:00:00+00' AS zoned,
             ARRAY[timestamp '2026-07-01 12:00:00'] AS unzoned_array
    `);
    expect(JSON.parse(JSON.stringify(rows))).toEqual([
      {
        unzoned: "2026-07-01T11:00:00.000Z",
        zoned: "2026-07-01T12:00:00.000Z",
        unzoned_array: ["2026-07-01T11:00:00.000Z"],
      },
    ]);
  } finally {
    if (previousTimezone === undefined) delete process.env.TZ;
    else process.env.TZ = previousTimezone;
  }
});

test("workspace stops a multi-batch cursor at 200 rows", async () => {
  const result = await query(`
    SELECT pg_backend_pid() AS pid, n FROM generate_series(1, 251) AS n ORDER BY n
  `);
  const pid = Number(result.rows[0]?.pid);
  expect(pid).toBeGreaterThan(0);
  const rows = Array.from({ length: 200 }, (_, index) => ({ pid, n: index + 1 }));
  expect(result).toEqual({
    rows,
    bytes: rows.reduce((sum, row) => sum + Buffer.byteLength(JSON.stringify(row)), 0),
    truncated: true,
    rowLimit: 200,
    byteLimit: 192 * 1024,
  });
  await expectConnectionClosed(pid);
});

test("workspace stops a cursor before the next row would exceed 192 KiB", async () => {
  const result = await query(`
    SELECT pg_backend_pid() AS pid, n, repeat('é', 2048) AS value
    FROM generate_series(1, 60) AS n ORDER BY n
  `);
  const pid = Number(result.rows[0]?.pid);
  expect(pid).toBeGreaterThan(0);
  // Each value contributes 4 KiB of UTF-8 before the row's JSON overhead.
  const rows = Array.from({ length: 47 }, (_, index) => ({ pid, n: index + 1, value: "é".repeat(2048) }));
  expect(result).toEqual({
    rows,
    bytes: rows.reduce((sum, row) => sum + Buffer.byteLength(JSON.stringify(row)), 0),
    truncated: true,
    rowLimit: 200,
    byteLimit: 192 * 1024,
  });
  await expectConnectionClosed(pid);
});
