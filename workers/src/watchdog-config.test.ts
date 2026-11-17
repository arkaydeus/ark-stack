import { expect, test } from "bun:test";
import { watchdogConfig } from "./watchdog-config.ts";

test("watchdog settings reject NaN, infinities, fractions, empty and out-of-range values", () => {
  const defaults = { intervalMs: 1000, staleMs: 5000, port: 2021 };
  expect(watchdogConfig({})).toEqual(defaults);
  for (const value of ["abc", "NaN", "Infinity", "", " ", "-1", "0", "65536", "0.5"]) {
    expect(
      watchdogConfig({
        ARK_EDGE_WATCHDOG_INTERVAL_MS: value,
        ARK_EDGE_WATCHDOG_STALE_MS: value,
        ARK_EDGE_WATCHDOG_PORT: value,
      }),
    ).toEqual(defaults);
  }
  expect(
    watchdogConfig({
      ARK_EDGE_WATCHDOG_INTERVAL_MS: "100",
      ARK_EDGE_WATCHDOG_STALE_MS: "500",
      ARK_EDGE_WATCHDOG_PORT: "3030",
    }),
  ).toEqual({ intervalMs: 100, staleMs: 500, port: 3030 });
});

test("worker starts with invalid settings on the default port and cadence", async () => {
  const control = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      if (new URL(request.url).pathname === "/config/") return Response.json({ apps: {} });
      return Response.json({ now: new Date().toISOString(), lease: null, routes: [] });
    },
  });
  const worker = Bun.spawn(["bun", new URL("./edge-watchdog.ts", import.meta.url).pathname], {
    env: {
      ...process.env,
      ARK_API_URL: control.url.toString(),
      ARK_EDGE_ADMIN_URL: control.url.toString().replace(/\/$/, ""),
      ARK_EDGE_WATCHDOG_INTERVAL_MS: "abc",
      ARK_EDGE_WATCHDOG_STALE_MS: "abc",
      ARK_EDGE_WATCHDOG_PORT: "abc",
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  try {
    let first: string | undefined;
    for (let i = 0; i < 40; i++) {
      const health = (await fetch("http://127.0.0.1:2021/v1/health")
        .then((response) => response.json())
        .catch(() => null)) as { lastTick?: { at: string } } | null;
      if (health?.lastTick?.at) {
        first = health.lastTick.at;
        break;
      }
      await Bun.sleep(50);
    }
    expect(first).toBeDefined();
    await Bun.sleep(1_100);
    const response = await fetch("http://127.0.0.1:2021/v1/health");
    const health = (await response.json()) as { lastTick: { at: string } };
    expect(Date.parse(health.lastTick.at) - Date.parse(first!)).toBeGreaterThanOrEqual(900);
    expect((await fetch("http://127.0.0.1:2021/v1/supervise")).status).toBe(200);
  } finally {
    worker.kill();
    await worker.exited;
    control.stop(true);
  }
  const output = await new Response(worker.stdout).text();
  expect(output).toContain("edge watchdog on :2021; interval 1000 ms, stale after 5000 ms");
}, 10_000);
