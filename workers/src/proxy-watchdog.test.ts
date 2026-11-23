import { expect, test } from "bun:test";
import type { EdgeLeaseDocument } from "@ark-stack/shared";
import { settledGatePass } from "../../scripts/edge-test/gate-edge.ts";
import { ProxyWatchdog } from "./proxy-watchdog.ts";

const fetchLease = async () => ({ now: new Date().toISOString(), lease: null, routes: [] });

test("settling uses the allowed policy captured by the completed Caddy pass", async () => {
  const since = Date.now();
  const validUntil = new Date(since + 60_000).toISOString();
  const lease = { generation: "lease", completedAt: new Date(since).toISOString(), validUntil, valid: true };
  const route = {
    id: "rt_fixture",
    kind: "http",
    hostname: "app.example.test",
    stableId: "node",
    ip: "100.64.0.2",
    port: 80,
  };
  const old = { now: new Date(since - 1).toISOString(), lease, routes: [] };
  const denied = { ...old, now: new Date(since + 1).toISOString() };
  const allowed = { ...denied, routes: [route], gateRecovery: "applied" };
  const delayed = Promise.withResolvers<EdgeLeaseDocument>();
  const enforcing = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  let answer: Promise<EdgeLeaseDocument> = Promise.resolve(old);
  let hold = false;
  const caddy = new ProxyWatchdog({
    fetchLease: () => answer,
    adapters: [
      {
        proxy: "caddy",
        async enforce(routes) {
          if (hold) {
            expect(routes.size).toBe(0);
            enforcing.resolve();
            await release.promise;
          }
          // A reachable Caddy with a route-free config is a verified no-op under every lease.
          return { proxy: "caddy", active: [], withdrawn: [] };
        },
        async stop() {},
      },
    ],
  });
  const settled = () => settledGatePass(caddy.completedPass(), since, 1);
  await caddy.tick();
  expect(settled()).toBe(false);
  answer = Promise.resolve(denied);
  await caddy.tick();
  expect(caddy.completedPass()?.verified).toBe(true);
  expect(settled()).toBe(false);

  hold = true;
  answer = delayed.promise;
  const pass = caddy.tick();
  await enforcing.promise; // The refresh wait expired and enforcement captured the denying lease.
  try {
    delayed.resolve(allowed);
    await delayed.promise;
    expect(caddy.watchdog.state().allowed).toBe(1);
    expect(settled()).toBe(false);
  } finally {
    release.resolve();
    await pass;
  }
  expect(settled()).toBe(false);
  expect(caddy.completedPass()?.policy.gateRecovery).toBeNull();
  hold = false;
  await caddy.tick();
  expect(settled()).toBe(true);
  expect(caddy.completedPass()?.policy.gateRecovery).toBe("applied");

  answer = Promise.resolve({ ...allowed, lease: { ...lease, valid: false } });
  await caddy.tick();
  expect(caddy.completedPass()?.policy.leaseValid).toBe(false);
  expect(settled()).toBe(false);
});

// Exercise the exact state used by /v1/supervise throughout a stalled HAProxy pass.
test("Caddy verification stays fresh while HAProxy enforcement stalls and then fails", async () => {
  const caddy = new ProxyWatchdog({
    fetchLease,
    adapters: [
      {
        proxy: "caddy",
        enforce: async () => ({ proxy: "caddy", active: [], withdrawn: [] }),
        stop: async () => {},
      },
    ],
  });
  const haproxy = new ProxyWatchdog({
    fetchLease,
    startupGraceMs: 0,
    adapters: [
      {
        proxy: "haproxy",
        enforce: async () => {
          await Bun.sleep(2_500);
          return { proxy: "haproxy", active: [], withdrawn: [], error: "CLI stalled" };
        },
        stop: async () => {},
      },
    ],
  });
  const slow = haproxy.tick();
  for (let i = 0; i < 6; i++) {
    await caddy.tick();
    expect(caddy.healthy()).toBe(true);
    expect(haproxy.healthy()).toBe(false);
    await Bun.sleep(500);
  }
  await slow;
  expect(caddy.healthy()).toBe(true);
  expect(haproxy.healthy()).toBe(false);
}, 5_000);

// FD-14: withdrawing a busy route can take a few seconds of CLI work. A pass that began verified stays
// healthy within the 3 s enforcement budget, so the launch guard does not stop HAProxy (and every
// unrelated session) mid-withdrawal; past the budget, or after a failure, it is unhealthy again.
test("an in-progress pass from a verified state stays healthy only within the enforcement budget", async () => {
  let delay = 0;
  let error: string | undefined;
  const haproxy = new ProxyWatchdog({
    fetchLease,
    startupGraceMs: 0,
    adapters: [
      {
        proxy: "haproxy",
        enforce: async () => {
          await Bun.sleep(delay);
          return { proxy: "haproxy", active: [], withdrawn: [], ...(error ? { error } : {}) };
        },
        stop: async () => {},
      },
    ],
  });
  await haproxy.tick();
  const verified = haproxy.lastVerifiedAt;
  expect(haproxy.healthy()).toBe(true);
  delay = 50;
  const pass = haproxy.tick();
  // 3 s after verification (stale on its own), into a pass that began right after it: healthy.
  expect(haproxy.healthy(verified + 2_500)).toBe(true);
  expect(haproxy.healthy(verified + 3_001)).toBe(false);
  await pass;
  error = "CLI stalled";
  await haproxy.tick();
  expect(haproxy.healthy()).toBe(false);
  // A pass that starts from an unverified state is never healthy.
  delay = 50;
  const unverified = haproxy.tick();
  expect(haproxy.healthy()).toBe(false);
  await unverified;
});

test("a late-started L4 pass cannot restart the deadline, and Caddy gets no L4 grace", () => {
  const make = (proxy: string) =>
    new ProxyWatchdog({
      fetchLease,
      adapters: [
        { proxy, enforce: async () => ({ proxy, active: [], withdrawn: [] }), stop: async () => {} },
      ],
    });
  for (const proxy of ["caddy", "haproxy"]) {
    const watchdog = make(proxy);
    watchdog.lastVerifiedAt = 0;
    watchdog.passStartedAt = 1_999;
    expect(watchdog.healthy(2_500)).toBe(proxy === "haproxy");
    expect(watchdog.healthy(3_001)).toBe(false);
  }
});
