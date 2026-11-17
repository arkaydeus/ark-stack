import { expect, test } from "bun:test";
import { ProxyWatchdog } from "./proxy-watchdog.ts";

const fetchLease = async () => ({ now: new Date().toISOString(), lease: null, routes: [] });

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
// healthy within the 5 s withdrawal budget, so the launch guard does not stop HAProxy (and every
// unrelated session) mid-withdrawal; past the budget, or after a failure, it is unhealthy again.
test("an in-progress pass from a verified state stays healthy only within the withdrawal budget", async () => {
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
  expect(haproxy.healthy(verified + 3_000)).toBe(true);
  expect(haproxy.healthy(haproxy.passStartedAt! + 5_001)).toBe(false);
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
