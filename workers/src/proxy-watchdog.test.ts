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
