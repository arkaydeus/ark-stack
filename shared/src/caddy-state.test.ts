import { test, expect } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { caddyState } from "./caddy-state.ts";
import { CaddyWithdrawalAdapter, CADDY_RESTART_GRACE_MS } from "./edge-withdrawal.ts";

const down = async (): Promise<Response> => {
  throw new Error("ECONNREFUSED");
};

test("a stop from drain is recognised by a fresh drain and watchdog; failed stop intent survives", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ark-caddy-state-"));
  try {
    const first = caddyState(dir);
    const second = caddyState(dir);
    let fail = true;
    const fetcher = async () => new Response(null, { status: fail ? 500 : 200 });
    const adapter = new CaddyWithdrawalAdapter("http://admin", fetcher, 3000, first);
    await adapter.markPendingStreams(["100.101.102.103:3000"]);
    await expect(adapter.stopForStreams()).rejects.toThrow("POST /stop");
    expect(await second.pendingStreams()).toEqual(["100.101.102.103:3000"]);
    fail = false;
    const drain = new CaddyWithdrawalAdapter("http://admin", fetcher, 3000, second);
    expect((await drain.enforce(new Set())).stopped).toHaveLength(1);
    expect(await first.pendingStreams()).toEqual([]);
    expect(Date.now() - (await first.appliedStopAt())!).toBeLessThan(CADDY_RESTART_GRACE_MS);
    for (let i = 0; i < 2; i++) {
      const result = await new CaddyWithdrawalAdapter("http://admin", down, 3000, caddyState(dir)).enforce(
        new Set(),
      );
      expect(result.unreachable).toBe(true);
      expect(result.error).toBeUndefined();
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("completing a stop preserves intents published by another adapter after its snapshot", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ark-caddy-intents-"));
  try {
    const first = caddyState(dir);
    const second = caddyState(dir);
    await first.markPendingStreams(["old"]);
    expect(await first.pendingStreams()).toEqual(["old"]);
    await second.markPendingStreams(["new"]);
    await first.clearPendingStreams();
    expect(await caddyState(dir).pendingStreams()).toEqual(["new"]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("an unreadable persistent stop record requests the fail-closed fallback", async () => {
  const adapter = new CaddyWithdrawalAdapter("http://admin", down, 3000, {
    pendingStreams: async () => {
      throw new Error("unreadable state");
    },
  });
  expect((await adapter.enforce(new Set())).error).toContain("Cannot inspect pending Caddy stops");
});
