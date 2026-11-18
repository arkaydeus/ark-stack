import { test, expect } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { caddyState } from "./caddy-state.ts";
import { CaddyWithdrawalAdapter, CADDY_RESTART_GRACE_MS } from "./edge-withdrawal.ts";

const down = async (): Promise<Response> => {
  throw new Error("ECONNREFUSED");
};

test("a fresh adapter recognises the shared fail-closed restart marker", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ark-caddy-state-"));
  try {
    const first = caddyState(dir);
    await first.recordStop();
    const second = caddyState(dir);
    expect(Date.now() - (await second.appliedStopAt())!).toBeLessThan(CADDY_RESTART_GRACE_MS);
    const result = await new CaddyWithdrawalAdapter("http://admin", down, 3000, second).enforce(new Set());
    expect(result.unreachable).toBe(true);
    expect(result.error).toBeUndefined();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
