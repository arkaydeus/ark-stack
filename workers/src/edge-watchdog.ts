// Edge-local lease watchdog (docs/design/front-door.md §3.2, FD-06).
//
// Runs as its own container on `control` (to read the lease from the API) and `edge-control` (to
// reach Caddy's admin API and to answer the Caddy launch guard). It holds no database credential,
// no root key and no Docker or tailscaled socket. Every second it reads the read-only lease/policy
// endpoint with its own token and withdraws every tailnet backend the policy does not allow from
// the running Caddy; when the lease expires, or the policy cannot be read for 5 s, that is all of
// them. If a withdrawal cannot be applied and verified it stops Caddy and raises an alert. It works
// with the operation workers stopped.
//
// `GET /v1/launch` answers `open` or `closed` for the Caddy launch guard
// (infra/platform/edge-launch-guard.sh): `open` only when every rendered route identity and pinned
// backend is allowed by a valid lease. `/v1/supervise` requires recently verified enforcement.
// FD-25 adds the HAProxy adapter and launch guard.
import { join } from "node:path";

import {
  CaddyWithdrawalAdapter,
  EdgeWatchdog,
  launchDecision,
  redactLogLine,
  type EdgeLeaseDocument,
  type WatchdogEvent,
} from "@ark-stack/shared";

import { watchdogConfig } from "./watchdog-config.ts";

const apiUrl = (process.env.ARK_API_URL ?? "http://api:3000").replace(/\/$/, "");
const token = process.env.ARK_EDGE_WATCHDOG_TOKEN?.trim() ?? "";
const adminUrl = process.env.ARK_EDGE_ADMIN_URL ?? "http://edge-admin:2019";
const caddyfile = join(process.env.ARK_EDGE_DIR ?? "/var/lib/ark/edge", "Caddyfile");
// Never slower than once a second (§3.2); tests may run it faster.
const { intervalMs, staleMs, port } = watchdogConfig(process.env);

const log = (line: string) => console.log(`${new Date().toISOString()} ${redactLogLine(line)}`);

async function fetchLease(): Promise<EdgeLeaseDocument> {
  if (!token) throw new Error("ARK_EDGE_WATCHDOG_TOKEN is not set");
  const response = await fetch(`${apiUrl}/api/internal/edge/lease`, {
    headers: { authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(2_000),
  });
  if (!response.ok) throw new Error(`lease endpoint returned ${response.status}`);
  return (await response.json()) as EdgeLeaseDocument;
}

async function report(event: WatchdogEvent) {
  if (!token) return;
  const response = await fetch(`${apiUrl}/api/internal/edge/watchdog-event`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(event),
    signal: AbortSignal.timeout(2_000),
  });
  if (!response.ok) throw new Error(`watchdog-event returned ${response.status}`);
}

const watchdog = new EdgeWatchdog({
  fetchLease,
  adapters: [new CaddyWithdrawalAdapter(adminUrl)],
  report,
  log,
  staleMs,
});

const run = { stopped: false };
let lastVerifiedAt = Number.NEGATIVE_INFINITY;
let lastTick: { at: string; withdrawn: string[]; errors: string[] } | null = null;

// Each pass reads the lease (waiting at most 300 ms, so a slow API never delays enforcement) and
// enforces it. Passes run every interval and also exactly when the current lease runs out.
async function loop() {
  while (!run.stopped) {
    const started = performance.now();
    try {
      const results = await watchdog.tick(300);
      if (results.every((result) => !result.error)) lastVerifiedAt = performance.now();
      else lastVerifiedAt = Number.NEGATIVE_INFINITY;
      lastTick = {
        at: new Date().toISOString(),
        withdrawn: results.flatMap((result) => result.withdrawn),
        errors: results.flatMap((result) => (result.error ? [`${result.proxy}: ${result.error}`] : [])),
      };
    } catch (error) {
      lastVerifiedAt = Number.NEGATIVE_INFINITY;
      log(`enforcement failed: ${(error as Error).message}`);
    }
    const untilExpiry = watchdog.msUntilExpiry();
    const wait = Math.max(0, intervalMs - (performance.now() - started));
    await Bun.sleep(untilExpiry === null ? wait : Math.min(wait, untilExpiry + 1));
  }
}

const server = Bun.serve({
  hostname: "0.0.0.0",
  port,
  async fetch(request) {
    const { pathname } = new URL(request.url);
    if (request.method !== "GET") return new Response("method not allowed", { status: 405 });
    if (pathname === "/v1/launch") {
      // Refresh first so a guard starting right after a watchdog restart sees the current lease.
      await watchdog.refresh();
      const text = await Bun.file(caddyfile)
        .text()
        .catch(() => null);
      const decision = text === null ? { open: false } : launchDecision(text, watchdog.effectiveAllowed());
      log(`launch guard asked: ${decision.open ? "open" : "closed"}`);
      return new Response(`${decision.open ? "open" : "closed"}\n`, {
        headers: { "cache-control": "no-store" },
      });
    }
    if (pathname === "/v1/supervise") {
      // Respond only from a recently completed, verified enforcement pass. A responsive HTTP
      // server with a wedged loop or unreadable admin API must not keep Caddy alive.
      const healthy = performance.now() - lastVerifiedAt <= 2_000;
      return new Response(healthy ? "ok\n" : "closed\n", {
        status: healthy ? 200 : 503,
        headers: { "cache-control": "no-store" },
      });
    }
    if (pathname === "/v1/health") {
      // Counts and timings only: no route, address or token.
      return Response.json({
        ...watchdog.state(),
        lastTick: lastTick && { ...lastTick, withdrawn: lastTick.withdrawn.length },
      });
    }
    return new Response("not found", { status: 404 });
  },
});

const shutdown = () => {
  run.stopped = true;
  void server.stop(true);
};
process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);

log(
  `edge watchdog on :${port}; interval ${intervalMs} ms, stale after ${staleMs} ms; Caddy admin ${adminUrl}`,
);
if (!token) log("ARK_EDGE_WATCHDOG_TOKEN is not set: every tailnet route stays withdrawn");
await loop();
