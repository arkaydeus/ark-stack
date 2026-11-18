// Edge-local lease watchdog (docs/design/front-door.md §3.2, FD-06).
//
// Runs as its own container on `control` (to read the lease from the API) and `edge-control` (to
// reach Caddy's admin API and to answer the launch guards). It holds no database credential, no root
// key and no Docker or tailscaled socket; for HAProxy it shares only the master CLI socket (group
// 4400) and reads the configuration generations. Every second it reads the read-only lease/policy
// endpoint with its own token and withdraws every tailnet backend the policy does not allow from the
// running Caddy and from every current and leaving HAProxy worker; when the lease expires, or the
// policy cannot be read for 5 s, that is all of them. If a withdrawal cannot be applied and verified
// it fences protected traffic and raises an alert. Caddy stops its HTTP app; HAProxy preserves
// unrelated HTTP, with its launch guard stopping the process if enforcement stays unverified.
// It works with the operation workers stopped. HAProxy closes withdrawn HTTP sessions on the
// route's SNI backend while Caddy replaces the route handler with a fixed 503.
//
// `GET /v1/launch[?proxy=haproxy]` answers `open` or `closed` for the launch guards
// (infra/platform/edge-launch-guard.sh, infra/platform/edge-l4-launch-guard.sh): `open` only when
// every rendered route identity and pinned backend is allowed by a valid lease.
// `GET /v1/supervise?proxy=<caddy|haproxy>` requires recently verified enforcement on that proxy
// (without `proxy`, on every proxy).
import { join } from "node:path";

import {
  caddyState,
  CaddyWithdrawalAdapter,
  HaproxyWithdrawalAdapter,
  haproxyLaunchDecision,
  launchDecision,
  redactLogLine,
  type EdgeLeaseDocument,
  type EdgeWithdrawalAdapter,
  type WatchdogEvent,
} from "@ark-stack/shared";

import { ProxyWatchdog } from "./proxy-watchdog.ts";

import { watchdogConfig } from "./watchdog-config.ts";

const apiUrl = (process.env.ARK_API_URL ?? "http://api:3000").replace(/\/$/, "");
const token = process.env.ARK_EDGE_WATCHDOG_TOKEN?.trim() ?? "";
const adminUrl = process.env.ARK_EDGE_ADMIN_URL ?? "http://edge-admin:2019";
const edgeDir = process.env.ARK_EDGE_DIR ?? "/var/lib/ark/edge";
const caddyfile = join(edgeDir, "Caddyfile");
// HAProxy (edge-l4, FD-25): enforced only where its master socket is mounted.
const haproxyMaster = process.env.ARK_HAPROXY_MASTER_SOCKET?.trim() ?? "";
const haproxyConfig = join(process.env.ARK_EDGE_L4_DIR ?? "/usr/local/etc/haproxy", "current", "haproxy.cfg");
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

const adapters: EdgeWithdrawalAdapter[] = [
  new CaddyWithdrawalAdapter(adminUrl, fetch, 3_000, {
    ...caddyState(edgeDir),
    scopedHttp: haproxyMaster
      ? () => new HaproxyWithdrawalAdapter(haproxyMaster).ensureHttpControl()
      : undefined,
  }),
];
if (haproxyMaster) adapters.push(new HaproxyWithdrawalAdapter(haproxyMaster));
const proxies = new Map(
  adapters.map((adapter) => [
    adapter.proxy,
    new ProxyWatchdog({ fetchLease, adapters: [adapter], report, log, staleMs }),
  ]),
);
const run = { stopped: false };

// Each pass reads the lease (waiting at most 300 ms, so a slow API never delays enforcement) and
// enforces it. Passes run every interval and also exactly when the current lease runs out.
async function loop(proxy: ProxyWatchdog) {
  const watchdog = proxy.watchdog;
  while (!run.stopped) {
    const started = performance.now();
    try {
      await proxy.tick();
    } catch (error) {
      log(`enforcement failed: ${(error as Error).message}`);
    }
    const took = performance.now() - started;
    if (took > 1_500) log(`slow enforcement pass: ${Math.round(took)} ms`);
    const untilExpiry = watchdog.msUntilExpiry();
    const wait = Math.max(0, intervalMs - (performance.now() - started));
    await Bun.sleep(untilExpiry === null ? wait : Math.min(wait, untilExpiry + 1));
  }
}

const server = Bun.serve({
  hostname: "0.0.0.0",
  port,
  async fetch(request) {
    const { pathname, searchParams } = new URL(request.url);
    if (request.method !== "GET") return new Response("method not allowed", { status: 405 });
    const proxy = searchParams.get("proxy");
    const watchdog = (proxies.get(proxy ?? "caddy") ?? proxies.get("caddy")!).watchdog;
    if (pathname === "/v1/launch") {
      // Refresh first so a guard starting right after a watchdog restart sees the current lease. The
      // HAProxy guard's periodic re-check (`cached=1`) uses the policy the watchdog loop keeps fresh.
      if (searchParams.get("cached") !== "1") await watchdog.refresh();
      const haproxy = proxy === "haproxy";
      const text = await Bun.file(haproxy ? haproxyConfig : caddyfile)
        .text()
        .catch(() => null);
      const allowed = watchdog.effectiveAllowed();
      const decision =
        text === null
          ? { open: false }
          : haproxy
            ? haproxyLaunchDecision(text, allowed)
            : launchDecision(text, allowed);
      if (searchParams.get("cached") !== "1")
        log(`${haproxy ? "haproxy" : "caddy"} launch guard asked: ${decision.open ? "open" : "closed"}`);
      return new Response(`${decision.open ? "open" : "closed"}\n`, {
        headers: { "cache-control": "no-store" },
      });
    }
    if (pathname === "/v1/supervise") {
      // Respond only from a recently completed, verified enforcement pass on that proxy. A responsive
      // HTTP server with a wedged loop or an unreadable admin API must not keep the proxy alive.
      const names = proxy ? [proxy] : [...proxies.keys()];
      const healthy = names.every((name) => proxies.get(name)?.healthy());
      return new Response(healthy ? "ok\n" : "closed\n", {
        status: healthy ? 200 : 503,
        headers: { "cache-control": "no-store" },
      });
    }
    if (pathname === "/v1/health") {
      // Counts and timings only: no route, address or token.
      return Response.json({
        ...watchdog.state(),
        // Preserve the original Caddy health summary for existing monitoring clients.
        lastTick: proxies.get("caddy")!.lastTick && {
          ...proxies.get("caddy")!.lastTick,
          withdrawn: proxies.get("caddy")!.lastTick!.withdrawn.length,
        },
        proxies: Object.fromEntries(
          [...proxies].map(([name, state]) => [
            name,
            {
              ...state.watchdog.state(),
              lastTick: state.lastTick && { ...state.lastTick, withdrawn: state.lastTick.withdrawn.length },
            },
          ]),
        ),
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
  `edge watchdog on :${port}; interval ${intervalMs} ms, stale after ${staleMs} ms; Caddy admin ${adminUrl}` +
    (haproxyMaster ? `; HAProxy master ${haproxyMaster}` : "; HAProxy not configured"),
);
if (!token) log("ARK_EDGE_WATCHDOG_TOKEN is not set: every tailnet route stays withdrawn");
await Promise.all([...proxies.values()].map(loop));
