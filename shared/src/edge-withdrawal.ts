// Active withdrawal of tailnet backends from the running edge proxies (docs/design/front-door.md
// §3.2, FD-06). The edge-local watchdog and the `edge.drain` operation both use it.
//
// The policy is an allowlist: a backend is allowed only while the persisted lease is fresh, the
// route is enabled and `ready`, and its pinned identity still matches the latest complete
// observation. Every tailnet backend in the active proxy config that is not on the list is withdrawn.
// If the withdrawal cannot be applied and verified, the proxy is stopped: stale configuration must
// not keep serving. Each proxy has an adapter; Caddy's is here, HAProxy's (FD-25) is in
// haproxy-control.ts.

import { inTailscaleRange, parseIpLiteral } from "./tailnet.ts";
import { backendKey } from "./tailnet-observe.ts";

/** One allowed tailnet backend, as served by `GET /api/internal/edge/lease`. */
export type EdgePolicyRoute = {
  id: string;
  kind: string;
  hostname: string;
  ip: string;
  port: number;
  stableId: string;
};

/** The read-only lease and policy document the watchdog polls. */
export type EdgeLeaseDocument = {
  /** The API's clock, so the watchdog can measure the remaining lease without trusting its own. */
  now: string;
  lease: { generation: string; completedAt: string; validUntil: string; valid: boolean } | null;
  /** Allowed routes; always empty when the lease is missing or expired. */
  routes: EdgePolicyRoute[];
};

/** Result of one enforcement pass on one proxy. */
export type WithdrawalResult = {
  proxy: string;
  /** Tailnet backends found in the active config. */
  active: string[];
  /** Backends removed by this pass. */
  withdrawn: string[];
  /** Set when withdrawal could not be applied or verified; the caller must stop the proxy. */
  error?: string;
  /** The proxy could not be inspected at all (it may be stopped or restarting). */
  unreachable?: boolean;
};

/**
 * What every proxy adapter provides. `enforce` withdraws tailnet handlers whose route identity
 * key is not in `allowed` and verifies the result; `stop` closes all of the proxy's listeners and sessions.
 * `HaproxyWithdrawalAdapter` (haproxy-control.ts, FD-25) implements it for HAProxy: master CLI,
 * admission first, sessions shut down across current and leaving workers, `stop` as the fallback.
 */
export interface EdgeWithdrawalAdapter {
  readonly proxy: string;
  enforce(allowed: ReadonlySet<string>): Promise<WithdrawalResult>;
  stop(): Promise<void>;
}

/** The canonical backend key of a Caddy `dial` address when it is a Tailscale address, else null. */
export function tailnetDialKey(dial: unknown) {
  if (typeof dial !== "string") return null;
  // Caddy network addresses may carry a network prefix such as `tcp/`.
  const address = dial.replace(/^[a-z0-9]+\//i, "");
  const match = /^\[([0-9a-f:.]+)\]:(\d{1,5})$/i.exec(address) ?? /^([0-9.]+):(\d{1,5})$/.exec(address);
  if (!match) return null;
  const ip = parseIpLiteral(match[1]!.toLowerCase());
  if (!ip || !inTailscaleRange(ip)) return null;
  return backendKey(ip.canonical, Number(match[2]));
}

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function reverseProxyKeys(handler: { [key: string]: Json }) {
  const upstreams = Array.isArray(handler.upstreams) ? handler.upstreams : [];
  return upstreams
    .map((upstream) =>
      upstream && typeof upstream === "object" && !Array.isArray(upstream)
        ? tailnetDialKey(upstream.dial)
        : null,
    )
    .filter((key): key is string => key !== null);
}

/** The static response that replaces a withdrawn handler. It names no internal host. */
export const WITHDRAWN_HANDLER = {
  handler: "static_response",
  status_code: 503,
  headers: { "Cache-Control": ["no-store"] },
  body: "This hostname is not available.",
} as const;

/** Every tailnet backend referenced by `reverse_proxy` handlers in a Caddy JSON config. */
export function caddyTailnetBackends(config: unknown) {
  const found = new Set<string>();
  const visit = (value: unknown) => {
    if (Array.isArray(value)) {
      for (const item of value) visit(item);
      return;
    }
    if (!value || typeof value !== "object") return;
    const object = value as { [key: string]: Json };
    if (object.handler === "reverse_proxy") for (const key of reverseProxyKeys(object)) found.add(key);
    for (const child of Object.values(object)) visit(child);
  };
  visit(config);
  return [...found].toSorted();
}

/** Identity metadata survives Caddyfile adaptation in a native `vars` handler. */
export function routeIdentityKey(
  route: Pick<EdgePolicyRoute, "id" | "hostname" | "stableId" | "ip" | "port">,
) {
  return encodeURIComponent(
    JSON.stringify([route.id, route.hostname, route.stableId, backendKey(route.ip, route.port)]),
  );
}

function identityMatches(identity: string, backend: string, hosts: string[]) {
  try {
    const [id, hostname, stableId, target] = JSON.parse(decodeURIComponent(identity));
    return (
      typeof id === "string" &&
      id.length > 0 &&
      typeof stableId === "string" &&
      stableId.length > 0 &&
      hosts.length === 1 &&
      hosts[0] === hostname &&
      target === backend
    );
  } catch {
    return false;
  }
}

/**
 * Withdraws individual handlers, even when several routes dial the same backend. Unmarked legacy
 * handlers fail closed. Host match, stable identity, route ID and pinned backend must all agree.
 */
export function withdrawCaddyBackends(config: unknown, allowed: ReadonlySet<string>) {
  const withdrawn = new Set<string>();
  const activeRoutes = new Set<string>();
  const rewrite = (value: Json, hosts: string[] = [], identity = ""): Json => {
    if (Array.isArray(value)) {
      let current = identity;
      return value.map((child) => {
        if (child && typeof child === "object" && !Array.isArray(child) && child.handler === "vars") {
          current = typeof child.ark_tailnet_route === "string" ? child.ark_tailnet_route : "";
        }
        return rewrite(child, hosts, current);
      });
    }
    if (!value || typeof value !== "object") return value;
    if (Array.isArray(value.match)) {
      const matched = value.match.flatMap((match) =>
        match && typeof match === "object" && !Array.isArray(match) && Array.isArray(match.host)
          ? match.host.filter((host): host is string => typeof host === "string")
          : [],
      );
      if (matched.length) hosts = matched;
    }
    if (value.handler === "reverse_proxy") {
      const keys = reverseProxyKeys(value);
      const denied = keys.filter((key) => !allowed.has(identity) || !identityMatches(identity, key, hosts));
      if (denied.length) {
        for (const key of denied) withdrawn.add(key);
        return structuredClone(WITHDRAWN_HANDLER) as unknown as Json;
      }
      if (keys.length) activeRoutes.add(identity);
    }
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, rewrite(child, hosts, identity)]),
    );
  };
  const next = rewrite(config as Json);
  return { config: next, withdrawn: [...withdrawn].toSorted(), activeRoutes: [...activeRoutes].toSorted() };
}

/** Route identities currently served by Caddy (only correctly marked and host-bound handlers). */
export function caddyTailnetRouteKeys(config: unknown) {
  // Collect metadata, then verify it in the same traversal used for enforcement.
  const candidates = new Set<string>();
  const visit = (value: unknown) => {
    if (!value || typeof value !== "object") return;
    if ("ark_tailnet_route" in value && typeof value.ark_tailnet_route === "string")
      candidates.add(value.ark_tailnet_route);
    for (const child of Object.values(value)) visit(child);
  };
  visit(config);
  return withdrawCaddyBackends(config, candidates).activeRoutes;
}

type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

/**
 * Caddy adapter over the admin API (`edge-admin:2019`, reachable only from edge-control). Withdrawal
 * is a `/load` of the active config with the denied handlers replaced, sent with
 * `Cache-Control: must-revalidate`. The reload closes the withdrawn handlers' upgraded connections
 * (Ark renders no `stream_close_delay` for tailnet routes yet) and the rendered `grace_period` bounds
 * in-flight requests on the old server. The fallback is `POST /stop`, which ends the Caddy process;
 * its launch guard then refuses to serve tailnet routes until the lease is valid again.
 */
export class CaddyWithdrawalAdapter implements EdgeWithdrawalAdapter {
  readonly proxy = "caddy";

  constructor(
    private readonly adminUrl: string,
    private readonly fetcher: Fetch = fetch,
    private readonly timeoutMs = 3_000,
  ) {}

  private request(path: string, init: RequestInit = {}) {
    return this.fetcher(`${this.adminUrl.replace(/\/$/, "")}${path}`, {
      ...init,
      signal: AbortSignal.timeout(this.timeoutMs),
    });
  }

  private async activeConfig() {
    const response = await this.request("/config/");
    if (!response.ok) throw new Error(`GET /config/ returned ${response.status}`);
    return (await response.json()) as unknown;
  }

  async activeRoutes() {
    return caddyTailnetRouteKeys(await this.activeConfig());
  }

  /** Tailnet backends Caddy dials right now. */
  async activeBackends() {
    return caddyTailnetBackends(await this.activeConfig());
  }

  async enforce(allowed: ReadonlySet<string>): Promise<WithdrawalResult> {
    let config: unknown;
    try {
      config = await this.activeConfig();
    } catch (error) {
      return {
        proxy: this.proxy,
        active: [],
        withdrawn: [],
        unreachable: true,
        error: `Caddy admin API unreachable: ${(error as Error).message}`,
      };
    }
    const active = caddyTailnetBackends(config);
    const { config: next, withdrawn } = withdrawCaddyBackends(config, allowed);
    if (!withdrawn.length) return { proxy: this.proxy, active, withdrawn };
    try {
      const loaded = await this.request("/load", {
        method: "POST",
        headers: { "content-type": "application/json", "cache-control": "must-revalidate" },
        body: JSON.stringify(next),
      });
      if (!loaded.ok)
        throw new Error(`POST /load returned ${loaded.status}: ${(await loaded.text()).slice(0, 200)}`);
      const remaining = withdrawCaddyBackends(await this.activeConfig(), allowed).withdrawn;
      if (remaining.length) throw new Error(`still dialing ${remaining.join(", ")} after reload`);
    } catch (error) {
      return {
        proxy: this.proxy,
        active,
        withdrawn,
        error: `withdrawal failed: ${(error as Error).message}`,
      };
    }
    return { proxy: this.proxy, active, withdrawn };
  }

  async stop() {
    const response = await this.request("/stop", { method: "POST" });
    if (!response.ok) throw new Error(`POST /stop returned ${response.status}`);
  }
}

/**
 * Allowed route identity keys (route ID, hostname, StableID and pinned backend), or none without a
 * fresh lease. Every route kind is included: Caddy matches only its HTTP handlers' identities and
 * HAProxy only the server names derived from L4 routes (`haproxyServerName`), so a key never
 * authorises a different proxy's handler.
 */
export function allowedBackends(document: Pick<EdgeLeaseDocument, "lease" | "routes">) {
  if (!document.lease?.valid) return new Set<string>();
  return new Set(document.routes.map(routeIdentityKey));
}

/** Tailnet `ip:port` literals in a rendered Caddyfile (`reverse_proxy 100.x.y.z:port`, `[fd7a:…]:port`). */
export function caddyfileTailnetBackends(caddyfile: string) {
  const found = new Set<string>();
  for (const match of caddyfile.matchAll(/(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b/g)) {
    const key = tailnetDialKey(`${match[1]}:${match[2]}`);
    if (key) found.add(key);
  }
  for (const match of caddyfile.matchAll(/\[([0-9a-fA-F:.]+)\]:(\d{1,5})\b/g)) {
    const key = tailnetDialKey(`[${match[1]}]:${match[2]}`);
    if (key) found.add(key);
  }
  return [...found].toSorted();
}

/**
 * The Caddy launch guard's decision for the full Caddyfile: `open` when it references no tailnet
 * backend, or when every one it references is allowed by a currently valid lease. Otherwise the
 * guard starts Caddy from the closed variant, which renders no tailnet route.
 */
export function launchDecision(caddyfile: string, allowed: ReadonlySet<string>) {
  const backends = caddyfileTailnetBackends(caddyfile);
  const denied = new Set<string>();
  const checked = new Set<string>();
  let hosts: string[] = [];
  let identity = "";
  for (const line of caddyfile.split("\n")) {
    const site = /^([a-z0-9.-]+) \{$/.exec(line);
    if (site) {
      hosts = [site[1]!];
      identity = "";
    }
    const metadata = /^\s*vars ark_tailnet_route (\S+)\s*$/.exec(line);
    if (metadata) identity = metadata[1]!;
    if (!/^\s*reverse_proxy\s/.test(line)) continue;
    for (const key of caddyfileTailnetBackends(line)) {
      checked.add(key);
      if (!allowed.has(identity) || !identityMatches(identity, key, hosts)) denied.add(key);
    }
  }
  for (const key of backends) if (!checked.has(key)) denied.add(key);
  return { open: denied.size === 0, backends, denied: [...denied].toSorted() };
}

export type WatchdogEvent = {
  event: "withdrawn" | "withdrawal_failed" | "proxy_stopped" | "stop_failed" | "policy_unavailable";
  proxy?: string;
  detail: string;
};

export type WatchdogOptions = {
  /** Fetches the lease document; throws when the API is unreachable or refuses the token. */
  fetchLease: () => Promise<EdgeLeaseDocument>;
  adapters: EdgeWithdrawalAdapter[];
  /** Reports an event to the API (alerts); failures are logged, never fatal. */
  report?: (event: WatchdogEvent) => Promise<void>;
  log?: (line: string) => void;
  now?: () => number;
  /** A policy older than this is treated as revoked (default 5 s, §3.9.3). */
  staleMs?: number;
  /** Initial Caddy startup only; once inspected, errors fail closed immediately. */
  startupGraceMs?: number;
};

/**
 * The edge-local lease watchdog (§3.2). `tick` runs at least every second, independently of the
 * operation workers: it refreshes the policy from the API, and when the lease has expired or the
 * policy cannot be refreshed for `staleMs`, it withdraws every tailnet backend.
 */
export class EdgeWatchdog {
  private allowed = new Set<string>();
  /** Local monotonic deadline of the current lease; never reached before the first read. */
  private deadline = Number.NEGATIVE_INFINITY;
  /** When the last policy was read (local clock), or null before the first successful read. */
  private fetchedAt: number | null = null;
  private lastPolicyError = "";
  /** Last unreachable message per proxy, so the log records changes rather than every second. */
  private readonly unreachable = new Map<string, string>();
  private readonly failures = new Map<string, string>();
  private readonly stopOutcomes = new Map<string, string>();
  private readonly pendingEvents = new Map<string, WatchdogEvent>();
  private readonly inspected = new Set<string>();
  private readonly startedAt: number;
  private readonly now: () => number;
  private readonly staleMs: number;

  constructor(private readonly options: WatchdogOptions) {
    this.now = options.now ?? (() => performance.now());
    this.staleMs = options.staleMs ?? 5_000;
    this.startedAt = this.now();
  }

  /** The backends allowed right now; empty when the lease expired or the policy is stale. */
  private leaseValid(at: number) {
    return this.fetchedAt !== null && at - this.fetchedAt <= this.staleMs && at < this.deadline;
  }

  effectiveAllowed(at = this.now()) {
    return this.leaseValid(at) ? this.allowed : new Set<string>();
  }

  state(at = this.now()) {
    return {
      leaseValid: this.leaseValid(at),
      allowed: this.effectiveAllowed(at).size,
      leaseRemainingMs: Number.isFinite(this.deadline) ? Math.max(0, Math.round(this.deadline - at)) : 0,
      policyAgeMs: this.fetchedAt === null ? null : Math.round(at - this.fetchedAt),
      policyError: this.lastPolicyError || null,
    };
  }

  async refresh() {
    const started = this.now();
    try {
      const document = await this.options.fetchLease();
      // A slow answer must not replace a newer one that arrived first.
      if (this.fetchedAt !== null && started < this.fetchedAt) return;
      const apiNow = Date.parse(document.now);
      const validUntil = document.lease ? Date.parse(document.lease.validUntil) : Number.NaN;
      this.allowed = allowedBackends(document);
      // Measure the remaining lease on the API's clock and count it down on ours.
      this.deadline =
        document.lease?.valid && Number.isFinite(apiNow) && Number.isFinite(validUntil)
          ? started + Math.max(0, validUntil - apiNow)
          : Number.NEGATIVE_INFINITY;
      this.fetchedAt = started;
      if (this.lastPolicyError) this.options.log?.("edge policy available again");
      this.lastPolicyError = "";
    } catch (error) {
      const message = (error as Error).message;
      if (message !== this.lastPolicyError) this.options.log?.(`edge policy unavailable: ${message}`);
      this.lastPolicyError = message;
    }
  }

  /** Milliseconds until the current lease runs out on the local clock, or null without one. */
  msUntilExpiry(at = this.now()) {
    return this.leaseValid(at) ? Math.max(0, this.deadline - at) : null;
  }

  /**
   * One pass: refresh the policy, waiting at most `refreshWaitMs`, then enforce. Reading the policy
   * after the config it is compared with means a route that edge.apply has just made live is not
   * withdrawn on a policy that predates it; bounding the wait means a slow API never delays expiry.
   */
  async tick(refreshWaitMs = Number.POSITIVE_INFINITY) {
    const refreshed = this.refresh();
    if (Number.isFinite(refreshWaitMs)) {
      await Promise.race([refreshed, new Promise((resolve) => setTimeout(resolve, refreshWaitMs))]);
    } else {
      await refreshed;
    }
    return this.enforce();
  }

  /**
   * Enforces the policy as it stands now, without waiting for the API. The worker runs this on its
   * own cadence and at the lease deadline, so a slow or hanging lease read cannot delay expiry.
   */
  async enforce() {
    await this.flushEvents();
    const allowed = this.effectiveAllowed();
    const results: WithdrawalResult[] = [];
    for (const adapter of this.options.adapters) {
      const started = this.now();
      const result = await adapter.enforce(allowed);
      const took = Math.round(this.now() - started);
      results.push(result);
      const unreachable = result.unreachable ? (result.error ?? "unreachable") : "";
      if (unreachable !== (this.unreachable.get(adapter.proxy) ?? "")) {
        this.options.log?.(
          unreachable ? `${adapter.proxy}: ${unreachable}` : `${adapter.proxy}: reachable again`,
        );
        this.unreachable.set(adapter.proxy, unreachable);
      }
      if (result.withdrawn.length && !result.error) {
        await this.emit({
          event: "withdrawn",
          proxy: adapter.proxy,
          detail: `withdrew ${backendSummary(result.withdrawn)} in ${took} ms${this.lastPolicyError ? ` (policy unavailable: ${this.lastPolicyError})` : ""}`,
        });
      }
      if (!result.unreachable) this.inspected.add(adapter.proxy);
      if (
        result.unreachable &&
        !this.inspected.has(adapter.proxy) &&
        this.now() - this.startedAt < (this.options.startupGraceMs ?? 5_000)
      )
        continue;
      if (result.error) {
        // Withdrawal could not be applied: stale configuration must not keep serving.
        const previous = this.failures.get(adapter.proxy);
        if (previous !== result.error) {
          await this.emit({ event: "withdrawal_failed", proxy: adapter.proxy, detail: result.error });
        }
        this.failures.set(adapter.proxy, result.error);
        try {
          await adapter.stop();
          if (this.stopOutcomes.get(adapter.proxy) !== "stopped")
            await this.emit({
              event: "proxy_stopped",
              proxy: adapter.proxy,
              detail: `stopped ${adapter.proxy} after a failed withdrawal of ${backendSummary(result.withdrawn)}`,
            });
          this.stopOutcomes.set(adapter.proxy, "stopped");
        } catch (error) {
          const message = (error as Error).message;
          if (this.stopOutcomes.get(adapter.proxy) !== message)
            await this.emit({ event: "stop_failed", proxy: adapter.proxy, detail: message });
          this.stopOutcomes.set(adapter.proxy, message);
        }
      } else {
        this.failures.delete(adapter.proxy);
        this.stopOutcomes.delete(adapter.proxy);
      }
    }
    return results;
  }

  private async emit(event: WatchdogEvent) {
    const bounded = { ...event, detail: event.detail.slice(0, 1000) };
    this.options.log?.(`${bounded.event}${bounded.proxy ? ` [${bounded.proxy}]` : ""}: ${bounded.detail}`);
    // Coalesce per proxy/event so retries remain bounded during an API outage. A successful
    // withdrawal must still be reported after the next pass sees no remaining denied handlers.
    this.pendingEvents.set(`${event.proxy ?? "edge"}:${event.event}`, bounded);
    await this.flushEvents();
  }

  private async flushEvents() {
    if (!this.options.report) {
      this.pendingEvents.clear();
      return;
    }
    for (const [key, event] of this.pendingEvents) {
      try {
        await this.options.report(event);
        this.pendingEvents.delete(key);
      } catch (error) {
        this.options.log?.(`report failed: ${(error as Error).message}`);
      }
    }
  }
}

function backendSummary(backends: string[]) {
  return `${backends.length} backend(s): ${backends.slice(0, 8).join(", ")}${backends.length > 8 ? ", …" : ""}`;
}
