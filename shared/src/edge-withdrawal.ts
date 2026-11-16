// Active withdrawal of tailnet backends from the running edge proxies (docs/design/front-door.md
// §3.2, FD-06). The edge-local watchdog and the `edge.drain` operation both use it.
//
// The policy is an allowlist: a backend is allowed only while the persisted lease is fresh, the
// route is enabled and `ready`, and its pinned identity still matches the latest complete
// observation. Every tailnet backend in the active proxy config that is not on the list is withdrawn.
// If the withdrawal cannot be applied and verified, the proxy is stopped: stale configuration must
// not keep serving. Each proxy has an adapter; Caddy's is here, HAProxy's arrives with FD-25.

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
  /** Allowed backends; always empty when the lease is missing or expired. */
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
 * What every proxy adapter provides. `enforce` withdraws every tailnet backend not in `allowed`
 * and verifies the result; `stop` closes all of the proxy's listeners and sessions.
 * FD-25 implements this for HAProxy (master CLI: disable servers, shut down sessions across every
 * worker generation, `stop` as the fallback).
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

/**
 * Replaces every `reverse_proxy` handler that dials a tailnet backend outside `allowed` with a
 * fixed 503. A handler with several upstreams is withdrawn whole when any one is not allowed.
 */
export function withdrawCaddyBackends(config: unknown, allowed: ReadonlySet<string>) {
  const withdrawn = new Set<string>();
  const rewrite = (value: Json): Json => {
    if (Array.isArray(value)) return value.map(rewrite);
    if (!value || typeof value !== "object") return value;
    if (value.handler === "reverse_proxy") {
      const denied = reverseProxyKeys(value).filter((key) => !allowed.has(key));
      if (denied.length) {
        for (const key of denied) withdrawn.add(key);
        return structuredClone(WITHDRAWN_HANDLER) as unknown as Json;
      }
    }
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, rewrite(child)]));
  };
  const next = rewrite(config as Json);
  return { config: next, withdrawn: [...withdrawn].toSorted() };
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
      const remaining = caddyTailnetBackends(await this.activeConfig()).filter((key) => !allowed.has(key));
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

/** Allowed backend keys of a lease document, or none when the lease is missing or expired. */
export function allowedBackends(document: Pick<EdgeLeaseDocument, "lease" | "routes">) {
  if (!document.lease?.valid) return new Set<string>();
  return new Set(document.routes.map((route) => backendKey(route.ip, route.port)));
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
  const denied = backends.filter((key) => !allowed.has(key));
  return { open: denied.length === 0, backends, denied };
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
  private readonly now: () => number;
  private readonly staleMs: number;

  constructor(private readonly options: WatchdogOptions) {
    this.now = options.now ?? (() => performance.now());
    this.staleMs = options.staleMs ?? 5_000;
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

  async tick() {
    await this.refresh();
    const allowed = this.effectiveAllowed();
    const results: WithdrawalResult[] = [];
    for (const adapter of this.options.adapters) {
      const result = await adapter.enforce(allowed);
      results.push(result);
      if (result.withdrawn.length && !result.error) {
        await this.emit({
          event: "withdrawn",
          proxy: adapter.proxy,
          detail: `withdrew ${result.withdrawn.join(", ")}${this.lastPolicyError ? ` (policy unavailable: ${this.lastPolicyError})` : ""}`,
        });
      }
      if (result.error && !result.unreachable) {
        // Withdrawal could not be applied: stale configuration must not keep serving.
        await this.emit({ event: "withdrawal_failed", proxy: adapter.proxy, detail: result.error });
        try {
          await adapter.stop();
          await this.emit({
            event: "proxy_stopped",
            proxy: adapter.proxy,
            detail: `stopped ${adapter.proxy} after a failed withdrawal of ${result.withdrawn.join(", ")}`,
          });
        } catch (error) {
          await this.emit({ event: "stop_failed", proxy: adapter.proxy, detail: (error as Error).message });
        }
      }
    }
    return results;
  }

  private async emit(event: WatchdogEvent) {
    this.options.log?.(`${event.event}${event.proxy ? ` [${event.proxy}]` : ""}: ${event.detail}`);
    await this.options
      .report?.(event)
      .catch((error: Error) => this.options.log?.(`report failed: ${error.message}`));
  }
}
