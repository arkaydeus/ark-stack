// Active withdrawal of tailnet backends from the running edge proxies (docs/design/front-door.md
// §3.2, FD-06). The edge-local watchdog and the `edge.drain` operation both use it.
//
// The policy is an allowlist: a backend is allowed only while the persisted lease is fresh, the
// route is enabled and `ready`, and its pinned identity still matches the latest complete
// observation. Every tailnet backend in the active proxy config that is not on the list is withdrawn.
// If withdrawal cannot be verified, the stop fallback fences protected traffic: stale routes must
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
  /**
   * L4 routes only (`tls`, `tcp`, FD-14): a fingerprint of the route's admission policy (CIDRs,
   * limits, TLS mode, client CA and its revoked serials). It is part of the identity key and so of
   * the HAProxy server name: a policy change makes every running server of the old policy
   * unauthorised, so the watchdog and `edge.drain` fence and drain it in every worker before the
   * restricted generation is reloaded (§3.8.6). Caddy routes never carry one.
   */
  policy?: string;
};

/** The read-only lease and policy document the watchdog polls. */
export type EdgeLeaseDocument = {
  /** The API's clock, so the watchdog can measure the remaining lease without trusting its own. */
  now: string;
  lease: { generation: string; completedAt: string; validUntil: string; valid: boolean } | null;
  /** Allowed routes; always empty when the lease is missing or expired. */
  routes: EdgePolicyRoute[];
  /**
   * Gate revocations (FD-11, §3.9.3) still waiting for their forced reload. A route whose
   * revocation is older than 5 s is already left out of `routes` (fail closed); this list is
   * informational for operators and tests.
   */
  revocations?: Array<{ id: string; routeId: string; createdAt: string; overdue: boolean }>;
};

/** Result of one enforcement pass on one proxy. */
export type WithdrawalResult = {
  proxy: string;
  /** Tailnet backends found in the active config. */
  active: string[];
  /** Backends removed by this pass. */
  withdrawn: string[];
  /** Set when withdrawal could not be applied or verified; the caller must invoke the stop fallback. */
  error?: string;
  /** The proxy could not be inspected at all (it may be stopped or restarting). */
  unreachable?: boolean;
  /**
   * Withdrawn backends that may hold upgraded streams a reload cannot promptly close (Caddy keeps
   * them for the old handler's `stream_close_delay`, FD-09). The adapter stopped the proxy; its
   * launch guard restarts it from the lease-checked configuration.
   */
  stopped?: string[];
};

/**
 * What every proxy adapter provides. `enforce` withdraws tailnet handlers whose route identity
 * key is not in `allowed` and verifies the result; `stop` fences protected traffic. Caddy stops its
 * HTTP app; HAProxy fences tailnet servers and sessions while preserving unrelated HTTP.
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

/**
 * Identity metadata survives Caddyfile adaptation in a native `vars` handler. An L4 route's policy
 * fingerprint (FD-14) is appended as a fifth element; HTTP identities are unchanged.
 */
export function routeIdentityKey(
  route: Pick<EdgePolicyRoute, "id" | "hostname" | "stableId" | "ip" | "port" | "policy">,
) {
  const identity = [route.id, route.hostname, route.stableId, backendKey(route.ip, route.port)];
  if (route.policy) identity.push(route.policy);
  return encodeURIComponent(JSON.stringify(identity));
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
  /** Withdrawn backends whose handler keeps upgraded streams open after a reload. */
  const delayed = new Set<string>();
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
        if (streamCloseDelayed(value)) for (const key of denied) delayed.add(key);
        return structuredClone(WITHDRAWN_HANDLER) as unknown as Json;
      }
      if (keys.length) activeRoutes.add(identity);
    }
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, rewrite(child, hosts, identity)]),
    );
  };
  const next = rewrite(config as Json);
  return {
    config: next,
    withdrawn: [...withdrawn].toSorted(),
    delayed: [...delayed].toSorted(),
    activeRoutes: [...activeRoutes].toSorted(),
  };
}

/** A handler's `stream_close_delay` in milliseconds (Caddy JSON stores nanoseconds or a duration). */
function streamCloseDelayMs(handler: { [key: string]: Json }) {
  const delay = handler.stream_close_delay;
  if (typeof delay === "number") return delay / 1e6;
  if (typeof delay !== "string" || !delay.trim()) return 0;
  let total = 0;
  const units: Record<string, number> = { ns: 1e-6, us: 1e-3, µs: 1e-3, ms: 1, s: 1e3, m: 6e4, h: 3.6e6 };
  for (const match of delay.trim().matchAll(/([0-9.]+)(ns|us|µs|ms|s|m|h)/g))
    total += Number(match[1]) * (units[match[2]!] ?? 0);
  return total;
}

/**
 * Tailnet backends of the given routes whose active handler keeps upgraded streams open longer than
 * `maxMs` after a reload. A gate revocation (FD-11, §3.9.3) on such a route (for example a public
 * route with a long delay that was just switched to SSO) cannot rely on the reload alone: the caller
 * stops Caddy after it, as `edge.apply` does for removed routes.
 */
export function caddyLongLivedStreams(config: unknown, routeIds: ReadonlySet<string>, maxMs: number) {
  const found = new Set<string>();
  const visit = (value: Json, identity: string) => {
    if (Array.isArray(value)) {
      let current = identity;
      for (const child of value) {
        if (child && typeof child === "object" && !Array.isArray(child) && child.handler === "vars")
          current = typeof child.ark_tailnet_route === "string" ? child.ark_tailnet_route : "";
        visit(child, current);
      }
      return;
    }
    if (!value || typeof value !== "object") return;
    if (value.handler === "reverse_proxy" && identity) {
      let id = "";
      try {
        id = String((JSON.parse(decodeURIComponent(identity)) as unknown[])[0] ?? "");
      } catch {
        id = "";
      }
      if (routeIds.has(id) && streamCloseDelayMs(value) > maxMs)
        for (const key of reverseProxyKeys(value)) found.add(key);
    }
    for (const child of Object.values(value)) visit(child, identity);
  };
  visit(config as Json, "");
  return [...found].toSorted();
}

/** A `reverse_proxy` handler whose upgraded streams outlive a reload (`stream_close_delay` > 0). */
function streamCloseDelayed(handler: { [key: string]: Json }) {
  const delay = handler.stream_close_delay;
  if (typeof delay === "number") return delay > 0;
  if (typeof delay === "string")
    return !/^0+(?:\.0+)?(?:ns|us|µs|ms|s|m|h)?$/.test(delay.trim()) && delay.trim() !== "";
  return false;
}

/**
 * Tailnet backends with requests in flight, from Caddy's `GET /reverse_proxy/upstreams`. An upgraded
 * stream (WebSocket) counts as in flight for its whole life. This is diagnostic only: an idle
 * snapshot cannot rule out an upgrade arriving before admission is fenced.
 */
export function caddyBusyBackends(upstreams: unknown) {
  const busy = new Set<string>();
  if (!Array.isArray(upstreams)) throw new Error("Caddy /reverse_proxy/upstreams did not return a list.");
  for (const item of upstreams) {
    if (!item || typeof item !== "object") continue;
    const { address, num_requests: requests } = item as { address?: unknown; num_requests?: unknown };
    const key = tailnetDialKey(address);
    if (key && typeof requests === "number" && requests > 0) busy.add(key);
  }
  return busy;
}

/** The backend key inside a route identity key (`routeIdentityKey`), or null. */
export function identityBackend(identity: string) {
  try {
    const value = JSON.parse(decodeURIComponent(identity)) as unknown;
    return Array.isArray(value) && typeof value[3] === "string" ? value[3] : null;
  } catch {
    return null;
  }
}

/** How long after a deliberate stop an unreachable Caddy is its launch guard restarting it. */
export const CADDY_RESTART_GRACE_MS = 60_000;

/**
 * Written to the rendered edge directory (wall-clock ms) by every deliberate Caddy stream stop.
 * All adapters read it so a restart initiated by another process is not a failure.
 */
export const CADDY_STOP_MARKER = "caddy-stopped-at";

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

/** Stable object ordering for exact adapted-config comparisons. */
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object")
    return `{${Object.entries(value)
      // Caddy's HTTP adapter appends its default Caddyfile hide even if already explicit.
      // File-server hides are an unordered set; duplicate entries change no serving behaviour.
      .map(
        ([key, child]) =>
          [
            key,
            key === "hide" &&
            "handler" in value &&
            value.handler === "file_server" &&
            Array.isArray(child) &&
            child.every((item) => typeof item === "string")
              ? [...new Set(child)].toSorted()
              : child,
          ] as const,
      )
      .toSorted(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`)
      .join(",")}}`;
  return JSON.stringify(value);
}

function caddyGeneration(value: unknown): string | null {
  if (!value || typeof value !== "object") return null;
  if ("ark_edge_generation" in value && typeof value.ark_edge_generation === "string")
    return value.ark_edge_generation;
  for (const child of Object.values(value)) {
    const found = caddyGeneration(child);
    if (found) return found;
  }
  return null;
}

type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

/** A reachable admin API returned an unusable inspection; restart grace cannot excuse this. */
class CaddyInspectionError extends Error {}

/**
 * Caddy adapter over the admin API (`edge-admin:2019`, reachable only from edge-control). Withdrawal
 * is a `/load` of the active config with the denied handlers replaced, sent with
 * `Cache-Control: must-revalidate`; the rendered `grace_period` bounds in-flight requests on the old
 * server. FD-09 routes render `stream_close_delay 5m` so WebSockets survive an ordinary edge.apply,
 * and Caddy applies the *old* handler's delay on reload: a withdrawn handler's upgraded streams would
 * stay open for five minutes. Whenever a withdrawn handler has a delay, the adapter stops Caddy after the
 * verified reload. That closes every stream at once (fail closed; other routes reconnect after the
 * restart); the launch guard restarts it from the lease-checked configuration. `POST /stop` is also
 * the fallback when withdrawal fails.
 */
export class CaddyWithdrawalAdapter implements EdgeWithdrawalAdapter {
  readonly proxy = "caddy";

  constructor(
    private readonly adminUrl: string,
    private readonly fetcher: Fetch = fetch,
    private readonly timeoutMs = 3_000,
    private readonly options: {
      /** Monotonic clock for this adapter's own stops. */
      now?: () => number;
      /**
       * Wall-clock time (ms) of the last deliberate stream stop by any adapter, read from
       * `CADDY_STOP_MARKER` in the rendered edge directory; null when there is none.
       */
      appliedStopAt?: () => Promise<number | null>;
      recordStop?: () => Promise<void>;
      pendingStreams?: () => Promise<string[]>;
      markPendingStreams?: (keys: string[]) => Promise<void>;
      clearPendingStreams?: () => Promise<void>;
      /** Read the current authoritative files, never a cached pre-stop snapshot. */
      configFiles?: () => Promise<{ full: string; closed: string }>;
    } = {},
  ) {}

  /** Set by a deliberate stop; until the grace ends, an unreachable Caddy is restarting, not failing. */
  private stoppedAt: number | null = null;
  private pendingStreams: string[] = [];
  private configEtag: string | null = null;

  private clock() {
    return (this.options.now ?? (() => performance.now()))();
  }

  private async restarting() {
    if (this.stoppedAt !== null && this.clock() - this.stoppedAt < CADDY_RESTART_GRACE_MS) return true;
    const applied = await this.options.appliedStopAt?.().catch(() => null);
    return typeof applied === "number" && Date.now() - applied < CADDY_RESTART_GRACE_MS;
  }

  private request(path: string, init: RequestInit = {}) {
    return this.fetcher(`${this.adminUrl.replace(/\/$/, "")}${path}`, {
      ...init,
      signal: AbortSignal.timeout(this.timeoutMs),
    });
  }

  private async activeConfig() {
    const response = await this.request("/config/");
    if (!response.ok) throw new CaddyInspectionError(`GET /config/ returned ${response.status}`);
    this.configEtag = response.headers.get("etag");
    try {
      return (await response.json()) as unknown;
    } catch {
      throw new CaddyInspectionError("GET /config/ returned invalid JSON");
    }
  }

  async activeRoutes() {
    return caddyTailnetRouteKeys(await this.activeConfig());
  }

  /** Tailnet backends Caddy dials right now. */
  async activeBackends() {
    return caddyTailnetBackends(await this.activeConfig());
  }

  /** Tailnet backends with requests or upgraded streams in flight. */
  async busyBackends() {
    const response = await this.request("/reverse_proxy/upstreams");
    if (!response.ok) throw new Error(`GET /reverse_proxy/upstreams returned ${response.status}`);
    return caddyBusyBackends(await response.json());
  }

  /**
   * Backends whose upgraded streams a reload to a config serving only `next` route identities would
   * leave open (all removed handlers with `stream_close_delay`, including currently idle ones).
   * `edge.apply` reads this before its `/load`, since it can remove a route before the watchdog
   * or `edge.drain` sees it.
   */
  async lingeringStreams(
    next: ReadonlySet<string>,
    revoked: { routeIds: ReadonlySet<string>; maxMs: number } | null = null,
  ) {
    // Admission is still open: even an idle handler can accept an upgrade before /load.
    const config = await this.activeConfig();
    const delayed = withdrawCaddyBackends(config, next).delayed;
    if (!revoked?.routeIds.size) return delayed;
    return [
      ...new Set([...delayed, ...caddyLongLivedStreams(config, revoked.routeIds, revoked.maxMs)]),
    ].toSorted();
  }

  /** Persist before changing configuration so a failed stop cannot lose the removed handler. */
  async markPendingStreams(keys: string[]) {
    this.pendingStreams = keys;
    await this.options.markPendingStreams?.(keys);
  }

  async stopForStreams() {
    await this.options.recordStop?.();
    await this.stop();
    this.stoppedAt = this.clock();
    this.pendingStreams = [];
    await this.options.clearPendingStreams?.();
  }

  /** Restore only the current generation's exact closed configuration, with an atomic ETag guard. */
  private async restoreCurrent(config: unknown, allowed: ReadonlySet<string>) {
    if (!this.options.configFiles || !this.configEtag || caddyTailnetRouteKeys(config).length) return config;
    const generation = caddyGeneration(config);
    if (!generation) return config;
    const etag = this.configEtag;
    const files = await this.options.configFiles();
    if (files.full === files.closed) return config;
    const adapt = async (body: string) => {
      const response = await this.request("/adapt", {
        method: "POST",
        headers: { "content-type": "text/caddyfile" },
        body,
      });
      if (!response.ok) throw new Error(`POST /adapt returned ${response.status}`);
      const { result } = (await response.json()) as { result: unknown };
      return result;
    };
    const closed = await adapt(files.closed);
    if (caddyGeneration(closed) !== generation || canonicalJson(closed) !== canonicalJson(config))
      return config;
    const full = await adapt(files.full);
    if (caddyGeneration(full) !== generation) return config;
    const next = withdrawCaddyBackends(full, allowed).config;
    if (canonicalJson(next) === canonicalJson(config)) return config;
    const loaded = await this.request("/config/", {
      method: "PATCH",
      headers: { "content-type": "application/json", "if-match": etag, "cache-control": "must-revalidate" },
      body: JSON.stringify(next),
    });
    if (!loaded.ok && loaded.status !== 412) throw new Error(`PATCH /config/ returned ${loaded.status}`);
    return this.activeConfig();
  }

  async enforce(allowed: ReadonlySet<string>): Promise<WithdrawalResult> {
    let pending: string[];
    try {
      pending = [...new Set([...this.pendingStreams, ...((await this.options.pendingStreams?.()) ?? [])])];
    } catch (error) {
      return {
        proxy: this.proxy,
        active: [],
        withdrawn: [],
        error: `Cannot inspect pending Caddy stops: ${(error as Error).message}`,
      };
    }
    if (pending.length) {
      try {
        await this.stopForStreams();
        return { proxy: this.proxy, active: [], withdrawn: [], stopped: pending, unreachable: true };
      } catch (error) {
        // Another adapter may have completed the same intents and stopped this process first.
        const remaining = await this.options.pendingStreams?.().catch(() => null);
        if (remaining?.length === 0 && (await this.restarting())) {
          this.pendingStreams = [];
          return { proxy: this.proxy, active: [], withdrawn: [], unreachable: true };
        }
        return {
          proxy: this.proxy,
          active: [],
          withdrawn: [],
          error: `Pending stream stop failed: ${(error as Error).message}`,
        };
      }
    }
    let config: unknown;
    try {
      config = await this.activeConfig();
    } catch (error) {
      // After a deliberate stop the launch guard restarts Caddy from lease-checked files; an
      // unreachable Caddy is never counted as verified enforcement (`/v1/supervise`).
      const restarting = !(error instanceof CaddyInspectionError) && (await this.restarting());
      return {
        proxy: this.proxy,
        active: [],
        withdrawn: [],
        unreachable: true,
        ...(restarting ? {} : { error: `Caddy admin API unreachable: ${(error as Error).message}` }),
      };
    }
    this.stoppedAt = null;
    try {
      config = await this.restoreCurrent(config, allowed);
    } catch (error) {
      return {
        proxy: this.proxy,
        active: [],
        withdrawn: [],
        error: `Restore failed: ${(error as Error).message}`,
      };
    }
    const active = caddyTailnetBackends(config);
    const { config: next, withdrawn, delayed } = withdrawCaddyBackends(config, allowed);
    if (!withdrawn.length) return { proxy: this.proxy, active, withdrawn };
    // No idle census can rule out a late upgrade while admission remains open.
    const lingering = delayed;
    try {
      if (lingering.length) await this.markPendingStreams(lingering);
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
    if (lingering.length) {
      try {
        await this.stopForStreams();
      } catch (error) {
        return {
          proxy: this.proxy,
          active,
          withdrawn,
          error: `withdrawn, but upgraded streams to ${lingering.join(", ")} stay open: stop failed: ${(error as Error).message}`,
        };
      }
      return { proxy: this.proxy, active, withdrawn, stopped: lingering };
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
          detail: `withdrew ${backendSummary(result.withdrawn)} in ${took} ms${result.stopped?.length ? `; stopped ${adapter.proxy} to close upgraded streams to ${backendSummary(result.stopped)} (the launch guard restarts it)` : ""}${this.lastPolicyError ? ` (policy unavailable: ${this.lastPolicyError})` : ""}`,
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
