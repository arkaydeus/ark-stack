import { describe, expect, test } from "bun:test";

import {
  CADDY_RESTART_GRACE_MS,
  CaddyWithdrawalAdapter,
  EdgeWatchdog,
  WITHDRAWN_HANDLER,
  caddyTailnetBackends,
  caddyfileTailnetBackends,
  launchDecision,
  routeIdentityKey,
  renderCaddyfile,
  tailnetDialKey,
  withdrawCaddyBackends,
  type EdgeLeaseDocument,
  type EdgeWithdrawalAdapter,
  type WatchdogEvent,
  type WithdrawalResult,
} from "./index.ts";

const routes = [
  { id: "rt_0", kind: "http", hostname: "www.example.com", stableId: "n", ip: "100.101.102.103", port: 3000 },
  {
    id: "rt_1",
    kind: "http",
    hostname: "v6.example.com",
    stableId: "n",
    ip: "fd7a:115c:a1e0::103",
    port: 8080,
  },
];
const allowed = (...indices: number[]) => new Set(indices.map((index) => routeIdentityKey(routes[index]!)));

const sharedBackendHandler = (route: (typeof routes)[number]) => ({
  match: [{ host: [route.hostname] }],
  handle: [
    {
      handler: "subroute",
      routes: [
        {
          handle: [
            { handler: "vars", ark_tailnet_route: routeIdentityKey(route) },
            { handler: "reverse_proxy", upstreams: [{ dial: `${route.ip}:${route.port}` }] },
          ],
        },
      ],
    },
  ],
});

// The shape `caddy adapt` gives a Caddyfile with one admin site and two tailnet routes.
const config = () => ({
  admin: { listen: "edge-admin:2019" },
  apps: {
    http: {
      servers: {
        srv0: {
          listen: [":443"],
          routes: [
            {
              match: [{ host: ["admin.example.com"] }],
              handle: [
                {
                  handler: "subroute",
                  routes: [{ handle: [{ handler: "reverse_proxy", upstreams: [{ dial: "api:3000" }] }] }],
                },
              ],
            },
            {
              match: [{ host: ["www.example.com"] }],
              handle: [
                {
                  handler: "subroute",
                  routes: [
                    {
                      handle: [
                        { handler: "vars", ark_tailnet_route: routeIdentityKey(routes[0]!) },
                        { handler: "reverse_proxy", upstreams: [{ dial: "100.101.102.103:3000" }] },
                      ],
                    },
                  ],
                },
              ],
            },
            {
              match: [{ host: ["v6.example.com"] }],
              handle: [
                { handler: "vars", ark_tailnet_route: routeIdentityKey(routes[1]!) },
                { handler: "reverse_proxy", upstreams: [{ dial: "[fd7a:115c:a1e0:0::103]:8080" }] },
              ],
            },
          ],
        },
      },
    },
  },
});

describe("Caddy config inspection and withdrawal", () => {
  test("finds only tailnet backends, canonically", () => {
    expect(caddyTailnetBackends(config())).toEqual(["100.101.102.103:3000", "[fd7a:115c:a1e0::103]:8080"]);
    expect(tailnetDialKey("tcp/100.64.0.5:22")).toBe("100.64.0.5:22");
    for (const dial of ["api:3000", "172.17.0.2:80", "127.0.0.1:2019", "unix//run/x.sock", 3000]) {
      expect(tailnetDialKey(dial)).toBeNull();
    }
  });

  test("replaces denied handlers with a fixed 503 and keeps everything else", () => {
    const { config: next, withdrawn } = withdrawCaddyBackends(config(), allowed(1));
    expect(withdrawn).toEqual(["100.101.102.103:3000"]);
    expect(caddyTailnetBackends(next)).toEqual(["[fd7a:115c:a1e0::103]:8080"]);
    expect(JSON.stringify(next)).toContain(JSON.stringify(WITHDRAWN_HANDLER));
    expect(JSON.stringify(next)).toContain('"dial":"api:3000"');
    expect(caddyTailnetBackends(next)).not.toContain("100.101.102.103:3000");
    // Nothing to do when everything is allowed.
    const all = allowed(0, 1);
    expect(withdrawCaddyBackends(config(), all).withdrawn).toEqual([]);
  });

  test("the launch decision is open only when every rendered tailnet backend is allowed", () => {
    const caddyfile = `# ark-tailnet-route rt_a 100.101.102.103:3000
www.example.com {
  vars ark_tailnet_route ${routeIdentityKey(routes[0]!)}
  reverse_proxy 100.101.102.103:3000
}
v6.example.com {
  vars ark_tailnet_route ${routeIdentityKey(routes[1]!)}
  reverse_proxy [fd7a:115c:a1e0::103]:8080
}
admin.example.com {
  reverse_proxy api:3000
}`;
    expect(caddyfileTailnetBackends(caddyfile)).toEqual([
      "100.101.102.103:3000",
      "[fd7a:115c:a1e0::103]:8080",
    ]);
    expect(launchDecision(caddyfile, new Set()).open).toBe(false);
    expect(launchDecision(caddyfile, allowed(0)).denied).toEqual(["[fd7a:115c:a1e0::103]:8080"]);
    expect(launchDecision(caddyfile, allowed(0, 1)).open).toBe(true);
    expect(launchDecision("admin.example.com {\n  reverse_proxy api:3000\n}\n", new Set()).open).toBe(true);
  });
});

/** A fake Caddy admin API: GET /config/, conditional PATCH /config/, POST /stop. */
function fakeCaddy(options: { failLoad?: boolean; initial?: unknown } = {}) {
  let active: unknown = options.initial ?? config();
  const calls: string[] = [];
  let stopped = false;
  const fetcher = async (url: string, init: RequestInit = {}) => {
    const path = new URL(url).pathname;
    calls.push(`${init.method ?? "GET"} ${path}`);
    if (stopped) throw new Error("connection refused");
    if (path === "/adapt") return Response.json({ result: JSON.parse(String(init.body)) });
    if (path === "/config/" && init.method === "PATCH") {
      if (new Headers(init.headers).get("if-match") !== JSON.stringify(active))
        return new Response("configuration changed", { status: 412 });
      expect(new Headers(init.headers).get("cache-control")).toBe("must-revalidate");
      if (options.failLoad) return new Response("load failed", { status: 500 });
      active = JSON.parse(String(init.body));
      return new Response("");
    }
    if (path === "/config/") return Response.json(active, { headers: { etag: JSON.stringify(active) } });
    if (path === "/load") {
      expect(new Headers(init.headers).get("cache-control")).toBe("must-revalidate");
      if (options.failLoad) return new Response("load failed", { status: 500 });
      active = JSON.parse(String(init.body));
      return new Response("");
    }
    if (path === "/stop") {
      stopped = true;
      return new Response("");
    }
    return new Response("not found", { status: 404 });
  };
  return {
    fetcher,
    calls,
    active: () => active,
    stopped: () => stopped,
    /** The launch guard's restart, from the given config (the closed variant by default). */
    restart: (from: unknown) => {
      active = from;
      stopped = false;
    },
  };
}

/** An admin API that refuses every connection (Caddy stopped or restarting). */
async function down(): Promise<Response> {
  throw new Error("ECONNREFUSED");
}

/** The FD-09 shape: the route's reverse_proxy keeps upgraded streams for 5 minutes after a reload. */
const delayedConfig = () => {
  const value = config();
  const v6 = value.apps.http.servers.srv0.routes[2]!.handle[1] as Record<string, unknown>;
  const www = (value.apps.http.servers.srv0.routes[1]!.handle[0] as { routes: Array<{ handle: unknown[] }> })
    .routes[0]!.handle[1] as Record<string, unknown>;
  www.stream_close_delay = 300_000_000_000;
  v6.stream_close_delay = 300_000_000_000;
  return value;
};

describe("withdrawal with stream_close_delay (FD-09)", () => {
  test("reports withdrawn handlers whose streams outlive a reload", () => {
    expect(withdrawCaddyBackends(delayedConfig(), allowed(1)).delayed).toEqual(["100.101.102.103:3000"]);
    expect(withdrawCaddyBackends(config(), allowed(1)).delayed).toEqual([]);
  });

  test("with scoped HAProxy control, delayed handlers are withdrawn by a Caddy reload", async () => {
    const caddy = fakeCaddy({ initial: delayedConfig() });
    const adapter = new CaddyWithdrawalAdapter("http://edge-admin:2019", caddy.fetcher, 3_000, {
      scopedHttp: async () => true,
    });
    expect(await adapter.enforce(allowed(1))).toEqual({
      proxy: "caddy",
      active: ["100.101.102.103:3000", "[fd7a:115c:a1e0::103]:8080"],
      withdrawn: ["100.101.102.103:3000"],
    });
    expect(caddy.calls).toEqual(["GET /config/", "PATCH /config/", "GET /config/"]);
  });

  test("a Caddy withdrawal cannot replace a concurrent edge apply", async () => {
    const caddy = fakeCaddy({ initial: delayedConfig() });
    const updated = { ...delayedConfig(), marker: { ark_edge_generation: "new-apply" } };
    const adapter = new CaddyWithdrawalAdapter(
      "http://edge-admin:2019",
      async (url, init) => {
        if (init?.method === "PATCH") caddy.restart(updated);
        return caddy.fetcher(url, init);
      },
      3_000,
      { scopedHttp: async () => true },
    );
    const result = await adapter.enforce(allowed(1));
    expect(result.error).toBeUndefined();
    expect(result.withdrawn).toEqual([]);
    expect(caddy.active()).toEqual(updated);
    expect(caddy.stopped()).toBe(false);
  });

  test("lease expiry without live HAProxy control stops Caddy", async () => {
    const caddy = fakeCaddy({ initial: delayedConfig() });
    const adapter = new CaddyWithdrawalAdapter("http://edge-admin:2019", caddy.fetcher, 3_000, {
      scopedHttp: async () => {
        throw new Error("master unavailable");
      },
    });
    expect((await adapter.enforce(new Set())).stopped).toHaveLength(2);
    expect(caddy.calls).toEqual(["GET /config/", "POST /stop"]);
  });

  test("an unreachable HAProxy master cannot protect a partial withdrawal on legacy HTTP", async () => {
    const caddy = fakeCaddy({ initial: delayedConfig() });
    let stopRecorded = false;
    const adapter = new CaddyWithdrawalAdapter("http://edge-admin:2019", caddy.fetcher, 3_000, {
      scopedHttp: async () => {
        throw new Error("master unavailable");
      },
      recordStop: async () => {
        stopRecorded = true;
      },
    });
    expect((await adapter.enforce(allowed(1))).stopped).toEqual(["100.101.102.103:3000"]);
    expect(stopRecorded).toBe(true);
    expect(caddy.calls).toEqual(["GET /config/", "POST /stop"]);
  });

  test("after a deliberate stop, an unreachable Caddy is restarting, not a failure, for a bounded time", async () => {
    let clock = 0;
    const caddy = fakeCaddy({
      initial: delayedConfig(),
    });
    const adapter = new CaddyWithdrawalAdapter("http://edge-admin:2019", caddy.fetcher, 3_000, {
      now: () => clock,
    });
    await adapter.enforce(allowed(1));
    clock += 10_000;
    const restarting = await adapter.enforce(allowed(1));
    expect(restarting).toMatchObject({ unreachable: true });
    expect(restarting.error).toBeUndefined();
    clock += CADDY_RESTART_GRACE_MS;
    expect((await adapter.enforce(allowed(1))).error).toMatch(/unreachable/);
  });

  const closed = {
    apps: {
      http: {
        servers: {
          srv0: { routes: [{ handle: [{ handler: "vars", ark_edge_generation: "generation-old" }] }] },
        },
      },
    },
  };
  const full = () => ({
    ...delayedConfig(),
    generationMarker: { handler: "vars", ark_edge_generation: "generation-old" },
  });
  const configFiles = async () => ({ full: JSON.stringify(full()), closed: JSON.stringify(closed) });

  test("a fresh adapter restores only the current generation's exact closed config, lease-checked", async () => {
    const caddy = fakeCaddy({ initial: full() });
    await new CaddyWithdrawalAdapter("http://edge-admin:2019", caddy.fetcher).enforce(allowed(1));
    caddy.restart(closed);
    const adapter = new CaddyWithdrawalAdapter("http://edge-admin:2019", caddy.fetcher, 3000, {
      configFiles,
    });
    const result = await adapter.enforce(allowed(1));
    expect(result.error).toBeUndefined();
    expect(caddyTailnetBackends(caddy.active())).toEqual(["[fd7a:115c:a1e0::103]:8080"]);
    expect(JSON.stringify(caddy.active())).toContain(JSON.stringify(WITHDRAWN_HANDLER));
  });

  test("CLI and HTTP adaptation may differ only by duplicate file-server hides", async () => {
    const diskClosed = {
      ...closed,
      files: { handler: "file_server", hide: ["/etc/caddy/ark/Caddyfile.closed", "./Caddyfile"] },
    };
    const caddy = fakeCaddy({ initial: diskClosed });
    const files = async () => ({ full: JSON.stringify(full()), closed: JSON.stringify(diskClosed) });
    const fetcher = async (url: string, init?: RequestInit) => {
      if (url.endsWith("/adapt") && init?.body === JSON.stringify(diskClosed)) {
        return Response.json({
          result: {
            ...diskClosed,
            files: { ...diskClosed.files, hide: [...diskClosed.files.hide, "./Caddyfile"] },
          },
        });
      }
      return caddy.fetcher(url, init);
    };
    const result = await new CaddyWithdrawalAdapter("http://edge-admin:2019", fetcher, 3000, {
      configFiles: files,
    }).enforce(allowed(1));
    expect(result.error).toBeUndefined();
    expect(caddyTailnetBackends(caddy.active())).toEqual(["[fd7a:115c:a1e0::103]:8080"]);
  });

  test("a newer zero-tailnet apply cannot resurrect public admin or superseded route settings", async () => {
    const caddy = fakeCaddy({ initial: full() });
    const adapter = new CaddyWithdrawalAdapter("http://edge-admin:2019", caddy.fetcher, 3000, {
      configFiles,
    });
    await adapter.enforce(allowed(1));
    const newer = { apps: {}, marker: { handler: "vars", ark_edge_generation: "generation-new" } };
    caddy.restart(newer);
    await adapter.enforce(new Set());
    expect(caddy.active()).toEqual(newer);
    expect(caddy.calls).not.toContain("PATCH /config/");
  });

  test("restore rejects a route-free config that is not the exact generated closed config", async () => {
    const newer = { ...closed, adminChanged: true };
    const caddy = fakeCaddy({ initial: newer });
    await new CaddyWithdrawalAdapter("http://edge-admin:2019", caddy.fetcher, 3000, { configFiles }).enforce(
      allowed(1),
    );
    expect(caddy.active()).toEqual(newer);
    expect(caddy.calls).not.toContain("PATCH /config/");
  });

  test("an apply racing restoration wins the conditional PATCH", async () => {
    const caddy = fakeCaddy({ initial: closed });
    const newer = { apps: {}, marker: { handler: "vars", ark_edge_generation: "generation-new" } };
    const fetcher = async (url: string, init?: RequestInit) => {
      if (init?.method === "PATCH") {
        caddy.restart(newer);
        return new Response(null, { status: 412 });
      }
      return caddy.fetcher(url, init);
    };
    await new CaddyWithdrawalAdapter("http://edge-admin:2019", fetcher, 3000, { configFiles }).enforce(
      allowed(1),
    );
    expect(caddy.active()).toEqual(newer);
  });

  test("a restore is re-checked against the lease at restore time", async () => {
    const caddy = fakeCaddy({ initial: closed });
    await new CaddyWithdrawalAdapter("http://edge-admin:2019", caddy.fetcher, 3000, { configFiles }).enforce(
      new Set(),
    );
    expect(caddyTailnetBackends(caddy.active())).toEqual([]);
  });

  test("a recorded fail-closed stop is a restart, not a failure", async () => {
    const marked = new CaddyWithdrawalAdapter("http://edge-admin:2019", down, 3_000, {
      appliedStopAt: async () => Date.now() - 5_000,
    });
    expect(await marked.enforce(new Set())).toEqual({
      proxy: "caddy",
      active: [],
      withdrawn: [],
      unreachable: true,
    });
    const stale = new CaddyWithdrawalAdapter("http://edge-admin:2019", down, 3_000, {
      appliedStopAt: async () => Date.now() - CADDY_RESTART_GRACE_MS - 1,
    });
    expect((await stale.enforce(new Set())).error).toMatch(/unreachable/);
  });

  test("a recent restart marker cannot excuse a reachable admin API's failed inspection", async () => {
    for (const response of [new Response(null, { status: 500 }), new Response("invalid JSON")]) {
      const adapter = new CaddyWithdrawalAdapter("http://edge-admin:2019", async () => response, 3000, {
        appliedStopAt: async () => Date.now(),
      });
      expect((await adapter.enforce(new Set())).error).toContain("GET /config/");
    }
  });

  test("the watchdog reports a stream stop as a withdrawal, not a failure", async () => {
    const caddy = fakeCaddy({
      initial: delayedConfig(),
    });
    const events: WatchdogEvent[] = [];
    let clock = 0;
    const watchdog = new EdgeWatchdog({
      fetchLease: async () => lease(clock, 60_000, [{ ip: "fd7a:115c:a1e0::103", port: 8080 }]),
      adapters: [
        new CaddyWithdrawalAdapter("http://edge-admin:2019", caddy.fetcher, 3_000, { now: () => clock }),
      ],
      report: async (event) => {
        events.push(event);
      },
      now: () => clock,
    });
    await watchdog.tick();
    clock += 1_000;
    await watchdog.tick();
    expect(events.map((event) => event.event)).toEqual(["withdrawn"]);
    expect(events[0]!.detail).toMatch(/stopped caddy to close upgraded streams/);
  });
});

describe("CaddyWithdrawalAdapter", () => {
  test("loads the withdrawn config with must-revalidate and verifies it", async () => {
    const caddy = fakeCaddy();
    const adapter = new CaddyWithdrawalAdapter("http://edge-admin:2019", caddy.fetcher);
    const result = await adapter.enforce(allowed(1));
    expect(result).toMatchObject({ withdrawn: ["100.101.102.103:3000"] });
    expect(result.error).toBeUndefined();
    expect(caddyTailnetBackends(caddy.active())).toEqual(["[fd7a:115c:a1e0::103]:8080"]);
    expect(caddy.calls).toEqual(["GET /config/", "PATCH /config/", "GET /config/"]);
    // Idempotent: a second pass changes nothing.
    expect((await adapter.enforce(allowed(1))).withdrawn).toEqual([]);
  });

  test("reports a failed load so the caller stops Caddy", async () => {
    const caddy = fakeCaddy({ failLoad: true });
    const result = await new CaddyWithdrawalAdapter("http://edge-admin:2019", caddy.fetcher).enforce(
      new Set(),
    );
    expect(result.error).toMatch(/withdrawal failed: PATCH \/config\/ returned 500/);
    expect(result.unreachable).toBeUndefined();
  });

  test("an unreachable admin API is reported as unreachable", async () => {
    const adapter = new CaddyWithdrawalAdapter("http://edge-admin:2019", async () => {
      throw new Error("ECONNREFUSED");
    });
    expect(await adapter.enforce(new Set())).toMatchObject({ unreachable: true });
  });
});

const lease = (now: number, validForMs: number, backendRoutes = [{ ip: "100.101.102.103", port: 3000 }]) =>
  ({
    now: new Date(now).toISOString(),
    lease: {
      generation: "gen_1",
      completedAt: new Date(now).toISOString(),
      validUntil: new Date(now + validForMs).toISOString(),
      valid: validForMs > 0,
    },
    routes: backendRoutes.map((route, index) => ({
      ...routes[index]!,
      id: `rt_${index}`,
      kind: "http",
      stableId: "n",
      ...route,
    })),
  }) satisfies EdgeLeaseDocument;

describe("EdgeWatchdog", () => {
  function harness(options: { failLoad?: boolean } = {}) {
    let clock = 0;
    let document: EdgeLeaseDocument | Error = lease(Date.parse("2026-11-16T12:00:00Z"), 6_000);
    const caddy = fakeCaddy(options);
    const events: WatchdogEvent[] = [];
    const watchdog = new EdgeWatchdog({
      fetchLease: async () => {
        if (document instanceof Error) throw document;
        return document;
      },
      adapters: [new CaddyWithdrawalAdapter("http://edge-admin:2019", caddy.fetcher)],
      report: async (event) => {
        events.push(event);
      },
      now: () => clock,
      staleMs: 5_000,
    });
    return {
      watchdog,
      caddy,
      events,
      advance: (ms: number) => (clock += ms),
      setLease: (next: EdgeLeaseDocument | Error) => (document = next),
    };
  }

  test("withdraws backends outside the lease immediately and keeps allowed ones", async () => {
    const h = harness();
    await h.watchdog.tick();
    expect(caddyTailnetBackends(h.caddy.active())).toEqual(["100.101.102.103:3000"]);
    expect(h.events.map((event) => event.event)).toEqual(["withdrawn"]);
  });

  test("withdraws everything when the lease runs out, even if the API keeps answering", async () => {
    const h = harness();
    const base = Date.parse("2026-11-16T12:00:00Z");
    // Observation stopped: the API's clock moves on, the lease's validUntil does not.
    const at = (elapsed: number) => {
      const document = lease(base, 6_000);
      return {
        ...document,
        now: new Date(base + elapsed).toISOString(),
        lease: { ...document.lease, valid: elapsed < 6_000 },
      };
    };
    h.setLease(at(0));
    await h.watchdog.tick();
    h.advance(5_999);
    h.setLease(at(5_999));
    await h.watchdog.tick();
    expect(caddyTailnetBackends(h.caddy.active())).toEqual(["100.101.102.103:3000"]);
    expect(h.watchdog.state().leaseRemainingMs).toBe(1);
    h.advance(1);
    h.setLease(at(6_000));
    await h.watchdog.tick();
    expect(caddyTailnetBackends(h.caddy.active())).toEqual([]);
    expect(h.watchdog.state().leaseValid).toBe(false);
  });

  test("counts the remaining lease down locally between reads", async () => {
    const h = harness();
    await h.watchdog.tick();
    h.setLease(new Error("API restarting"));
    h.advance(4_000);
    await h.watchdog.tick();
    expect(caddyTailnetBackends(h.caddy.active())).toEqual(["100.101.102.103:3000"]);
    expect(h.watchdog.state().leaseRemainingMs).toBe(2_000);
  });

  test("withdraws everything when the policy cannot be read for longer than the stale limit", async () => {
    const h = harness();
    h.setLease(lease(Date.parse("2026-11-16T12:00:00Z"), 300_000));
    await h.watchdog.tick();
    h.setLease(new Error("lease endpoint returned 502"));
    h.advance(5_000);
    await h.watchdog.tick();
    expect(caddyTailnetBackends(h.caddy.active())).toEqual(["100.101.102.103:3000"]);
    h.advance(1);
    await h.watchdog.tick();
    expect(caddyTailnetBackends(h.caddy.active())).toEqual([]);
  });

  test("starts closed: nothing is allowed before the first lease is read", async () => {
    const h = harness();
    h.setLease(new Error("unreachable"));
    expect(h.watchdog.effectiveAllowed().size).toBe(0);
    await h.watchdog.tick();
    expect(caddyTailnetBackends(h.caddy.active())).toEqual([]);
  });

  test("an expired lease document allows nothing", async () => {
    const h = harness();
    h.setLease(lease(Date.parse("2026-11-16T12:00:00Z"), 0));
    await h.watchdog.tick();
    expect(caddyTailnetBackends(h.caddy.active())).toEqual([]);
  });

  test("a route made live after the last policy read is not withdrawn on that stale policy", async () => {
    const h = harness();
    const base = Date.parse("2026-11-16T12:00:00Z");
    // The cached policy predates the route; edge.apply then loads it, and the API now allows it.
    h.setLease(lease(base, 6_000, []));
    await h.watchdog.refresh();
    h.setLease(
      lease(base, 6_000, [
        { ip: "100.101.102.103", port: 3000 },
        { ip: "fd7a:115c:a1e0::103", port: 8080 },
      ]),
    );
    await h.watchdog.tick(300);
    expect(caddyTailnetBackends(h.caddy.active())).toEqual([
      "100.101.102.103:3000",
      "[fd7a:115c:a1e0::103]:8080",
    ]);
    expect(h.events).toEqual([]);
  });

  test("a hanging lease read does not delay enforcement past the refresh wait", async () => {
    let clock = 0;
    const caddy = fakeCaddy();
    let calls = 0;
    const watchdog = new EdgeWatchdog({
      fetchLease: () => {
        calls++;
        return calls === 1
          ? Promise.resolve(lease(Date.parse("2026-11-16T12:00:00Z"), 1_000))
          : new Promise<never>(() => undefined);
      },
      adapters: [new CaddyWithdrawalAdapter("http://edge-admin:2019", caddy.fetcher)],
      now: () => clock,
    });
    await watchdog.tick(20);
    expect(caddyTailnetBackends(caddy.active())).toEqual(["100.101.102.103:3000"]);
    clock += 1_000;
    const started = performance.now();
    await watchdog.tick(20);
    expect(performance.now() - started).toBeLessThan(500);
    expect(caddyTailnetBackends(caddy.active())).toEqual([]);
  });

  test("an older lease answer arriving late does not replace a newer one", async () => {
    let clock = 0;
    const base = Date.parse("2026-11-16T12:00:00Z");
    const pending: { release?: (value: EdgeLeaseDocument) => void } = {};
    const answers: Array<() => Promise<EdgeLeaseDocument>> = [
      () => new Promise<EdgeLeaseDocument>((resolve) => (pending.release = resolve)),
      async () => lease(base, 0),
    ];
    const watchdog = new EdgeWatchdog({
      fetchLease: () => answers.shift()!(),
      adapters: [],
      now: () => clock,
    });
    const slow = watchdog.refresh();
    clock += 10;
    await watchdog.refresh();
    pending.release?.(lease(base, 60_000));
    await slow;
    expect(watchdog.effectiveAllowed().size).toBe(0);
  });

  test("an overlapping lease read cannot roll back an observed gate recovery", async () => {
    let clock = 0;
    const base = Date.parse("2026-11-16T12:00:00Z");
    const first = Promise.withResolvers<EdgeLeaseDocument>();
    const second = Promise.withResolvers<EdgeLeaseDocument>();
    const answers = [first.promise, second.promise];
    const watchdog = new EdgeWatchdog({ fetchLease: () => answers.shift()!, adapters: [], now: () => clock });
    const recovered = watchdog.refresh();
    clock += 10;
    const stale = watchdog.refresh();
    // The second request reached the API before the journal commit, but its reply arrives last.
    first.resolve({ ...lease(base, 60_000), gateRecovery: "applied" });
    await recovered;
    second.resolve(lease(base, 0));
    await stale;
    expect(watchdog.state().leaseValid).toBe(true);
    expect(watchdog.state().allowed).toBeGreaterThan(0);
  });

  test("a failed withdrawal stops the proxy and raises events", async () => {
    const h = harness({ failLoad: true });
    await h.watchdog.tick();
    expect(h.caddy.stopped()).toBe(true);
    expect(h.events.map((event) => event.event)).toEqual(["withdrawal_failed", "proxy_stopped"]);
  });

  test("a failed stop is reported too", async () => {
    const adapter: EdgeWithdrawalAdapter = {
      proxy: "fake",
      enforce: async (): Promise<WithdrawalResult> => ({
        proxy: "fake",
        active: ["x"],
        withdrawn: ["x"],
        error: "boom",
      }),
      stop: async () => {
        throw new Error("stop refused");
      },
    };
    const events: WatchdogEvent[] = [];
    const watchdog = new EdgeWatchdog({
      fetchLease: async () => {
        throw new Error("down");
      },
      adapters: [adapter],
      report: async (event) => {
        events.push(event);
      },
    });
    await watchdog.tick();
    expect(events.map((event) => event.event)).toEqual(["withdrawal_failed", "stop_failed"]);
  });
});

describe("route identity and fail-closed regressions", () => {
  test("revokes one hostname on a shared backend and refuses the stale launch file", async () => {
    const keep = routes[0]!;
    const revoke = { ...keep, id: "rt_revoked", hostname: "revoked.example.com", stableId: "old" };

    const active = {
      apps: {
        http: { servers: { srv0: { routes: [sharedBackendHandler(keep), sharedBackendHandler(revoke)] } } },
      },
    };
    const { config: next, withdrawn } = withdrawCaddyBackends(active, new Set([routeIdentityKey(keep)]));
    expect(withdrawn).toEqual(["100.101.102.103:3000"]);
    const serialized = JSON.stringify(next);
    expect(serialized.match(/"handler":"reverse_proxy"/g)).toHaveLength(1);
    expect(caddyTailnetBackends(next)).toEqual(["100.101.102.103:3000"]);
    expect(serialized).toContain(JSON.stringify(WITHDRAWN_HANDLER));
    const stale = renderCaddyfile({
      adminMode: "tailnet",
      apiUpstream: "api:3000",
      challengeDir: "/acme",
      certificates: [keep, revoke].map((route) => ({
        hostname: route.hostname,
        status: "issued",
        fullchain: "/cert.pem",
        privkey: "/key.pem",
      })),
      httpRoutes: [keep, revoke].map((route) => ({ ...route, access: "public" as const })),
    });
    expect(launchDecision(stale, new Set([routeIdentityKey(keep)])).open).toBe(false);
    expect(launchDecision(stale, new Set([routeIdentityKey(keep), routeIdentityKey(revoke)])).open).toBe(
      true,
    );
    // Changing just the pin, route ID, host match or backend cannot reuse the old authorisation.
    for (const changed of [
      { ...keep, stableId: "replacement" },
      { ...keep, id: "rt_new" },
      { ...keep, hostname: "other.example.com" },
      { ...keep, port: 4000 },
    ]) {
      expect(withdrawCaddyBackends(active, new Set([routeIdentityKey(changed)])).activeRoutes).toEqual([]);
    }
    const legacy = {
      match: [{ host: [keep.hostname] }],
      handle: [{ handler: "reverse_proxy", upstreams: [{ dial: "100.101.102.103:3000" }] }],
    };
    expect(withdrawCaddyBackends(legacy, allowed(0)).withdrawn).toHaveLength(1);
    expect(launchDecision("www.example.com {\n reverse_proxy 100.101.102.103:3000\n}", allowed(0)).open).toBe(
      false,
    );
  });

  test("read failure stops and alerts even if the public proxy remains live; repeated failures are coalesced", async () => {
    let stops = 0;
    let reads = 0;
    const events: WatchdogEvent[] = [];
    const adapter = new CaddyWithdrawalAdapter("http://admin:2019", async (url) => {
      if (url.endsWith("/config/")) {
        reads++;
        return new Response("admin broken, public still live", { status: 503 });
      }
      stops++;
      return new Response("stop also failed", { status: 503 });
    });
    const watchdog = new EdgeWatchdog({
      fetchLease: async () => lease(0, 0),
      adapters: [adapter],
      startupGraceMs: 0,
      report: async (event) => {
        events.push(event);
      },
    });
    for (let i = 0; i < 4; i++) await watchdog.tick();
    expect(reads).toBe(4);
    expect(stops).toBe(4); // Retry the safety action; deduplicate reporting only.
    expect(events.map((event) => event.event)).toEqual(["withdrawal_failed", "stop_failed"]);
  });

  test("startup grace is bounded, and cannot hide later inspection failures", async () => {
    let now = 0;
    let stops = 0;
    const watchdog = new EdgeWatchdog({
      now: () => now,
      fetchLease: async () => lease(0, 0),
      adapters: [
        {
          proxy: "fake",
          enforce: async () => ({
            proxy: "fake",
            active: [],
            withdrawn: [],
            error: "read failed",
            unreachable: true,
          }),
          stop: async () => {
            stops++;
          },
        },
      ],
    });
    await watchdog.tick();
    expect(stops).toBe(0);
    now = 5000;
    await watchdog.tick();
    expect(stops).toBe(1);
  });

  test("a persistent reload failure reports once, continues stopping and reports again after recovery", async () => {
    let failing = true;
    let stops = 0;
    const events: WatchdogEvent[] = [];
    const watchdog = new EdgeWatchdog({
      fetchLease: async () => lease(0, 0),
      adapters: [
        {
          proxy: "fake",
          enforce: async () => ({
            proxy: "fake",
            active: ["x"],
            withdrawn: failing ? ["x"] : [],
            ...(failing ? { error: "load failed" } : {}),
          }),
          stop: async () => {
            stops++;
          },
        },
      ],
      report: async (event) => {
        events.push(event);
      },
    });
    for (let i = 0; i < 5; i++) await watchdog.tick();
    expect(stops).toBe(5);
    expect(events.map((event) => event.event)).toEqual(["withdrawal_failed", "proxy_stopped"]);
    failing = false;
    await watchdog.tick();
    failing = true;
    await watchdog.tick();
    expect(events.map((event) => event.event)).toEqual([
      "withdrawal_failed",
      "proxy_stopped",
      "withdrawal_failed",
      "proxy_stopped",
    ]);
  });

  test("bulk events stay bounded and a failed delivery retries after the config has converged", async () => {
    const backends = Array.from({ length: 100 }, (_, i) => `100.80.1.${i + 1}:3000`);
    let active = true;
    let attempts = 0;
    const events: WatchdogEvent[] = [];
    const watchdog = new EdgeWatchdog({
      fetchLease: async () => lease(0, 0),
      adapters: [
        {
          proxy: "fake",
          enforce: async () => {
            const withdrawn = active ? backends : [];
            active = false;
            return { proxy: "fake", active: [], withdrawn };
          },
          stop: async () => undefined,
        },
      ],
      report: async (event) => {
        attempts++;
        if (attempts === 1) throw new Error("API offline");
        events.push(event);
      },
    });
    await watchdog.tick();
    expect(events).toHaveLength(0);
    await watchdog.tick();
    expect(attempts).toBe(2);
    expect(events).toHaveLength(1);
    expect(events[0]!.detail).toContain("100 backend(s)");
    expect(events[0]!.detail.length).toBeLessThanOrEqual(1000);
  });
});
