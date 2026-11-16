import { describe, expect, test } from "bun:test";

import {
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

/** A fake Caddy admin API: GET /config/, POST /load (optionally failing), POST /stop. */
function fakeCaddy(options: { failLoad?: boolean } = {}) {
  let active: unknown = config();
  const calls: string[] = [];
  let stopped = false;
  const fetcher = async (url: string, init: RequestInit = {}) => {
    const path = new URL(url).pathname;
    calls.push(`${init.method ?? "GET"} ${path}`);
    if (stopped) throw new Error("connection refused");
    if (path === "/config/") return Response.json(active);
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
  return { fetcher, calls, active: () => active, stopped: () => stopped };
}

describe("CaddyWithdrawalAdapter", () => {
  test("loads the withdrawn config with must-revalidate and verifies it", async () => {
    const caddy = fakeCaddy();
    const adapter = new CaddyWithdrawalAdapter("http://edge-admin:2019", caddy.fetcher);
    const result = await adapter.enforce(allowed(1));
    expect(result).toMatchObject({ withdrawn: ["100.101.102.103:3000"] });
    expect(result.error).toBeUndefined();
    expect(caddyTailnetBackends(caddy.active())).toEqual(["[fd7a:115c:a1e0::103]:8080"]);
    expect(caddy.calls).toEqual(["GET /config/", "POST /load", "GET /config/"]);
    // Idempotent: a second pass changes nothing.
    expect((await adapter.enforce(allowed(1))).withdrawn).toEqual([]);
  });

  test("reports a failed load so the caller stops Caddy", async () => {
    const caddy = fakeCaddy({ failLoad: true });
    const result = await new CaddyWithdrawalAdapter("http://edge-admin:2019", caddy.fetcher).enforce(
      new Set(),
    );
    expect(result.error).toMatch(/withdrawal failed: POST \/load returned 500/);
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
      tailnetRoutes: [keep, revoke],
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
