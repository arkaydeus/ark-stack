// `edge.observe` against a mocked LocalAPI on a real unix socket (front door §3.2, FD-06): complete
// generations, absent-peer deletion, failed and partial reads that never renew the lease, identity
// pinning (rename -> identity_mismatch, removal -> awaiting_acl, same StableID -> IP update), the
// edge-netns TCP probe gate for `ready`, durable withdrawal, the lease policy the watchdog enforces,
// expiry, and the five-minute schedule.

import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  SNAPSHOT_VALIDITY_MS,
  createId,
  parseEnvFile,
  planEdge,
  renderCaddyfile,
  renderEdgeL4Generation,
  type OperationKind,
} from "@ark-stack/shared";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { sql } = await import("./db.ts");
const { edgePolicy, expireStaleEdgeRoutes, observeEdgeTailnet, startEdgeObserveSchedule, tailnetOverview } =
  await import("./modules/edge-observe.ts");
const { edgeLocalApi } = await import("./modules/tailnet-localapi.ts");
const { MockLocalApi } = await import("./mock-localapi.ts");

const suffix = createId("t").slice(2, 10);
const tailnet = ".tail1234.ts.net";
const socket = join(tmpdir(), `ark-localapi-${suffix}.sock`);
const self = {
  id: `nEDGE${suffix}`,
  name: "ark-edge",
  ips: ["100.64.0.1", "fd7a:115c:a1e0::1"],
  tags: ["tag:ark-edge"],
};
const home = { id: `nHOME${suffix}`, name: "home", ips: ["100.101.102.103", "fd7a:115c:a1e0::103"] };
const nas = { id: `nNAS${suffix}`, name: "nas", ips: ["100.88.1.20"] };

const mock = new MockLocalApi({
  backendState: "Running",
  suffix: tailnet,
  self,
  peers: [home, nas],
  reachable: new Set(),
});
await mock.listen(socket);
const api = edgeLocalApi(socket);

type Queued = { kind: OperationKind; targetIds: string[]; payload?: Record<string, unknown> };
let queued: Queued[] = [];
const enqueue = async (operation: Queued) => {
  queued.push(operation);
};
const endpointIds: string[] = [];
const routeIds: string[] = [];

async function addRoute(input: {
  target: string;
  stableId: string;
  ip: string;
  port: number;
  status: string;
  certificate?: boolean;
  domainId?: string;
  accessMode?: "public" | "sso";
  enabled?: boolean;
  httpOptions?: Record<string, unknown>;
}) {
  const endpointId = createId("end");
  const routeId = `rt_${createId("x").slice(2, 18)}`;
  await sql`INSERT INTO endpoints (id, kind, hostname, domain_id) VALUES (${endpointId}, 'route', ${`${routeId.slice(3)}.example.com`}, ${input.domainId ?? null})`;
  await sql`
    INSERT INTO front_routes (id, kind, endpoint_id, listen_port, target_input, target_node_stable_id,
      target_ip, target_port, access_mode, status, enabled, http_options)
    VALUES (${routeId}, 'http', ${endpointId}, 443, ${input.target}, ${input.stableId}, ${input.ip},
      ${input.port}, ${input.accessMode ?? "public"}, ${input.status}, ${input.enabled ?? true},
      ${JSON.stringify(input.httpOptions ?? {})}::jsonb)
  `;
  if (input.certificate ?? ["ready", "observation_expired"].includes(input.status))
    await sql`INSERT INTO certificates (id, endpoint_id, names, status, last_deployed_at)
    VALUES (${createId("crt")}, ${endpointId}, ${JSON.stringify([`${routeId.slice(3)}.example.com`])}::jsonb, 'issued', now())`;
  endpointIds.push(endpointId);
  routeIds.push(routeId);
  return routeId;
}

async function route(id: string) {
  const [row] = await sql`SELECT status, target_ip, last_error FROM front_routes WHERE id = ${id}`;
  return row as { status: string; target_ip: string; last_error: string | null };
}

async function snapshotRow() {
  const [row] =
    await sql`SELECT generation, completed_at, valid_until FROM tailnet_snapshots WHERE source = 'edge'`;
  if (!row) return undefined;
  return {
    generation: String(row.generation),
    completed_at: new Date(row.completed_at as string),
    valid_until: new Date(row.valid_until as string),
  };
}

async function nodeIds() {
  const rows = await sql`SELECT stable_id FROM tailnet_nodes WHERE source = 'edge' ORDER BY stable_id`;
  return rows.map((row) => String(row.stable_id));
}

const observe = (now?: Date) => observeEdgeTailnet({ api, enqueue, now: now ? () => now : undefined });

/** Renders the edge as `edge.apply` would, from the current lease policy. */
async function rendered(now = new Date()) {
  const policy = await edgePolicy(now);
  const routes = policy.routes.map((item) => ({
    id: item.id,
    stableId: item.stableId,
    hostname: item.hostname,
    ip: item.ip,
    port: item.port,
    access: "public" as const,
  }));
  const plan = planEdge({
    adminMode: "tailnet",
    endpoints: [],
    certificates: [],
    httpRoutes: routes,
  });
  return renderCaddyfile({
    adminMode: "tailnet",
    challengeDir: "/var/lib/ark/acme",
    apiUpstream: "api:3000",
    certificates: routes.map((item) => ({
      hostname: item.hostname,
      status: "issued",
      fullchain: `/certs/${item.hostname}/fullchain.pem`,
      privkey: `/certs/${item.hostname}/privkey.pem`,
    })),
    httpRoutes: plan.httpRoutes,
  });
}

async function removeRoutes() {
  if (routeIds.length) await sql`DELETE FROM audit_events WHERE resource_id = ANY(${routeIds})`;
  if (routeIds.length) await sql`DELETE FROM front_routes WHERE id = ANY(${routeIds})`;
  if (endpointIds.length) await sql`DELETE FROM certificates WHERE endpoint_id = ANY(${endpointIds})`;
  if (endpointIds.length) await sql`DELETE FROM endpoints WHERE id = ANY(${endpointIds})`;
  routeIds.length = 0;
  endpointIds.length = 0;
}

beforeEach(async () => {
  await removeRoutes();
  await sql`DELETE FROM tailnet_nodes WHERE source = 'edge'`;
  await sql`DELETE FROM tailnet_snapshots WHERE source = 'edge'`;
  mock.state = { backendState: "Running", suffix: tailnet, self, peers: [home, nas], reachable: new Set() };
  queued = [];
});

afterAll(async () => {
  mock.stop();
  await removeRoutes();
  await sql`DELETE FROM tailnet_nodes WHERE source = 'edge'`;
  await sql`DELETE FROM tailnet_snapshots WHERE source = 'edge'`;
});

describe("complete generations", () => {
  test("commits self and every peer with a six-minute lease from the start of the read", async () => {
    const before = Date.now();
    const result = await observe();
    const row = await snapshotRow();
    expect(row?.generation).toBe(result.generation);
    expect(row!.valid_until.getTime() - row!.completed_at.getTime()).toBe(SNAPSHOT_VALIDITY_MS);
    expect(row!.completed_at.getTime()).toBeGreaterThanOrEqual(before - 1000);
    expect(await nodeIds()).toEqual([home.id, nas.id, self.id].toSorted());
    const [selfRow] =
      await sql`SELECT dns_name, tags, is_self FROM tailnet_nodes WHERE stable_id = ${self.id}`;
    expect(selfRow).toEqual({ dns_name: `ark-edge${tailnet}`, tags: ["tag:ark-edge"], is_self: true });
    expect(mock.calls).toContain("GET /localapi/v0/status");
  });

  test("deletes peers absent from the next completed generation", async () => {
    const first = await observe();
    mock.state.peers = [home];
    const second = await observe();
    expect(second.generation).not.toBe(first.generation);
    expect(await nodeIds()).toEqual([home.id, self.id].toSorted());
    const generations = await sql`SELECT DISTINCT generation FROM tailnet_nodes WHERE source = 'edge'`;
    expect(generations.map((row) => row.generation)).toEqual([second.generation]);
  });

  const failures: Array<[string, () => void]> = [
    ["the LocalAPI answers 500", () => (mock.state.statusFault = { code: 500 })],
    ["the connection closes mid-read", () => (mock.state.statusFault = { close: true })],
    ["the status is not JSON", () => (mock.state.statusFault = { body: "{" })],
    ["the node is logged out", () => (mock.state.backendState = "NeedsLogin")],
    ["a peer has no StableNodeID", () => (mock.state.peers = [home, { ...nas, id: "" }])],
    ["a StableNodeID appears twice", () => (mock.state.peers = [home, { ...nas, id: home.id }])],
    ["a peer address is malformed", () => (mock.state.peers = [home, { ...nas, ips: ["100.88.1"] }])],
  ];
  for (const [name, fault] of failures) {
    test(`a failed or partial read never renews the lease or drops peers: ${name}`, async () => {
      await observe();
      const before = await snapshotRow();
      const nodes = await nodeIds();
      fault();
      await expect(observe()).rejects.toThrow(/lease was not renewed/);
      expect(await snapshotRow()).toEqual(before);
      expect(await nodeIds()).toEqual(nodes);
    });
  }

  test("an unreachable socket is a failed observation", async () => {
    await observe();
    const before = await snapshotRow();
    const missing = edgeLocalApi(join(tmpdir(), `ark-missing-${suffix}.sock`));
    await expect(observeEdgeTailnet({ api: missing, enqueue })).rejects.toThrow(/could not be read/);
    expect(await snapshotRow()).toEqual(before);
  });

  test("an older read cannot replace a newer generation", async () => {
    await observe();
    await expect(observe(new Date(Date.now() - 60_000))).rejects.toThrow(/newer edge observation/);
  });
});

describe("identity pinning and the edge-netns probe", () => {
  test("a peer in status whose port fails the probe stays awaiting_acl; a passing probe makes it ready", async () => {
    const id = await addRoute({
      target: `home${tailnet}`,
      stableId: home.id,
      ip: "100.101.102.103",
      port: 3000,
      status: "awaiting_acl",
      certificate: true,
    });
    await observe();
    expect((await route(id)).status).toBe("awaiting_acl");
    expect((await route(id)).last_error).toMatch(/cannot open TCP to 100\.101\.102\.103:3000/);
    expect(mock.calls).toContain("dial 100.101.102.103:3000");
    expect((await edgePolicy()).routes.map((item) => item.id)).not.toContain(id);
    expect(await rendered()).not.toContain("100.101.102.103");

    mock.state.reachable.add("100.101.102.103:3000");
    const result = await observe();
    expect((await route(id)).status).toBe("ready");
    expect(result.routes.find((item) => item.id === id)).toMatchObject({ from: "awaiting_acl", to: "ready" });
    expect((await edgePolicy()).routes.map((item) => item.id)).toContain(id);
    expect(await rendered()).toContain(`# ark-tailnet-route ${id} 100.101.102.103:3000`);
    expect(queued.map((item) => item.kind)).toContain("edge.apply");
  });

  test("renaming the target machine flips a name-pinned route to identity_mismatch and removes it from the config", async () => {
    mock.state.reachable.add("100.101.102.103:3000");
    const id = await addRoute({
      target: `home${tailnet}`,
      stableId: home.id,
      ip: "100.101.102.103",
      port: 3000,
      status: "ready",
    });
    await observe();
    expect((await route(id)).status).toBe("ready");
    expect(await rendered()).toContain("reverse_proxy 100.101.102.103:3000");
    queued = [];

    // A different machine now answers to the same name (and even the same address).
    const impostor = { ...home, id: `nIMPOSTOR${suffix}` };
    mock.state.peers = [impostor, nas];
    await observe();
    const row = await route(id);
    expect(row.status).toBe("identity_mismatch");
    expect(row.last_error).toMatch(/no longer identifies the pinned machine/);
    expect((await edgePolicy()).routes.map((item) => item.id)).not.toContain(id);
    expect(await rendered()).not.toContain(id);
    expect(await rendered()).not.toContain("100.101.102.103");
    expect(queued.map((item) => item.kind)).toEqual(["edge.apply", "edge.drain"]);
    expect(queued[1]?.payload).toMatchObject({
      reason: "identity",
      routeIds: [id],
      backends: ["100.101.102.103:3000"],
    });
    const [audit] =
      await sql`SELECT action FROM audit_events WHERE resource_id = ${id} ORDER BY created_at DESC LIMIT 1`;
    expect(audit?.action).toBe("front_route.identity_mismatch");

    // The mismatch is sticky until the owner re-confirms, even if the old machine comes back.
    mock.state.peers = [home, nas];
    await observe();
    expect((await route(id)).status).toBe("identity_mismatch");
  });

  test("the lease policy withdraws a replaced identity as soon as its generation commits", async () => {
    mock.state.reachable.add("100.101.102.103:3000");
    const id = await addRoute({
      target: `home${tailnet}`,
      stableId: home.id,
      ip: "100.101.102.103",
      port: 3000,
      status: "ready",
    });
    await observe();
    expect((await edgePolicy()).routes.map((item) => item.id)).toContain(id);
    // A committed generation in which another machine holds the name, before any worker has
    // re-validated routes: the policy the watchdog reads excludes the route already.
    await sql`UPDATE tailnet_nodes SET stable_id = ${`nOTHER${suffix}`} WHERE stable_id = ${home.id}`;
    expect((await route(id)).status).toBe("ready");
    expect((await edgePolicy()).routes.map((item) => item.id)).not.toContain(id);
  });

  test("removing the target peer withdraws the route as awaiting_acl", async () => {
    mock.state.reachable.add("100.88.1.20:8443");
    const id = await addRoute({
      target: "100.88.1.20",
      stableId: nas.id,
      ip: "100.88.1.20",
      port: 8443,
      status: "ready",
    });
    await observe();
    expect((await route(id)).status).toBe("ready");
    queued = [];
    mock.state.peers = [home];
    await observe();
    expect((await route(id)).status).toBe("awaiting_acl");
    expect(queued.find((item) => item.kind === "edge.drain")?.payload).toMatchObject({ routeIds: [id] });
  });

  test("the same StableID at a new address updates the pinned IP and drains the old backend", async () => {
    mock.state.reachable.add("100.101.102.103:3000").add("100.101.102.200:3000");
    const id = await addRoute({
      target: `home${tailnet}`,
      stableId: home.id,
      ip: "100.101.102.103",
      port: 3000,
      status: "ready",
    });
    await observe();
    queued = [];
    mock.state.peers = [{ ...home, ips: ["100.101.102.200"] }, nas];
    await observe();
    expect(await route(id)).toMatchObject({ status: "ready", target_ip: "100.101.102.200" });
    expect(queued.find((item) => item.kind === "edge.drain")?.payload).toMatchObject({
      backends: ["100.101.102.103:3000"],
    });
    const audits =
      await sql`SELECT action, detail FROM audit_events WHERE resource_id = ${id} AND action = 'front_route.target_ip_changed'`;
    expect(audits[0]?.detail).toMatchObject({ from: "100.101.102.103", to: "100.101.102.200" });
    expect(await rendered()).toContain("reverse_proxy 100.101.102.200:3000");
  });
});

describe("lease expiry", () => {
  test("an expired lease allows nothing, and the next observation withdraws ready routes first", async () => {
    mock.state.reachable.add("100.101.102.103:3000");
    const id = await addRoute({
      target: `home${tailnet}`,
      stableId: home.id,
      ip: "100.101.102.103",
      port: 3000,
      status: "ready",
    });
    const t0 = new Date();
    await observe(t0);
    expect(
      (await edgePolicy(new Date(t0.getTime() + SNAPSHOT_VALIDITY_MS - 1))).routes.map((item) => item.id),
    ).toContain(id);
    const later = new Date(t0.getTime() + SNAPSHOT_VALIDITY_MS);
    const expired = await edgePolicy(later);
    expect(expired.lease?.valid).toBe(false);
    expect(expired.routes).toEqual([]);
    expect(await rendered(later)).not.toContain("100.101.102.103");

    // A failed observation after expiry withdraws durably and still renews nothing.
    queued = [];
    mock.state.backendState = "Stopped";
    await expect(observe(later)).rejects.toThrow(/lease was not renewed/);
    expect((await route(id)).status).toBe("observation_expired");
    expect(queued.map((item) => item.kind)).toEqual(["edge.apply", "edge.drain"]);
    expect((await snapshotRow())!.valid_until.getTime()).toBe(later.getTime());

    // A complete observation renews the lease and the probe makes the route ready again.
    mock.state.backendState = "Running";
    await observe(new Date(later.getTime() + 1_000));
    expect((await route(id)).status).toBe("ready");
  });

  test("expireStaleEdgeRoutes does nothing while the lease is valid", async () => {
    await observe();
    expect(await expireStaleEdgeRoutes({ enqueue })).toEqual([]);
  });

  test("the overview reports the generation, lease and each route's identity state", async () => {
    mock.state.reachable.add("100.101.102.103:3000");
    const id = await addRoute({
      target: `home${tailnet}`,
      stableId: home.id,
      ip: "100.101.102.103",
      port: 3000,
      status: "awaiting_acl",
      certificate: true,
    });
    await observe();
    const overview = await tailnetOverview();
    expect(overview.generation?.leaseValid).toBe(true);
    expect(overview.self).toMatchObject({ stableId: self.id, tags: ["tag:ark-edge"] });
    expect(overview.tailnetSuffix).toBe(tailnet);
    expect(overview.peers.map((peer) => peer.stableId)).toEqual([home.id, nas.id]);
    expect(overview.routes.find((item) => item.id === id)).toMatchObject({
      status: "ready",
      identity: "ok",
      serving: true,
      pinned: { stableId: home.id, ip: "100.101.102.103", port: 3000 },
    });
  });
});

describe("schedule", () => {
  test("enqueues edge.observe immediately and then every interval", async () => {
    const calls: Queued[] = [];
    const timer = startEdgeObserveSchedule({
      enqueue: async (operation) => {
        calls.push(operation);
      },
      intervalMs: 50,
    });
    await Bun.sleep(180);
    clearInterval(timer);
    expect(calls.length).toBeGreaterThanOrEqual(3);
    expect(calls.every((call) => call.kind === "edge.observe" && call.targetIds[0] === "tailnet:edge")).toBe(
      true,
    );
  });

  test("defaults to every five minutes", async () => {
    const { EDGE_OBSERVE_INTERVAL_MS } = await import("@ark-stack/shared");
    expect(EDGE_OBSERVE_INTERVAL_MS).toBe(5 * 60_000);
    const intervals: number[] = [];
    const original = globalThis.setInterval;
    globalThis.setInterval = ((handler: () => void, ms: number) => {
      intervals.push(ms);
      return original(handler, 1_000_000);
    }) as typeof setInterval;
    try {
      clearInterval(startEdgeObserveSchedule({ enqueue: async () => undefined }));
    } finally {
      globalThis.setInterval = original;
    }
    expect(intervals).toEqual([5 * 60_000]);
  });
});

describe("coordinator wiring", () => {
  test.each([true, false])(
    "edge.observe reconciles only renderable routes (issued certificate: %s)",
    async (certificate) => {
      const { enqueue: realEnqueue, runOperation } = await import("./coordinator.ts");
      await observe(); // Establish a current lease before adding an already-ready route.
      mock.state.reachable.add("100.101.102.103:3000");
      const id = await addRoute({
        target: `home${tailnet}`,
        stableId: home.id,
        ip: "100.101.102.103",
        port: 3000,
        status: "ready",
        certificate,
      });
      // A running Caddy that serves nothing from the tailnet (for example, started from the closed config).
      const caddy = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch: (request) =>
          new URL(request.url).pathname === "/config/"
            ? Response.json({ apps: { http: { servers: { srv0: { routes: [] } } } } })
            : new Response("not found", { status: 404 }),
      });
      const previous = { socket: process.env.ARK_EDGE_TS_SOCKET, reload: process.env.ARK_EDGE_RELOAD_URL };
      process.env.ARK_EDGE_TS_SOCKET = socket;
      process.env.ARK_EDGE_RELOAD_URL = `http://127.0.0.1:${caddy.port}`;
      const created: string[] = [];
      try {
        await sql`UPDATE operations SET status = 'cancelled' WHERE kind = 'edge.apply' AND status = 'queued'`;
        const operation = await realEnqueue({
          kind: "edge.observe",
          targetIds: ["tailnet:edge"],
          payload: { test: suffix },
        });
        created.push(operation.id);
        const result = (await runOperation("edge.observe", operation)) as {
          reconcile: { missing: string[] };
        };
        expect((await route(id)).status).toBe(certificate ? "ready" : "awaiting_dns");
        expect(result.reconcile.missing).toEqual(certificate ? [id] : []);
        const applies = await sql`SELECT id FROM operations WHERE kind = 'edge.apply' AND status = 'queued'`;
        created.push(...applies.map((row) => String(row.id)));
        // Missing certificates now withdraw the formerly-ready route and queue a render too.
        expect(applies).toHaveLength(1);
      } finally {
        caddy.stop(true);
        if (previous.socket === undefined) delete process.env.ARK_EDGE_TS_SOCKET;
        else process.env.ARK_EDGE_TS_SOCKET = previous.socket;
        if (previous.reload === undefined) delete process.env.ARK_EDGE_RELOAD_URL;
        else process.env.ARK_EDGE_RELOAD_URL = previous.reload;
        if (created.length) {
          await sql`DELETE FROM operation_steps WHERE operation_id = ANY(${created})`;
          await sql`DELETE FROM operations WHERE id = ANY(${created})`;
        }
      }
    },
  );

  test("edge.observe refuses to run without the edge node's socket", async () => {
    const { enqueue: realEnqueue, runOperation } = await import("./coordinator.ts");
    const previous = process.env.ARK_EDGE_TS_SOCKET;
    delete process.env.ARK_EDGE_TS_SOCKET;
    const operation = await realEnqueue({
      kind: "edge.observe",
      targetIds: ["tailnet:edge"],
      payload: { test: `${suffix}-nosocket` },
    });
    try {
      await expect(runOperation("edge.observe", operation)).rejects.toThrow(/ARK_EDGE_TS_SOCKET is not set/);
    } finally {
      if (previous !== undefined) process.env.ARK_EDGE_TS_SOCKET = previous;
      await sql`DELETE FROM operations WHERE id = ${operation.id}`;
    }
  });
});

describe("lifecycle recovery", () => {
  test.each(["awaiting_dns", "issuing_certificate"])(
    "%s survives temporary peer loss and recovers without becoming ready",
    async (status) => {
      const id = await addRoute({
        target: `home${tailnet}`,
        stableId: home.id,
        ip: "100.101.102.103",
        port: 3000,
        status,
      });
      mock.state.peers = [nas];
      await observe();
      expect((await route(id)).status).toBe(status);
      expect((await route(id)).last_error).not.toBeNull();
      mock.state.peers = [home, nas];
      mock.state.reachable.add("100.101.102.103:3000");
      await observe();
      expect((await route(id)).status).toBe(status);
      expect((await route(id)).last_error).toBeNull();
      expect((await edgePolicy()).routes.map((item) => item.id)).not.toContain(id);
    },
  );
  test("a healthy lifecycle observation preserves errors owned by DNS or certificate work", async () => {
    const id = await addRoute({
      target: `home${tailnet}`,
      stableId: home.id,
      ip: "100.101.102.103",
      port: 3000,
      status: "awaiting_dns",
    });
    await sql`UPDATE front_routes SET last_error = 'DNS provider refused the record' WHERE id = ${id}`;
    await observe();
    expect((await route(id)).last_error).toBe("DNS provider refused the record");
    expect((await route(id)).status).toBe("awaiting_dns");
  });
  test("a lifecycle identity mismatch is sticky", async () => {
    const id = await addRoute({
      target: `home${tailnet}`,
      stableId: home.id,
      ip: "100.101.102.103",
      port: 3000,
      status: "issuing_certificate",
    });
    mock.state.peers = [{ ...home, id: "nREPLACED" }];
    await observe();
    expect((await route(id)).status).toBe("identity_mismatch");
    mock.state.peers = [home, nas];
    await observe();
    expect((await route(id)).status).toBe("identity_mismatch");
  });
});

describe("route lifecycle (FD-08)", () => {
  const domainId = createId("dom");
  beforeEach(async () => {
    await sql`
      INSERT INTO domain_claims (id, name, ownership_token, status)
      VALUES (${domainId}, ${`${suffix}.example.com`}, 'ark-own-test', 'verified')
      ON CONFLICT (id) DO NOTHING
    `;
  });
  afterAll(async () => {
    await removeRoutes();
    await sql`DELETE FROM domain_claims WHERE id = ${domainId}`;
  });

  test("a passing probe moves a new route on to awaiting_dns and queues domain.verify, not ready", async () => {
    mock.state.reachable.add("100.101.102.103:3000");
    const id = await addRoute({
      target: `home${tailnet}`,
      stableId: home.id,
      ip: "100.101.102.103",
      port: 3000,
      status: "awaiting_acl",
      domainId,
    });
    const result = await observe();
    expect((await route(id)).status).toBe("awaiting_dns");
    expect(result.routes.find((item) => item.id === id)).toMatchObject({
      from: "awaiting_acl",
      to: "awaiting_dns",
    });
    expect(queued).toContainEqual({
      kind: "domain.verify",
      targetIds: [domainId],
      payload: { routeEndpointsOnly: true },
    });
    expect((await edgePolicy()).routes.map((item) => item.id)).not.toContain(id);
    // DNS is re-checked on every observation until it resolves.
    queued = [];
    await observe();
    expect((await route(id)).status).toBe("awaiting_dns");
    expect(queued).toContainEqual({
      kind: "domain.verify",
      targetIds: [domainId],
      payload: { routeEndpointsOnly: true },
    });
  });

  test("issuing_certificate becomes ready only with an issued certificate and a passing probe", async () => {
    const id = await addRoute({
      target: `home${tailnet}`,
      stableId: home.id,
      ip: "100.101.102.103",
      port: 3000,
      status: "issuing_certificate",
      domainId,
    });
    mock.state.reachable.add("100.101.102.103:3000");
    await observe();
    expect((await route(id)).status).toBe("issuing_certificate");
    const [row] = await sql`SELECT endpoint_id FROM front_routes WHERE id = ${id}`;
    await sql`INSERT INTO certificates (id, endpoint_id, names, status, last_deployed_at)
      VALUES (${createId("crt")}, ${row!.endpoint_id}, '[]'::jsonb, 'untrusted', now())`;
    await observe();
    expect((await route(id)).status).toBe("issuing_certificate");
    await sql`INSERT INTO certificates (id, endpoint_id, names, status, last_deployed_at)
      VALUES (${createId("crt")}, ${row!.endpoint_id}, '[]'::jsonb, 'issued', now() + interval '1 second')`;
    mock.state.reachable.clear();
    await observe();
    expect((await route(id)).status).toBe("awaiting_acl");
    mock.state.reachable.add("100.101.102.103:3000");
    await observe();
    expect((await route(id)).status).toBe("ready");
  });
});

describe("coordinator drain failure", () => {
  test.each(["load", "read"])("%s failure attempts a stop and raises a critical alert", async (failure) => {
    const { enqueue: realEnqueue, runOperation } = await import("./coordinator.ts");
    const calls: string[] = [];
    const caddy = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        const path = new URL(request.url).pathname;
        calls.push(`${request.method} ${path}`);
        if (path === "/stop") return new Response("");
        if (path === "/config/" && failure === "load")
          return Response.json({ handler: "reverse_proxy", upstreams: [{ dial: "100.101.102.103:3000" }] });
        return new Response("injected failure", { status: 503 });
      },
    });
    const previous = process.env.ARK_EDGE_RELOAD_URL;
    process.env.ARK_EDGE_RELOAD_URL = `http://127.0.0.1:${caddy.port}`;
    const operation = await realEnqueue({
      kind: "edge.drain",
      targetIds: ["edge:drain"],
      payload: { reason: "test" },
    });
    try {
      await expect(runOperation("edge.drain", operation)).rejects.toThrow(/withdrawal failed/);
      expect(calls).toContain("POST /stop");
      const [alert] = await sql`SELECT severity FROM alerts WHERE dedup_key = 'edge-withdrawal'`;
      expect(alert?.severity).toBe("critical");
    } finally {
      caddy.stop(true);
      if (previous === undefined) delete process.env.ARK_EDGE_RELOAD_URL;
      else process.env.ARK_EDGE_RELOAD_URL = previous;
      await sql`DELETE FROM operations WHERE id = ${operation.id}`;
      await sql`DELETE FROM alerts WHERE dedup_key = 'edge-withdrawal'`;
    }
  });
});

describe("stale probes", () => {
  test("a delayed passing probe cannot promote a changed target port", async () => {
    const id = await addRoute({
      target: `home${tailnet}`,
      stableId: home.id,
      ip: "100.101.102.103",
      port: 3000,
      status: "awaiting_acl",
      certificate: true,
    });
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const ports: number[] = [];
    const pending = observeEdgeTailnet({
      api: {
        status: () => api.status(),
        probe: async (_ip, port) => {
          ports.push(port);
          entered.resolve();
          await release.promise;
          return { ok: true, detail: "connected" };
        },
      },
      enqueue,
    });
    await entered.promise;
    try {
      await sql`UPDATE front_routes SET target_port = 3001, status = 'awaiting_acl' WHERE id = ${id}`;
    } finally {
      release.resolve();
    }
    await pending;
    expect(ports).toEqual([3000]);
    expect((await route(id)).status).toBe("awaiting_acl");
    expect(queued).toEqual([]);
    mock.state.reachable.add("100.101.102.103:3001");
    await observe();
    expect(mock.calls).toContain("dial 100.101.102.103:3001");
    expect((await route(id)).status).toBe("ready");
  });

  test("a ready route with an expired certificate re-enters repair", async () => {
    const id = await addRoute({
      target: `home${tailnet}`,
      stableId: home.id,
      ip: "100.101.102.103",
      port: 3000,
      status: "ready",
    });
    await sql`UPDATE certificates SET expires_at = now() - interval '1 day'
      WHERE endpoint_id = (SELECT endpoint_id FROM front_routes WHERE id = ${id})`;
    mock.state.reachable.add("100.101.102.103:3000");
    await observe();
    expect((await route(id)).status).toBe("awaiting_dns");
    expect(queued.some((item) => item.kind === "edge.drain")).toBe(true);
  });
});

/** Both rendered configs as edge.apply and edge.l4_apply produce them from the database. */
async function renderedConfigs() {
  const { edgePlan, edgeL4Input } = await import("./coordinator.ts");
  const plan = await edgePlan("tailnet", null);
  const caddyfile = renderCaddyfile({
    ...plan,
    challengeDir: "/var/lib/ark/acme",
    apiUpstream: "api:3000",
    adminHostname: plan.adminHostname,
  });
  const haproxy = renderEdgeL4Generation(edgeL4Input(plan)).files["haproxy.cfg"]!;
  return { plan, caddyfile, haproxy };
}

const hostOf = (id: string) => `${id.slice(3)}.example.com`;

describe("edge rendering of HTTP routes (FD-09)", () => {
  test("unservable states and SSO routes are absent from both rendered configs", async () => {
    mock.state.reachable.add("100.101.102.103:3000");
    const target = { target: `home${tailnet}`, stableId: home.id, ip: "100.101.102.103", port: 3000 };
    const live = await addRoute({ ...target, status: "ready" });
    const sso = await addRoute({ ...target, status: "ready", accessMode: "sso" });
    const apex = await addRoute({ ...target, status: "ready", httpOptions: { redirectTo: hostOf(live) } });
    const unservable = new Map<string, string>();
    for (const status of ["awaiting_acl", "identity_mismatch", "observation_expired", "disabled"]) {
      unservable.set(status, await addRoute({ ...target, status: "ready", certificate: true }));
    }
    // An enabled flag of false keeps even a ready route out.
    const switchedOff = await addRoute({ ...target, status: "ready", enabled: false });
    await observe();
    for (const [status, id] of unservable) {
      await sql`UPDATE front_routes SET status = ${status}, enabled = ${status !== "disabled"} WHERE id = ${id}`;
    }

    const { plan, caddyfile, haproxy } = await renderedConfigs();
    expect(caddyfile).toContain(`# ark-tailnet-route ${live} 100.101.102.103:3000\n${hostOf(live)} {`);
    expect(haproxy).toContain(hostOf(live));
    // The Location policy knows the target's MagicDNS name and its IPv6 address from the observation.
    expect(caddyfile).toContain("home\\.tail1234\\.ts\\.net\\.?");
    expect(caddyfile).toContain("\\[fd7a:115c:a1e0::103\\]");
    // Apex canonicalisation: a redirect site in both configs, but no tailnet marker or dial.
    expect(caddyfile).toContain(`${hostOf(apex)} {`);
    expect(caddyfile).toContain(`redir https://${hostOf(live)}{uri} 308`);
    expect(caddyfile).not.toContain(`# ark-tailnet-route ${apex}`);
    expect(haproxy).toContain(hostOf(apex));
    // SSO before FD-11: omitted with a reason, served nowhere.
    expect(plan.omitted.map((item) => item.id)).toEqual([sso]);
    expect(plan.omitted[0]?.reason).toMatch(/access mode "sso"/);
    for (const id of [sso, switchedOff, ...unservable.values()]) {
      expect(caddyfile).not.toContain(hostOf(id));
      expect(haproxy).not.toContain(hostOf(id));
    }
  });

  test("an enabled SSO route can never be rendered, even if handed straight to the renderer", async () => {
    mock.state.reachable.add("100.101.102.103:3000");
    const sso = await addRoute({
      target: `home${tailnet}`,
      stableId: home.id,
      ip: "100.101.102.103",
      port: 3000,
      status: "ready",
      accessMode: "sso",
    });
    await observe();
    const { edgeHttpRoutes } = await import("./modules/edge-routes.ts");
    const routes = await edgeHttpRoutes((await edgePolicy()).routes);
    expect(routes.map((item) => [item.id, item.access])).toEqual([[sso, "sso"]]);
    expect(() =>
      renderCaddyfile({
        adminMode: "tailnet",
        challengeDir: "/var/lib/ark/acme",
        apiUpstream: "api:3000",
        certificates: [{ hostname: hostOf(sso), status: "issued", fullchain: "/c.pem", privkey: "/k.pem" }],
        httpRoutes: routes,
      }),
    ).toThrow(/cannot serve/);
  });

  test("invalid stored HTTP options omit the route instead of failing every edge apply", async () => {
    mock.state.reachable.add("100.101.102.103:3000");
    const target = { target: `home${tailnet}`, stableId: home.id, ip: "100.101.102.103", port: 3000 };
    const live = await addRoute({ ...target, status: "ready", httpOptions: { maxBodyMb: 5, hsts: false } });
    const broken = await addRoute({
      ...target,
      status: "ready",
      httpOptions: { responseHeaderTimeout: '60s"\n}\nimport evil' },
    });
    await observe();
    const { plan, caddyfile, haproxy } = await renderedConfigs();
    expect(plan.omitted.map((item) => item.id)).toEqual([broken]);
    expect(caddyfile).toContain("max_size 5MB");
    expect(caddyfile).not.toContain(hostOf(broken));
    expect(caddyfile).not.toContain("import evil");
    expect(haproxy).toContain(hostOf(live));
    expect(haproxy).not.toContain(hostOf(broken));
  });
});
