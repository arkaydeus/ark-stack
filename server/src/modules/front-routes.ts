// HTTP route lifecycle (docs/design/front-door.md §3.3, §3.13, §3.14, FD-08).
//
// Owners create, update, enable, disable and delete public HTTP routes to tailnet services. A route
// moves through `draft -> awaiting_acl -> awaiting_dns -> issuing_certificate -> ready`:
//
// - draft: the row, its endpoint and its address records exist (created by the API).
// - awaiting_acl: the ACL snippet was handed out; waiting for the edge-netns TCP probe that
//   `edge.observe` runs (FD-06). Netmap presence alone is never enough.
// - awaiting_dns: the probe passed; `domain.verify` checks that the A (and gated AAAA) record
//   resolves to this server. The observer re-queues it on every run until it does.
// - issuing_certificate: DNS resolves to `public_ipv4`; `certificate.issue` was queued. Certificates
//   are never requested before this point.
// - ready: an issued certificate and a fresh passing probe. Only `edge.observe` writes `ready`.
//
// `enable` is refused before `ready`. Rendering routes into the live edge is FD-09; until then the
// edge serves at most the FD-06 tailnet route blocks for enabled `ready` routes.
//
// Every validation runs before the caller consumes a step-up grant, and every action is audited.

import {
  HTTP_LISTEN_PORT,
  ROUTE_RECORD_PURPOSE,
  assertSupportedAccessMode,
  assertSupportedRouteKind,
  backendKey,
  createId,
  looseningChanges,
  normalizeRedirectTo,
  normalizeRouteHostname,
  redactValue,
  routeAddressRecords,
  routeDomainFor,
  tailnetSuffixOf,
  validateRouteTarget,
  type DnsRecordPlan,
  type FrontRouteCreateInput,
  type FrontRouteUpdateInput,
  type OperationKind,
} from "@ark-stack/shared";
import { and, eq, like } from "drizzle-orm";

import { db } from "../db.ts";
import {
  auditEvents,
  certificates,
  dnsRecords,
  domainClaims,
  endpoints,
  frontRoutes,
  platformSettings,
} from "../schema.ts";
import { EDGE_OBSERVE_TARGET, edgePolicy, loadEdgeSnapshot } from "./edge-observe.ts";

export type RouteEnqueue = (input: {
  kind: OperationKind;
  targetIds: string[];
  payload?: Record<string, unknown>;
}) => Promise<unknown>;

export type RouteActor = { userId: string; role: string };

/** A refusal with an HTTP status. The API maps it to that status before any grant is consumed. */
export class FrontRouteError extends Error {
  status: 404 | 409 | 422;
  constructor(status: 404 | 409 | 422, message: string) {
    super(message);
    this.name = "FrontRouteError";
    this.status = status;
  }
}

type RouteRow = typeof frontRoutes.$inferSelect;
type EndpointRow = typeof endpoints.$inferSelect;
type DomainRow = typeof domainClaims.$inferSelect;

function redirectOf(route: Pick<RouteRow, "httpOptions">) {
  const value = route.httpOptions?.redirectTo;
  return typeof value === "string" ? value : null;
}

export async function auditRoute(
  actor: RouteActor | null,
  action: string,
  routeId: string,
  detail: Record<string, unknown>,
  operationId?: string,
) {
  await db.insert(auditEvents).values({
    id: createId("aud"),
    actorId: actor?.userId,
    role: actor?.role,
    action,
    resourceType: "front_route",
    resourceId: routeId,
    operationId,
    detail: redactValue(detail) as Record<string, unknown>,
  });
}

function idOf(operation: unknown) {
  return operation && typeof operation === "object" && "id" in operation ? String(operation.id) : undefined;
}

function isUniqueViolation(error: unknown) {
  let current: unknown = error;
  for (let depth = 0; depth < 5 && current; depth++) {
    if (typeof current === "object" && current && "code" in current && current.code === "23505") return true;
    current = typeof current === "object" && current && "cause" in current ? current.cause : undefined;
  }
  return false;
}

async function settings() {
  const [row] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  return row ?? null;
}

/** Validates a target against the edge node's latest complete snapshot (§3.2 rules 1-5). */
async function pinTarget(target: string, port: number, allowSensitivePort: boolean | undefined) {
  const loaded = await loadEdgeSnapshot();
  const result = validateRouteTarget({
    target,
    port,
    allowSensitivePort,
    peers: loaded.peers,
    snapshot: loaded.snapshot,
    self: loaded.self,
    now: new Date(),
    tailnetSuffix: loaded.self ? tailnetSuffixOf(loaded.self) : "",
    source: "edge",
  });
  if (!result.ok) throw new FrontRouteError(422, result.message);
  return result;
}

async function loadRoute(routeId: string) {
  const [row] = await db
    .select({ route: frontRoutes, endpoint: endpoints })
    .from(frontRoutes)
    .innerJoin(endpoints, eq(endpoints.id, frontRoutes.endpointId))
    .where(eq(frontRoutes.id, routeId));
  if (!row) throw new FrontRouteError(404, "Route not found.");
  const [domain] = row.endpoint.domainId
    ? await db.select().from(domainClaims).where(eq(domainClaims.id, row.endpoint.domainId))
    : [];
  return { route: row.route, endpoint: row.endpoint, domain: domain ?? null };
}

function requireHttp(route: RouteRow) {
  if (route.kind !== "http") {
    throw new FrontRouteError(422, `Route kind "${route.kind}" is not managed by this API yet.`);
  }
}

// ---- Listing ----------------------------------------------------------------------------------

function summarize(
  route: RouteRow,
  endpoint: EndpointRow,
  domain: DomainRow | null,
  records: Array<typeof dnsRecords.$inferSelect>,
  certificate: typeof certificates.$inferSelect | null,
  serving: Set<string>,
) {
  return {
    id: route.id,
    kind: route.kind,
    hostname: endpoint.hostname,
    listenPort: route.listenPort,
    accessMode: route.accessMode,
    redirectTo: redirectOf(route),
    enabled: route.enabled,
    status: route.status,
    lastError: route.lastError,
    serving: serving.has(route.id),
    target: {
      input: route.targetInput,
      stableId: route.targetNodeStableId,
      ip: route.targetIp,
      port: route.targetPort,
    },
    domain: domain
      ? { id: domain.id, name: domain.name, status: domain.status, dnsProvider: domain.dnsProvider }
      : null,
    dns: {
      endpointStatus: endpoint.status,
      lastVerifiedAt: endpoint.lastVerifiedAt?.toISOString() ?? null,
      records: records
        .filter((record) => record.name === endpoint.hostname && ["A", "AAAA"].includes(record.type))
        .map((record) => ({
          type: record.type,
          name: record.name,
          relativeName: record.relativeName,
          value: record.expectedValue,
          observed: record.observedValue,
          required: record.required,
          status: record.status,
        }))
        .toSorted((a, b) => a.type.localeCompare(b.type)),
    },
    certificate: certificate
      ? {
          status: certificate.status,
          issuer: certificate.issuer,
          expiresAt: certificate.expiresAt?.toISOString() ?? null,
        }
      : null,
    createdAt: route.createdAt.toISOString(),
    updatedAt: route.updatedAt.toISOString(),
  };
}

export type FrontRouteSummary = ReturnType<typeof summarize>;

/** `GET /api/front/routes`: status, listener, pinned target, DNS and certificate state. */
export async function listFrontRoutes(routeId?: string): Promise<FrontRouteSummary[]> {
  const rows = await db
    .select({ route: frontRoutes, endpoint: endpoints })
    .from(frontRoutes)
    .innerJoin(endpoints, eq(endpoints.id, frontRoutes.endpointId))
    .where(routeId ? eq(frontRoutes.id, routeId) : undefined);
  if (!rows.length) return [];
  const [domains, records, certs, policy] = await Promise.all([
    db.select().from(domainClaims),
    db.select().from(dnsRecords),
    db.select().from(certificates),
    edgePolicy(),
  ]);
  const serving = new Set(policy.routes.map((route) => route.id));
  return rows
    .map(({ route, endpoint }) => {
      const domain = domains.find((item) => item.id === endpoint.domainId) ?? null;
      const certificate =
        certs
          .filter((item) => item.endpointId === endpoint.id)
          .toSorted((a, b) => (b.lastDeployedAt?.getTime() ?? 0) - (a.lastDeployedAt?.getTime() ?? 0))[0] ??
        null;
      return summarize(
        route,
        endpoint,
        domain,
        records.filter((record) => record.domainId === endpoint.domainId),
        certificate,
        serving,
      );
    })
    .toSorted((a, b) => a.hostname.localeCompare(b.hostname) || a.id.localeCompare(b.id));
}

// ---- Create -----------------------------------------------------------------------------------

export type RouteCreatePlan = Awaited<ReturnType<typeof prepareRouteCreate>>;

/** Every check for `POST /api/front/routes`, with no writes. Throws `FrontRouteError` or 422s. */
export async function prepareRouteCreate(input: FrontRouteCreateInput) {
  assertSupportedRouteKind(input.kind);
  assertSupportedAccessMode(input.accessMode, "create");
  const hostname = normalizeRouteHostname(input.hostname);
  const domain = routeDomainFor(hostname, await db.select().from(domainClaims));
  if (!domain) {
    throw new FrontRouteError(
      422,
      `No domain claim covers ${hostname}. Add the domain and verify its ownership record first.`,
    );
  }
  if (domain.status !== "verified") {
    throw new FrontRouteError(
      422,
      `The domain ${domain.name} is not verified yet (status ${domain.status}). Publish its ownership record and verify it first.`,
    );
  }
  const platform = await settings();
  if (!platform?.publicIpv4) {
    throw new FrontRouteError(422, "Set the server's public IPv4 address before creating routes.");
  }
  if (hostname === platform.adminHostname || hostname === platform.gateLoginHostname) {
    throw new FrontRouteError(409, `${hostname} is reserved for the Ark administration or login origin.`);
  }
  const [endpoint] = await db.select().from(endpoints).where(eq(endpoints.hostname, hostname));
  if (endpoint && endpoint.kind !== "route") {
    throw new FrontRouteError(409, `${hostname} is already used by the ${endpoint.kind} endpoint.`);
  }
  if (endpoint) {
    const [existing] = await db
      .select({ id: frontRoutes.id })
      .from(frontRoutes)
      .where(and(eq(frontRoutes.endpointId, endpoint.id), eq(frontRoutes.listenPort, HTTP_LISTEN_PORT)));
    if (existing)
      throw new FrontRouteError(409, `${hostname} already has a route on port 443 (${existing.id}).`);
  }
  const redirectTo =
    input.redirectTo == null ? null : normalizeRedirectTo(input.redirectTo, { hostname, zone: domain.name });
  const targetInput = input.target.trim();
  const pinned = await pinTarget(targetInput, input.targetPort, input.allowSensitivePort);
  const records = routeAddressRecords({
    hostname,
    zone: domain.name,
    publicIpv4: platform.publicIpv4,
    publicIpv6: platform.publicIpv6,
    ipv6Status: platform.ipv6Status,
    aaaaEnabled: domain.aaaaEnabled,
    purpose: ROUTE_RECORD_PURPOSE,
  });
  return {
    hostname,
    domain,
    endpoint: endpoint ?? null,
    redirectTo,
    targetInput,
    targetPort: input.targetPort,
    accessMode: "public" as const,
    pinned,
    records,
  };
}

async function writeRecords(domainId: string, records: DnsRecordPlan[]) {
  const existing = await db.select().from(dnsRecords).where(eq(dnsRecords.domainId, domainId));
  for (const record of records) {
    const current = existing.find((item) => item.type === record.type && item.name === record.name);
    if (!current) {
      await db.insert(dnsRecords).values({
        id: createId("dns"),
        domainId,
        type: record.type,
        name: record.name,
        relativeName: record.relativeName,
        expectedValue: record.value,
        purpose: record.purpose,
        required: record.required,
      });
    } else if (current.purpose.startsWith(ROUTE_RECORD_PURPOSE) && current.expectedValue !== record.value) {
      // A leftover route record for an old address: re-check it against the current one.
      await db
        .update(dnsRecords)
        .set({
          expectedValue: record.value,
          required: record.required,
          status: "pending",
          observedValue: null,
        })
        .where(eq(dnsRecords.id, current.id));
    }
  }
}

/**
 * Writes the endpoint, address records and route (`draft`), then hands it to the lifecycle
 * (`awaiting_acl`) and queues the edge-netns probe. Call only after the step-up grant.
 */
export async function commitRouteCreate(plan: RouteCreatePlan, actor: RouteActor, enqueue: RouteEnqueue) {
  const routeId = createId("rt");
  const now = new Date();
  try {
    await db.transaction(async (tx) => {
      let endpointId = plan.endpoint?.id;
      if (!endpointId) {
        endpointId = createId("end");
        await tx.insert(endpoints).values({
          id: endpointId,
          kind: "route",
          hostname: plan.hostname,
          domainId: plan.domain.id,
          exposure: "public",
          status: "awaiting_dns",
        });
      }
      await tx.insert(frontRoutes).values({
        id: routeId,
        kind: "http",
        endpointId,
        listenPort: HTTP_LISTEN_PORT,
        targetInput: plan.targetInput,
        targetNodeStableId: plan.pinned.stableId,
        targetIp: plan.pinned.ip,
        targetPort: plan.targetPort,
        accessMode: plan.accessMode,
        httpOptions: plan.redirectTo ? { redirectTo: plan.redirectTo } : {},
        enabled: false,
        status: "draft",
        createdBy: actor.userId,
        createdAt: now,
        updatedAt: now,
      });
    });
  } catch (error) {
    if (isUniqueViolation(error)) {
      throw new FrontRouteError(409, `${plan.hostname} already has a route or endpoint; reload and retry.`);
    }
    throw error;
  }
  await writeRecords(plan.domain.id, plan.records);
  await auditRoute(actor, "front_route.create", routeId, {
    hostname: plan.hostname,
    domainId: plan.domain.id,
    target: plan.targetInput,
    targetPort: plan.targetPort,
    pinned: plan.pinned,
    accessMode: plan.accessMode,
    redirectTo: plan.redirectTo,
    records: plan.records.map((record) => ({ type: record.type, name: record.name, value: record.value })),
    status: "draft",
  });
  // The ACL snippet goes back with the response; the route now waits for the edge probe.
  await db
    .update(frontRoutes)
    .set({ status: "awaiting_acl", updatedAt: new Date() })
    .where(and(eq(frontRoutes.id, routeId), eq(frontRoutes.status, "draft")));
  const observe = await enqueue({ kind: "edge.observe", targetIds: [EDGE_OBSERVE_TARGET] });
  await auditRoute(
    actor,
    "front_route.awaiting_acl",
    routeId,
    { from: "draft", to: "awaiting_acl", reason: "acl_snippet_issued" },
    idOf(observe),
  );
  return { routeId, observeOperationId: idOf(observe) ?? null };
}

// ---- Update -----------------------------------------------------------------------------------

export type RouteUpdatePlan = Awaited<ReturnType<typeof prepareRouteUpdate>>;

/** Every check for `PATCH /api/front/routes/:id`, with no writes. */
export async function prepareRouteUpdate(routeId: string, input: FrontRouteUpdateInput) {
  const { route, endpoint, domain } = await loadRoute(routeId);
  requireHttp(route);
  if (input.accessMode !== undefined) assertSupportedAccessMode(input.accessMode, "update");
  let redirectTo = redirectOf(route);
  if (input.redirectTo !== undefined) {
    if (input.redirectTo === null) redirectTo = null;
    else {
      if (!domain) throw new FrontRouteError(409, "The route's domain is no longer available.");
      redirectTo = normalizeRedirectTo(input.redirectTo, { hostname: endpoint.hostname, zone: domain.name });
    }
  }
  const targetInput = input.target?.trim() ?? route.targetInput;
  const targetPort = input.targetPort ?? route.targetPort;
  const current = {
    targetInput: route.targetInput,
    targetPort: route.targetPort,
    accessMode: route.accessMode,
    redirectTo: redirectOf(route),
    status: route.status,
  };
  const loosening = looseningChanges(current, {
    targetInput: input.target === undefined ? undefined : targetInput,
    targetPort: input.targetPort,
    accessMode: input.accessMode,
    redirectTo: input.redirectTo === undefined ? undefined : redirectTo,
    allowSensitivePort: input.allowSensitivePort,
  });
  const repin = loosening.some((item) => ["target", "targetPort", "reconfirmTarget"].includes(item));
  const pinned = repin ? await pinTarget(targetInput, targetPort, input.allowSensitivePort) : null;
  const changes: Record<string, { from: unknown; to: unknown }> = {};
  if (targetInput !== route.targetInput) changes.target = { from: route.targetInput, to: targetInput };
  if (targetPort !== route.targetPort) changes.targetPort = { from: route.targetPort, to: targetPort };
  if (input.accessMode !== undefined && input.accessMode !== route.accessMode)
    changes.accessMode = { from: route.accessMode, to: input.accessMode };
  if (redirectTo !== redirectOf(route)) changes.redirectTo = { from: redirectOf(route), to: redirectTo };
  if (pinned && (pinned.stableId !== route.targetNodeStableId || pinned.ip !== route.targetIp))
    changes.pinned = {
      from: { stableId: route.targetNodeStableId, ip: route.targetIp },
      to: { stableId: pinned.stableId, ip: pinned.ip },
    };
  return {
    route,
    endpoint,
    targetInput,
    targetPort,
    accessMode: input.accessMode ?? route.accessMode,
    redirectTo,
    pinned,
    loosening,
    changes,
  };
}

/** Applies a prepared update, re-pins and restarts the lifecycle at `awaiting_acl` on a new target. */
export async function commitRouteUpdate(plan: RouteUpdatePlan, actor: RouteActor, enqueue: RouteEnqueue) {
  const { route } = plan;
  const status = plan.pinned ? "awaiting_acl" : route.status;
  const httpOptions = { ...route.httpOptions };
  if (plan.redirectTo) httpOptions.redirectTo = plan.redirectTo;
  else delete httpOptions.redirectTo;
  await db
    .update(frontRoutes)
    .set({
      targetInput: plan.targetInput,
      targetPort: plan.targetPort,
      targetNodeStableId: plan.pinned?.stableId ?? route.targetNodeStableId,
      targetIp: plan.pinned?.ip ?? route.targetIp,
      accessMode: plan.accessMode,
      httpOptions,
      status,
      lastError: plan.pinned ? null : route.lastError,
      updatedAt: new Date(),
    })
    .where(eq(frontRoutes.id, route.id));
  const live = route.enabled && route.status === "ready";
  const apply = await enqueue({ kind: "edge.apply", targetIds: ["platform"] });
  if (live && plan.pinned) {
    // The old backend stops serving now, not at the next observation.
    await enqueue({
      kind: "edge.drain",
      targetIds: ["edge:drain"],
      payload: {
        reason: "route_updated",
        routeIds: [route.id],
        backends: [backendKey(route.targetIp, route.targetPort)],
      },
    });
  }
  await auditRoute(
    actor,
    "front_route.update",
    route.id,
    { changes: plan.changes, loosening: plan.loosening },
    idOf(apply),
  );
  if (status !== route.status) {
    const observe = await enqueue({ kind: "edge.observe", targetIds: [EDGE_OBSERVE_TARGET] });
    await auditRoute(
      actor,
      "front_route.awaiting_acl",
      route.id,
      { from: route.status, to: status, reason: "target_changed" },
      idOf(observe),
    );
  } else if (plan.pinned) {
    await enqueue({ kind: "edge.observe", targetIds: [EDGE_OBSERVE_TARGET] });
  }
  return { status };
}

// ---- Enable, disable, delete ------------------------------------------------------------------

/** Checks for `enable`: an implemented access mode, and a `ready` route that is not yet enabled. */
export async function prepareRouteEnable(routeId: string) {
  const { route, endpoint } = await loadRoute(routeId);
  requireHttp(route);
  if (route.enabled) throw new FrontRouteError(409, "The route is already enabled.");
  assertSupportedAccessMode(route.accessMode, "enable");
  if (route.status !== "ready") {
    throw new FrontRouteError(
      409,
      `The route is ${route.status}; it can be enabled once it is ready (ACL probe, DNS and certificate complete).`,
    );
  }
  return { route, endpoint };
}

export async function commitRouteEnable(
  plan: Awaited<ReturnType<typeof prepareRouteEnable>>,
  actor: RouteActor,
  enqueue: RouteEnqueue,
) {
  const updated = await db
    .update(frontRoutes)
    .set({ enabled: true, updatedAt: new Date() })
    .where(
      and(eq(frontRoutes.id, plan.route.id), eq(frontRoutes.status, "ready"), eq(frontRoutes.enabled, false)),
    )
    .returning({ id: frontRoutes.id });
  if (!updated.length) throw new FrontRouteError(409, "The route changed state; reload and retry.");
  const apply = await enqueue({ kind: "edge.apply", targetIds: ["platform"] });
  await auditRoute(
    actor,
    "front_route.enable",
    plan.route.id,
    { hostname: plan.endpoint.hostname, accessMode: plan.route.accessMode },
    idOf(apply),
  );
}

/** Disabling only tightens exposure: no step-up, and the backend is drained at once. */
export async function disableRoute(routeId: string, actor: RouteActor, enqueue: RouteEnqueue) {
  const { route, endpoint } = await loadRoute(routeId);
  requireHttp(route);
  if (!route.enabled) throw new FrontRouteError(409, "The route is already disabled.");
  await db
    .update(frontRoutes)
    .set({ enabled: false, updatedAt: new Date() })
    .where(eq(frontRoutes.id, route.id));
  const apply = await enqueue({ kind: "edge.apply", targetIds: ["platform"] });
  await enqueue({
    kind: "edge.drain",
    targetIds: ["edge:drain"],
    payload: {
      reason: "route_disabled",
      routeIds: [route.id],
      backends: [backendKey(route.targetIp, route.targetPort)],
    },
  });
  await auditRoute(
    actor,
    "front_route.disable",
    route.id,
    { hostname: endpoint.hostname, status: route.status },
    idOf(apply),
  );
}

export async function prepareRouteDelete(routeId: string) {
  return loadRoute(routeId);
}

/**
 * Removes the route and drains it. The endpoint, its certificates and its route address records go
 * too unless another route still uses the endpoint. Provider-side DNS records are not deleted here;
 * exact, reviewed provider deletes arrive with FD-19.
 */
export async function commitRouteDelete(
  plan: Awaited<ReturnType<typeof prepareRouteDelete>>,
  actor: RouteActor,
  enqueue: RouteEnqueue,
) {
  const { route, endpoint } = plan;
  const removedEndpoint = await db.transaction(async (tx) => {
    await tx.delete(frontRoutes).where(eq(frontRoutes.id, route.id));
    const others = await tx
      .select({ id: frontRoutes.id })
      .from(frontRoutes)
      .where(eq(frontRoutes.endpointId, endpoint.id));
    if (others.length || endpoint.kind !== "route") return false;
    if (endpoint.domainId) {
      await tx
        .delete(dnsRecords)
        .where(
          and(
            eq(dnsRecords.domainId, endpoint.domainId),
            eq(dnsRecords.name, endpoint.hostname),
            like(dnsRecords.purpose, `${ROUTE_RECORD_PURPOSE}%`),
          ),
        );
    }
    await tx.delete(certificates).where(eq(certificates.endpointId, endpoint.id));
    await tx.delete(endpoints).where(eq(endpoints.id, endpoint.id));
    return true;
  });
  const apply = await enqueue({ kind: "edge.apply", targetIds: ["platform"] });
  await enqueue({
    kind: "edge.drain",
    targetIds: ["edge:drain"],
    payload: {
      reason: "route_deleted",
      routeIds: [route.id],
      backends: [backendKey(route.targetIp, route.targetPort)],
    },
  });
  await auditRoute(
    actor,
    "front_route.delete",
    route.id,
    {
      hostname: endpoint.hostname,
      status: route.status,
      enabled: route.enabled,
      target: route.targetInput,
      targetPort: route.targetPort,
      endpointRemoved: removedEndpoint,
    },
    idOf(apply),
  );
  return { endpointRemoved: removedEndpoint };
}

// ---- Lifecycle hooks for domain.verify and certificate.issue ----------------------------------

async function routesOn(endpointId: string) {
  return db.select().from(frontRoutes).where(eq(frontRoutes.endpointId, endpointId));
}

/**
 * Called by `domain.verify` for a `route` endpoint. When every required address record resolves
 * to this server, routes in `awaiting_dns` move to `issuing_certificate` and the caller requests a
 * certificate; before that, nothing is requested and the route records what DNS still shows.
 */
export async function routesAfterDnsCheck(input: {
  endpointId: string;
  verified: boolean;
  pending: Array<{ type: string; name: string; expected: string; observed: string }>;
  operationId?: string;
}) {
  const routes = await routesOn(input.endpointId);
  let issue = false;
  for (const route of routes) {
    if (route.status === "issuing_certificate") issue = true;
    if (route.status !== "awaiting_dns") continue;
    if (input.verified) {
      await db
        .update(frontRoutes)
        .set({ status: "issuing_certificate", lastError: null, updatedAt: new Date() })
        .where(and(eq(frontRoutes.id, route.id), eq(frontRoutes.status, "awaiting_dns")));
      await auditRoute(
        null,
        "front_route.issuing_certificate",
        route.id,
        { from: "awaiting_dns", to: "issuing_certificate", reason: "dns_resolves" },
        input.operationId,
      );
      issue = true;
      continue;
    }
    const first = input.pending[0];
    const lastError = first
      ? `Waiting for DNS: ${first.type} ${first.name} must resolve to ${first.expected} (observed: ${first.observed || "nothing"}).`
      : "Waiting for DNS: the route hostname has no address record to check.";
    if (lastError !== route.lastError) {
      await db
        .update(frontRoutes)
        .set({ lastError, updatedAt: new Date() })
        .where(eq(frontRoutes.id, route.id));
    }
  }
  return { issueCertificate: issue };
}

/**
 * Called by `certificate.issue` for a `route` endpoint. A publicly trusted certificate completes
 * the DNS/certificate part; the caller then queues `edge.observe`, whose fresh probe makes the
 * route `ready`. An untrusted (staging or local) certificate is never served, so the route stays.
 */
export async function routesAfterCertificate(input: {
  endpointId: string;
  status: string;
  issuer: string;
  operationId?: string;
}) {
  const routes = (await routesOn(input.endpointId)).filter((route) => route.status === "issuing_certificate");
  if (!routes.length) return { observe: false };
  const lastError =
    input.status === "issued"
      ? null
      : `The certificate from ${input.issuer} is not publicly trusted, so the edge will not serve it. Set ARK_ACME_STAGING=0, then verify the domain again to reissue.`;
  for (const route of routes) {
    await db
      .update(frontRoutes)
      .set({ lastError, updatedAt: new Date() })
      .where(eq(frontRoutes.id, route.id));
    await auditRoute(
      null,
      "front_route.certificate_issued",
      route.id,
      { issuer: input.issuer, certificateStatus: input.status },
      input.operationId,
    );
  }
  return { observe: input.status === "issued" };
}

/** Records a failed issuance on the waiting routes; `POST /api/domains/:id/verify` retries it. */
export async function routesCertificateFailed(endpointId: string, message: string) {
  const routes = (await routesOn(endpointId)).filter((route) => route.status === "issuing_certificate");
  for (const route of routes) {
    await db
      .update(frontRoutes)
      .set({
        lastError: `Certificate issuance failed: ${message.slice(0, 500)}. Verify the domain again to retry.`,
        updatedAt: new Date(),
      })
      .where(eq(frontRoutes.id, route.id));
  }
}
