// Edge observer and identity pinning (docs/design/front-door.md §3.2, §3.6, FD-06).
//
// `edge.observe` reads the edge node's LocalAPI status (read-only), commits the self node and the
// entire peer set as one complete `edge` generation, deletes peers absent from it in the same
// transaction, and sets the lease (`valid_until`, six minutes from completion). A failed or partial
// read changes nothing, so it can never renew the lease. Every route is then re-validated against
// the new generation; routes that lose their identity are withdrawn durably (`edge.apply` re-renders
// without them and `edge.drain` withdraws them from the running proxies), and the edge-local
// watchdog enforces the same allowlist every second from `edgePolicy`, even when no worker runs.

import {
  EDGE_OBSERVE_INTERVAL_MS,
  backendKey,
  createId,
  leaseValidityMs,
  parseLocalApiStatus,
  redactValue,
  revalidateRouteTarget,
  tailnetSuffixOf,
  type EdgeLeaseDocument,
  type EdgePolicyRoute,
  type OperationKind,
  type RouteRevalidation,
  type TailnetNode,
} from "@ark-stack/shared";
import { desc, eq } from "drizzle-orm";

import { db } from "../db.ts";
import { auditEvents, certificates, endpoints, frontRoutes, operations } from "../schema.ts";
import { currentRoute, routeVersion } from "./front-route-state.ts";
import { l4RoutePolicy, revokedSerials, storedL4Settings } from "./l4-routes.ts";
import type { EdgeLocalApi, ProbeResult } from "./tailnet-localapi.ts";
import {
  commitTailnetGeneration,
  loadTailnetSnapshot,
  snapshotLeaseValid,
  type LoadedSnapshot,
} from "./tailnet-snapshot.ts";

type Enqueue = (input: {
  kind: OperationKind;
  targetIds: string[];
  payload?: Record<string, unknown>;
}) => Promise<unknown>;

/** Statuses `edge.observe` owns. `identity_mismatch` is sticky until the owner re-confirms (FD-08). */
const OBSERVED_STATUSES = new Set(["awaiting_acl", "ready", "observation_expired"]);
/**
 * Route lifecycle (FD-08): draft -> awaiting_acl -> awaiting_dns -> issuing_certificate -> ready.
 * The probe is the only evidence of an outbound grant, so this observer is the only writer of
 * `ready`: a passing probe moves `awaiting_acl` on to `awaiting_dns` (and queues `domain.verify`)
 * until the hostname has an issued certificate, and `issuing_certificate` to `ready` once it has.
 */
/** Lifecycle statuses owned by DNS and certificate work (FD-08); transient failures keep the lifecycle position; identity mismatch remains sticky. */
const LIFECYCLE_STATUSES = new Set(["awaiting_dns", "issuing_certificate"]);
const LIFECYCLE_OBSERVATION_ERROR = "Edge observation: ";

export const EDGE_OBSERVE_TARGET = "tailnet:edge";

type RouteRow = typeof frontRoutes.$inferSelect & {
  hostname: string;
  domainId: string | null;
  version: string;
};

/** The persisted `edge` snapshot and its nodes. */
export function loadEdgeSnapshot() {
  return loadTailnetSnapshot("edge");
}

type Loaded = LoadedSnapshot;

async function loadRoutes(): Promise<RouteRow[]> {
  const rows = await db
    .select({
      route: frontRoutes,
      hostname: endpoints.hostname,
      domainId: endpoints.domainId,
      version: routeVersion,
    })
    .from(frontRoutes)
    .innerJoin(endpoints, eq(endpoints.id, frontRoutes.endpointId));
  return rows.map((row) => ({
    ...row.route,
    hostname: row.hostname,
    domainId: row.domainId,
    version: row.version,
  }));
}

/**
 * Endpoints whose current certificate (the most recently deployed row, as the edge selects it) is
 * `issued` and unexpired: the DNS and certificate part of a route's lifecycle is complete.
 */
export async function endpointsWithServableCertificate(now = new Date()) {
  const latest = new Map<string, typeof certificates.$inferSelect>();
  for (const row of await db.select().from(certificates)) {
    const current = latest.get(row.endpointId);
    if (!current || (row.lastDeployedAt?.getTime() ?? 0) > (current.lastDeployedAt?.getTime() ?? 0))
      latest.set(row.endpointId, row);
  }
  const servable = new Set<string>();
  for (const [endpointId, row] of latest) {
    if (row.status === "issued" && (!row.expiresAt || row.expiresAt.getTime() > now.getTime()))
      servable.add(endpointId);
  }
  return servable;
}

function revalidate(route: RouteRow, loaded: Loaded, now: Date): RouteRevalidation {
  return revalidateRouteTarget({
    route: {
      targetInput: route.targetInput,
      targetNodeStableId: route.targetNodeStableId,
      targetIp: route.targetIp,
    },
    peers: loaded.peers,
    snapshot: loaded.snapshot,
    self: loaded.self,
    now,
    tailnetSuffix: loaded.self ? tailnetSuffixOf(loaded.self) : "",
    source: "edge",
  });
}

const leaseValid = snapshotLeaseValid;

/**
 * The allowlist every proxy enforces (§3.2): enabled `ready` routes whose pinned StableID and IP
 * still match the latest complete generation, while its lease is valid. Re-validating here, not
 * only in the worker, means a replaced identity is withdrawn as soon as its generation commits.
 */
export async function edgePolicy(
  now = new Date(),
): Promise<EdgeLeaseDocument & { routes: EdgePolicyRoute[] }> {
  const loaded = await loadEdgeSnapshot();
  const valid = leaseValid(loaded, now);
  const routes: EdgePolicyRoute[] = [];
  if (valid) {
    const live = (await loadRoutes()).filter((route) => route.enabled && route.status === "ready");
    // TLS-TCP and raw-TCP routes (FD-14) carry their admission policy in the identity, so a policy
    // change or a client certificate revocation fences and drains their old servers everywhere.
    const revoked = await revokedSerials(
      live.flatMap((route) =>
        route.tlsMode === "terminate_mtls" && route.clientCaId ? [route.clientCaId] : [],
      ),
    );
    for (const route of live) {
      const check = revalidate(route, loaded, now);
      if (!check.ok || check.ip !== route.targetIp) continue;
      let policy: string | undefined;
      if (route.kind === "tls" || route.kind === "tcp") {
        const settings = storedL4Settings(route);
        // Invalid stored settings, or an unconfirmed open route: never allowed (fail closed). An
        // empty list stays allowed and renders deny-all (the route admits nobody).
        if (!settings || (settings.allowInternet && !route.internetConfirmedAt)) continue;
        policy = l4RoutePolicy(settings, revoked);
      }
      routes.push({
        id: route.id,
        kind: route.kind,
        hostname: route.hostname,
        ip: route.targetIp,
        port: route.targetPort,
        stableId: route.targetNodeStableId,
        ...(policy ? { policy } : {}),
      });
    }
  }
  return {
    now: now.toISOString(),
    lease: loaded.row
      ? {
          generation: loaded.row.generation,
          completedAt: loaded.row.completedAt.toISOString(),
          validUntil: loaded.row.validUntil.toISOString(),
          valid,
        }
      : null,
    routes: routes.toSorted((a, b) => a.id.localeCompare(b.id)),
  };
}

async function audit(action: string, routeId: string, detail: Record<string, unknown>, operationId?: string) {
  await db.insert(auditEvents).values({
    id: createId("aud"),
    action,
    resourceType: "front_route",
    resourceId: routeId,
    operationId,
    detail: redactValue(detail) as Record<string, unknown>,
  });
}

/**
 * Durable withdrawal: re-render without the routes and drain them from the running proxies. The
 * watchdog already enforces the allowlist; these operations make the rendered files agree and
 * survive a worker restart.
 */
async function withdraw(
  enqueue: Enqueue,
  routes: Array<{ id: string; ip: string; port: number }>,
  reason: string,
) {
  await enqueue({ kind: "edge.apply", targetIds: ["platform"] });
  if (!routes.length) return;
  await enqueue({
    kind: "edge.drain",
    targetIds: ["edge:drain"],
    payload: {
      reason,
      routeIds: routes.map((route) => route.id).toSorted(),
      backends: routes.map((route) => backendKey(route.ip, route.port)).toSorted(),
    },
  });
}

/**
 * When the lease has expired, live routes become `observation_expired` and are withdrawn. Called
 * before every observation and after a failed one; the watchdog does not wait for it.
 */
export async function expireStaleEdgeRoutes(input: { enqueue: Enqueue; now?: Date; operationId?: string }) {
  const now = input.now ?? new Date();
  const loaded = await loadEdgeSnapshot();
  if (leaseValid(loaded, now)) return [];
  const expired = (await loadRoutes()).filter((route) => route.status === "ready");
  if (!expired.length) return [];
  const committed: RouteRow[] = [];
  for (const route of expired) {
    const changed = await db
      .update(frontRoutes)
      .set({
        status: "observation_expired",
        lastError: "The edge node's tailnet observation expired; the route is withdrawn until it is renewed.",
        updatedAt: now,
      })
      .where(currentRoute(route.id, route.version))
      .returning({ id: frontRoutes.id });
    if (!changed.length) continue;
    committed.push(route);
    await audit(
      "front_route.observation_expired",
      route.id,
      { validUntil: loaded.row?.validUntil ?? null },
      input.operationId,
    );
  }
  await withdraw(
    input.enqueue,
    committed.map((route) => ({ id: route.id, ip: route.targetIp, port: route.targetPort })),
    "observation_expired",
  );
  return committed.map((route) => route.id);
}

function commitGeneration(input: {
  generation: string;
  self: TailnetNode;
  peers: TailnetNode[];
  completedAt: Date;
  validUntil: Date;
}) {
  return commitTailnetGeneration("edge", input);
}

export type RouteOutcome = {
  id: string;
  hostname: string;
  from: string;
  to: string;
  ip: string;
  ipChanged: boolean;
  probe?: ProbeResult;
  reason?: string;
};

/** Re-validates every route against the committed generation (§3.2 rule 6) and probes ready candidates. */
async function revalidateRoutes(input: {
  api: EdgeLocalApi;
  enqueue: Enqueue;
  now: Date;
  operationId?: string;
}) {
  const loaded = await loadEdgeSnapshot();
  const outcomes: RouteOutcome[] = [];
  const withdrawn: Array<{ id: string; ip: string; port: number }> = [];
  let renderChanged = false;
  const probes = new Map<string, Promise<ProbeResult>>();
  const servable = await endpointsWithServableCertificate(input.now);
  const verifyDomains = new Set<string>();
  for (const route of await loadRoutes()) {
    if (!OBSERVED_STATUSES.has(route.status) && !LIFECYCLE_STATUSES.has(route.status)) continue;
    const check = revalidate(route, loaded, input.now);
    let status = route.status;
    let lastError: string | null = route.lastError;
    let ip = route.targetIp;
    let probe: ProbeResult | undefined;
    if (!check.ok) {
      status =
        LIFECYCLE_STATUSES.has(route.status) && check.status !== "identity_mismatch"
          ? route.status
          : check.status;
      lastError = LIFECYCLE_STATUSES.has(status)
        ? `${LIFECYCLE_OBSERVATION_ERROR}${check.message}`
        : check.message;
    } else {
      ip = check.ip;
      // Only clear errors owned by this observer; DNS/certificate diagnostics belong to their worker.
      if (LIFECYCLE_STATUSES.has(route.status) && lastError?.startsWith(LIFECYCLE_OBSERVATION_ERROR))
        lastError = null;
      const certified = servable.has(route.endpointId);
      if (OBSERVED_STATUSES.has(route.status) || (route.status === "issuing_certificate" && certified)) {
        const key = backendKey(check.ip, route.targetPort);
        if (!probes.has(key)) probes.set(key, input.api.probe(check.ip, route.targetPort));
        probe = await probes.get(key)!;
        // A route that loses its usable certificate re-enters DNS/certificate repair.
        status = !probe.ok ? "awaiting_acl" : certified ? "ready" : "awaiting_dns";
        lastError = probe.ok
          ? null
          : `The edge cannot open TCP to ${key} (${probe.detail}). Check the tailnet grant for this port.`;
      }
      // DNS is re-checked on every observation until it resolves (the five-minute schedule).
    }
    const ipChanged = ip !== route.targetIp;
    // Even a no-change probe must compare the snapshot before emitting follow-up work.
    const changed = await db
      .update(frontRoutes)
      .set({ status, targetIp: ip, lastError, updatedAt: input.now })
      .where(currentRoute(route.id, route.version))
      .returning({ id: frontRoutes.id });
    if (!changed.length) continue;
    if (check.ok && status === "awaiting_dns" && route.domainId) verifyDomains.add(route.domainId);
    const live = route.enabled && route.status === "ready";
    if (live && (status !== "ready" || ipChanged)) {
      withdrawn.push({ id: route.id, ip: route.targetIp, port: route.targetPort });
    }
    if (route.enabled && (status === "ready") !== live) renderChanged = true;
    if (ipChanged) {
      await audit(
        "front_route.target_ip_changed",
        route.id,
        { stableId: route.targetNodeStableId, from: route.targetIp, to: ip },
        input.operationId,
      );
    }
    if (status !== route.status) {
      await audit(
        `front_route.${status}`,
        route.id,
        { from: route.status, to: status, reason: check.ok ? (probe?.detail ?? null) : check.reason },
        input.operationId,
      );
    }
    outcomes.push({
      id: route.id,
      hostname: route.hostname,
      from: route.status,
      to: status,
      ip,
      ipChanged,
      probe,
      reason: check.ok ? undefined : check.reason,
    });
  }
  if (withdrawn.length || renderChanged) {
    await withdraw(input.enqueue, withdrawn, "identity");
  }
  for (const domainId of [...verifyDomains].toSorted()) {
    await input.enqueue({
      kind: "domain.verify",
      targetIds: [domainId],
      payload: { routeEndpointsOnly: true },
    });
  }
  return { outcomes, withdrawn: withdrawn.map((route) => route.id) };
}

/**
 * One `edge.observe` run. Throws on a failed or partial observation, after withdrawing routes if
 * the existing lease has already expired; the stored snapshot is left untouched.
 */
export async function observeEdgeTailnet(input: {
  api: EdgeLocalApi;
  enqueue: Enqueue;
  now?: () => Date;
  operationId?: string;
  validityMs?: number;
}) {
  const clock = input.now ?? (() => new Date());
  const startedAt = clock();
  const expired = await expireStaleEdgeRoutes({
    enqueue: input.enqueue,
    now: startedAt,
    operationId: input.operationId,
  });
  const generation = createId("gen");
  let parsed: ReturnType<typeof parseLocalApiStatus>;
  try {
    parsed = parseLocalApiStatus(await input.api.status(), { generation });
  } catch (error) {
    parsed = { ok: false, reason: `LocalAPI status could not be read: ${(error as Error).message}` };
  }
  if (!parsed.ok) {
    throw new Error(`Edge observation failed; the lease was not renewed. ${parsed.reason}`);
  }
  // The lease counts from when the read started, never from when it was committed.
  const validUntil = new Date(startedAt.getTime() + (input.validityMs ?? leaseValidityMs()));
  await commitGeneration({
    generation,
    self: parsed.self,
    peers: parsed.peers,
    completedAt: startedAt,
    validUntil,
  });
  const routes = await revalidateRoutes({
    api: input.api,
    enqueue: input.enqueue,
    now: clock(),
    operationId: input.operationId,
  });
  return {
    generation,
    completedAt: startedAt.toISOString(),
    validUntil: validUntil.toISOString(),
    self: { stableId: parsed.self.stableId, dnsName: parsed.self.dnsName, tags: parsed.self.tags },
    peers: parsed.peers.length,
    expiredBeforeObservation: expired,
    routes: routes.outcomes.map(({ id, from, to, ipChanged, probe, reason }) => ({
      id,
      from,
      to,
      ipChanged,
      probe: probe?.detail,
      reason,
    })),
    withdrawn: routes.withdrawn,
  };
}

function publicNode(item: TailnetNode) {
  return {
    stableId: item.stableId,
    dnsName: item.dnsName,
    hostName: item.hostName,
    ipv4: item.ipv4,
    ipv6: item.ipv6,
    tags: item.tags,
    online: item.online,
  };
}

/** `GET /api/front/tailnet`: the latest generation and every route's identity state. */
export async function tailnetOverview(now = new Date()) {
  const loaded = await loadEdgeSnapshot();
  const valid = leaseValid(loaded, now);
  const [lastRun] = await db
    .select({
      id: operations.id,
      status: operations.status,
      error: operations.error,
      updatedAt: operations.updatedAt,
    })
    .from(operations)
    .where(eq(operations.kind, "edge.observe"))
    .orderBy(desc(operations.createdAt))
    .limit(1);
  const policy = await edgePolicy(now);
  const allowed = new Set(policy.routes.map((route) => route.id));
  return {
    generation: loaded.row
      ? {
          id: loaded.row.generation,
          completedAt: loaded.row.completedAt.toISOString(),
          validUntil: loaded.row.validUntil.toISOString(),
          leaseValid: valid,
        }
      : null,
    self: loaded.self ? publicNode(loaded.self) : null,
    tailnetSuffix: loaded.self ? tailnetSuffixOf(loaded.self) : null,
    peers: loaded.peers.map(publicNode).toSorted((a, b) => a.dnsName.localeCompare(b.dnsName)),
    lastObservation: lastRun
      ? {
          operationId: lastRun.id,
          status: lastRun.status,
          error: lastRun.error,
          at: lastRun.updatedAt.toISOString(),
        }
      : null,
    routes: (await loadRoutes())
      .map((route) => {
        const check = revalidate(route, loaded, now);
        return {
          id: route.id,
          kind: route.kind,
          hostname: route.hostname,
          status: route.status,
          enabled: route.enabled,
          targetInput: route.targetInput,
          pinned: { stableId: route.targetNodeStableId, ip: route.targetIp, port: route.targetPort },
          identity: check.ok ? (check.ipChanged ? "ip_changed" : "ok") : check.status,
          identityMessage: check.ok ? null : check.message,
          serving: allowed.has(route.id),
          lastError: route.lastError,
        };
      })
      .toSorted((a, b) => a.hostname.localeCompare(b.hostname)),
  };
}

/**
 * Enqueues `edge.observe` now and every five minutes (§3.4). Run by the domain worker when the
 * edge-ts socket is mounted, and by the embedded coordinator in development. A queued or running
 * observation is reused, so a stopped worker does not pile up duplicates.
 */
export function startEdgeObserveSchedule(input: {
  enqueue: Enqueue;
  intervalMs?: number;
  log?: (line: string) => void;
}) {
  const intervalMs = input.intervalMs ?? EDGE_OBSERVE_INTERVAL_MS;
  const run = () =>
    void input
      .enqueue({ kind: "edge.observe", targetIds: [EDGE_OBSERVE_TARGET] })
      .catch((error: Error) => input.log?.(`edge.observe could not be scheduled: ${error.message}`));
  run();
  return setInterval(run, intervalMs);
}
