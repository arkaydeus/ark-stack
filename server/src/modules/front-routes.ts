// Route lifecycle (docs/design/front-door.md §3.3, §3.8, §3.13, §3.14, FD-08, FD-14, FD-26).
//
// Owners create, update, enable, disable and delete public routes to tailnet services: `http`
// routes (Caddy behind the 443 SNI router), `tls` routes (TLS-TCP by SNI on 443 or an enabled shared
// SNI port: passthrough, terminate or terminate_mtls), `tcp` routes (raw TCP, `plain`, on a
// dedicated port from 20000-20049) and `postgres` routes (direct-TLS PostgreSQL by SNI on 5432,
// passthrough for PG >= 17 or edge termination with ALPN postgresql, and an opt-in compatibility port
// from the raw range for passthrough routes). Every kind shares one lifecycle. A route
// moves through `draft -> awaiting_acl -> awaiting_dns -> issuing_certificate -> ready`:
//
// - draft: creation audit state; persisted atomically with endpoint, DNS and awaiting_acl.
// - awaiting_acl: the ACL snippet was handed out; waiting for the edge-netns TCP probe that
//   `edge.observe` runs (FD-06). Netmap presence alone is never enough.
// - awaiting_dns: the probe passed; `domain.verify` checks that the A (and gated AAAA) record
//   resolves to this server. The observer re-queues a route-only check until it does.
// - issuing_certificate: DNS resolves to `public_ipv4`; `certificate.issue` was queued. Certificates
//   are never requested before this point.
// - ready: an issued certificate and a fresh passing probe. Only `edge.observe` writes `ready`.
//
// `enable` is refused before `ready`. `edge.apply` renders enabled `ready` HTTP routes allowed by
// the lease into Caddy (FD-09): `public` routes directly and `sso` routes (the default) behind the
// login gate (FD-11) with their bypass paths and Origin exceptions. Tightening the gate records
// a revocation in the same transaction (§3.9.3). `edge.l4_apply` renders `tls`, `tcp` and `postgres`
// routes into HAProxy (FD-14, FD-26, modules/l4-routes.ts, shared/src/edge-l4.ts).
//
// L4 routes deny every source until their `sourceCidrs` list says otherwise (empty = deny all).
// Enabling an L4 route with an empty list is refused; `allowInternet` opens it to every source only
// when saved under the owner's exposure.public step-up (`internet_confirmed_at`). Any change to an
// L4 route's admission policy renames its HAProxy servers (the lease fingerprint), so a live route's
// old sessions are drained in every HAProxy worker.
//
// HTTP routes may also carry a per-client rate limit and require client certificates (FD-23). An
// HTTP mTLS route has its own `http-client` CA (`client_ca_id`), created with the route or when mTLS
// is switched on, and retired when it is switched off. Caddy admits exactly the CA's unrevoked,
// unexpired certificates, so issuing one re-renders the edge, and revoking one goes through the gate
// revocation journal: the route's sessions are drained around the forced reload that drops it.
//
// Preparation validates without writes; final validation and grant consumption share the mutation
// transaction, so conflicts roll back the grant. Every action is audited.

import {
  HTTP_LISTEN_PORT,
  ROUTE_RECORD_PURPOSE,
  assertFieldsForKind,
  assertL4Enableable,
  assertSupportedAccessMode,
  assertSupportedRouteKind,
  backendKey,
  checkL4RouteSettings,
  l4LooseningChanges,
  routeListenPort,
  type L4RouteSettings,
  type SupportedRouteKind,
  checkGateRouteSettings,
  createId,
  HTTP_CLIENT_CERTIFICATE_LIMIT,
  httpRateLimit,
  type HttpRateLimit,
  planHash,
  looseningChanges,
  normalizeRedirectTo,
  normalizeRouteHostname,
  redactValue,
  routeAddressRecords,
  routeDomainFor,
  tailnetSuffixOf,
  validateRouteTarget,
  type FrontRouteCreateInput,
  type FrontRouteUpdateInput,
  type OperationKind,
} from "@ark-stack/shared";
import { and, desc, eq, gt, sql as statement } from "drizzle-orm";

import { db, type DbTransaction } from "../db.ts";
import {
  auditEvents,
  certificates,
  clientCertificates,
  dnsRecords,
  domainClaims,
  endpoints,
  frontRoutes,
  platformSettings,
  privateCas,
  operations,
} from "../schema.ts";
import { currentRoute, routeVersion } from "./front-route-state.ts";
import {
  endpointDnsScope,
  desiredDns,
  ensureEndpointDnsRecords,
  lockedDnsDomain,
  pendingWithdrawal,
  retireDnsRecord,
} from "./domain-dns.ts";
import { EDGE_OBSERVE_TARGET, edgePolicy, loadEdgeSnapshot } from "./edge-observe.ts";
import { enabledSniPorts, isL4Kind, storedL4Settings } from "./l4-routes.ts";
import * as pki from "./pki.ts";

export type RouteEnqueue = (input: {
  kind: OperationKind;
  targetIds: string[];
  payload?: Record<string, unknown>;
}) => Promise<unknown>;

export type RouteAuthorize = (tx: DbTransaction) => Promise<unknown>;

export type RouteActor = { userId: string; role: string };

/** A refusal with an HTTP status; rejected transactional mutations roll back grant consumption. */
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

function allowedOriginsOf(route: Pick<RouteRow, "httpOptions">) {
  const value = route.httpOptions?.allowedOrigins;
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

/** The stored rate limit of an HTTP route (FD-23), or undefined when the stored value is invalid. */
function storedRateLimit(route: Pick<RouteRow, "rateLimit">): HttpRateLimit | null | undefined {
  try {
    return httpRateLimit(route.rateLimit);
  } catch {
    return undefined;
  }
}

/** Validates a requested rate limit as a request error (422). */
function requestedRateLimit(value: unknown) {
  try {
    return httpRateLimit(value);
  } catch (error) {
    throw new FrontRouteError(422, (error as Error).message);
  }
}

/** HTTP mTLS (FD-23): the route's own client CA with a first (empty) CRL, in the caller's transaction. */
async function createHttpClientCa(routeId: string, tx: DbTransaction) {
  const ca = await pki.createPrivateCa({ purpose: "http-client", name: `Route ${routeId}` }, tx);
  await pki.generateCaCrl({ caId: ca.id }, tx);
  return ca;
}

/** Retires a route's client CA once no route uses it (deletion, or HTTP mTLS switched off). */
async function retireRouteCa(tx: DbTransaction, caId: string) {
  const [shared] = await tx
    .select({ id: frontRoutes.id })
    .from(frontRoutes)
    .where(eq(frontRoutes.clientCaId, caId))
    .limit(1);
  if (!shared) await tx.update(privateCas).set({ status: "retired" }).where(eq(privateCas.id, caId));
}

/** Bypass paths and Origin exceptions belong to SSO routes only (§3.9.4, §3.9.5). */
function gateSettings(
  accessMode: "public" | "sso",
  input: { bypassPaths?: unknown; allowedOrigins?: unknown },
  current: { bypassPaths: string[]; allowedOrigins: string[] },
) {
  let checked: ReturnType<typeof checkGateRouteSettings>;
  try {
    checked = checkGateRouteSettings(input);
  } catch (error) {
    throw new FrontRouteError(422, (error as Error).message);
  }
  const bypassPaths = checked.bypassPaths ?? current.bypassPaths;
  const allowedOrigins = checked.allowedOrigins ?? current.allowedOrigins;
  if (accessMode === "public" && (bypassPaths.length || allowedOrigins.length))
    throw new FrontRouteError(
      422,
      'Bypass paths and allowed origins apply only to access mode "sso"; clear them for a public route.',
    );
  return { bypassPaths, allowedOrigins };
}

export async function auditRoute(
  actor: RouteActor | null,
  action: string,
  routeId: string,
  detail: Record<string, unknown>,
  operationId?: string,
  executor: Pick<typeof db, "insert"> = db,
) {
  await executor.insert(auditEvents).values({
    id: createId("aud"),
    createdAt: statement`clock_timestamp()`,
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
    .select({ route: frontRoutes, endpoint: endpoints, version: routeVersion })
    .from(frontRoutes)
    .innerJoin(endpoints, eq(endpoints.id, frontRoutes.endpointId))
    .where(eq(frontRoutes.id, routeId));
  if (!row) throw new FrontRouteError(404, "Route not found.");
  const [domain] = row.endpoint.domainId
    ? await db.select().from(domainClaims).where(eq(domainClaims.id, row.endpoint.domainId))
    : [];
  return { route: row.route, endpoint: row.endpoint, domain: domain ?? null, version: row.version };
}

function requireManaged(route: RouteRow) {
  if (route.kind !== "http" && !isL4Kind(route.kind)) {
    throw new FrontRouteError(422, `Route kind "${route.kind}" is not managed by this API yet.`);
  }
}

/** Refusals from the shared L4 rules are request errors (422), not server faults. */
function l4Check<T>(work: () => T): T {
  try {
    return work();
  } catch (error) {
    if (error instanceof FrontRouteError) throw error;
    if (error instanceof Error && error.name !== "Error") throw new FrontRouteError(422, error.message);
    throw error;
  }
}

/** The stored L4 settings of a `tls`/`tcp`/`postgres` row, refusing a corrupt row instead of guessing. */
function currentL4(route: RouteRow): L4RouteSettings {
  const stored = storedL4Settings(route);
  if (!stored) throw new FrontRouteError(409, "The route's stored TLS/TCP settings are invalid.");
  return stored;
}

function l4Summary(route: RouteRow) {
  if (!isL4Kind(route.kind)) return null;
  const stored = storedL4Settings(route);
  return {
    tlsMode: route.tlsMode,
    compatPort: route.kind === "postgres" ? route.compatPort : null,
    sourceCidrs: route.sourceCidrs,
    allowInternet: route.allowInternet,
    internetConfirmedAt: route.internetConfirmedAt?.toISOString() ?? null,
    protocolAuthConfirmed: route.protocolAuthConfirmed,
    limits: stored?.limits ?? null,
    clientCaId: route.clientCaId,
    // Empty = deny all; the route cannot be enabled until it admits someone.
    admits: route.allowInternet ? "internet" : route.sourceCidrs.length ? "allowlist" : "nobody",
  };
}

/**
 * A dedicated raw port carries one listener: a `tcp` route's port or a `postgres` route's compatibility
 * port. The unique indexes cover each kind separately; this check (under the raw-port lock in the
 * mutation transaction) covers a port used by one kind and requested by the other.
 */
async function assertRawPortFree(executor: Pick<typeof db, "select">, port: number, except: string | null) {
  const rows = await executor
    .select({
      id: frontRoutes.id,
      kind: frontRoutes.kind,
      listenPort: frontRoutes.listenPort,
      compatPort: frontRoutes.compatPort,
    })
    .from(frontRoutes)
    .where(
      statement`(${frontRoutes.kind} = 'tcp' AND ${frontRoutes.listenPort} = ${port}) OR ${frontRoutes.compatPort} = ${port}`,
    );
  const taken = rows.find((row) => row.id !== except);
  if (taken) {
    throw new FrontRouteError(
      409,
      `Port ${port} already carries route ${taken.id} (${taken.kind === "tcp" ? "raw TCP" : "Postgres compatibility port"}).`,
    );
  }
}

/** Serialises raw-port allocation across tcp routes and Postgres compatibility ports. */
async function lockRawPorts(tx: DbTransaction) {
  await tx.execute(statement`SELECT pg_advisory_xact_lock(hashtext('ark:front:raw-ports'))`);
}

async function routeDrain(enqueue: RouteEnqueue, route: RouteRow, reason: string) {
  await enqueue({
    kind: "edge.drain",
    targetIds: ["edge:drain"],
    payload: { reason, routeIds: [route.id], backends: [backendKey(route.targetIp, route.targetPort)] },
  });
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
    accessMode: route.kind === "http" ? route.accessMode : null,
    bypassPaths: route.bypassPaths,
    allowedOrigins: allowedOriginsOf(route),
    redirectTo: redirectOf(route),
    // FD-23: the per-client request limit (null: none) and required client certificates.
    rateLimit: route.kind === "http" ? (storedRateLimit(route) ?? null) : null,
    mtls: route.kind === "http" && route.clientCaId !== null,
    l4: l4Summary(route),
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
        .filter(
          (record) =>
            record.name === endpoint.hostname &&
            ["A", "AAAA"].includes(record.type) &&
            (desiredDns(record) || pendingWithdrawal(record)),
        )
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
  const kind: SupportedRouteKind = assertSupportedRouteKind(input.kind);
  assertFieldsForKind(kind, input);
  if (kind === "http") assertSupportedAccessMode(input.accessMode, "create");
  const listenPort =
    kind === "http"
      ? HTTP_LISTEN_PORT
      : l4Check(() => routeListenPort(kind, input.listenPort, enabledSniPorts()));
  const l4 =
    kind === "http"
      ? null
      : l4Check(() =>
          checkL4RouteSettings({
            kind,
            listenPort,
            tlsMode: input.tlsMode,
            sourceCidrs: input.sourceCidrs,
            allowInternet: input.allowInternet,
            allowPlaintext: input.allowPlaintext,
            protocolAuthConfirmed: input.protocolAuthConfirmed,
            limits: input.limits,
            compatPort: input.compatPort,
          }),
        );
  // HTTP defaults to the login gate; L4 admission is governed by its own policy.
  const accessMode = kind === "http" ? (input.accessMode ?? "sso") : "public";
  const gate =
    kind === "http"
      ? gateSettings(accessMode, input, { bypassPaths: [], allowedOrigins: [] })
      : { bypassPaths: [], allowedOrigins: [] };
  // FD-23: HTTP rate limit and client certificates (HTTP_ONLY fields, refused on other kinds).
  const rateLimit = kind === "http" ? requestedRateLimit(input.rateLimit) : null;
  const mtls = kind === "http" && input.mtls === true;
  const hostname = await publicRouteHostname(input.hostname);
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
  if (kind === "tcp") {
    // A dedicated port carries exactly one route, whatever its hostname.
    await assertRawPortFree(db, listenPort, null);
  } else if (endpoint) {
    // HTTP and TLS-TCP routes share a listener by SNI: one route per hostname and port.
    const [existing] = await db
      .select({ id: frontRoutes.id })
      .from(frontRoutes)
      .where(
        and(
          eq(frontRoutes.endpointId, endpoint.id),
          eq(frontRoutes.listenPort, listenPort),
          statement`${frontRoutes.kind} <> 'tcp'`,
        ),
      );
    if (existing)
      throw new FrontRouteError(
        409,
        `${hostname} already has a route on port ${listenPort} (${existing.id}).`,
      );
  }
  if (l4?.compatPort != null) await assertRawPortFree(db, l4.compatPort, null);
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
    kind,
    listenPort,
    l4,
    hostname,
    domain,
    endpoint: endpoint ?? null,
    redirectTo,
    targetInput,
    targetPort: input.targetPort,
    accessMode,
    ...gate,
    rateLimit,
    mtls,
    pinned,
    records,
  };
}

async function publicRouteHostname(value: string) {
  const hostname = normalizeRouteHostname(value);
  const { self } = await loadEdgeSnapshot();
  return normalizeRouteHostname(hostname, self ? tailnetSuffixOf(self) : undefined);
}

/**
 * Atomically writes the endpoint, address records, route, audits and awaiting_acl handoff.
 * The optional step-up callback runs in the same transaction. Periodic observation recovers an
 * interrupted immediate enqueue after commit.
 */
export async function commitRouteCreate(
  plan: RouteCreatePlan,
  actor: RouteActor,
  enqueue: RouteEnqueue,
  authorize?: RouteAuthorize,
) {
  const routeId = createId("rt");
  const now = new Date();
  let records = plan.records;
  try {
    await db.transaction(async (tx) => {
      const { domain, settings: platform } = await lockedDnsDomain(tx, plan.domain.id);
      if (domain.status !== "verified" || !platform?.publicIpv4) {
        throw new FrontRouteError(409, "The domain or server address changed. Review the route again.");
      }
      records = routeAddressRecords({
        hostname: plan.hostname,
        zone: domain.name,
        publicIpv4: platform.publicIpv4,
        publicIpv6: platform.publicIpv6,
        ipv6Status: platform.ipv6Status,
        aaaaEnabled: domain.aaaaEnabled,
        purpose: ROUTE_RECORD_PURPOSE,
      });
      await authorize?.(tx);
      if (plan.kind === "tcp" || plan.l4?.compatPort != null) {
        await lockRawPorts(tx);
        await assertRawPortFree(tx, plan.kind === "tcp" ? plan.listenPort : plan.l4!.compatPort!, null);
      }
      // terminate_mtls: the route's own client CA, created atomically with the route. Its CRL is
      // generated before the route is first rendered (`edge.l4_apply` refreshes missing CRLs).
      const clientCa =
        plan.l4?.tlsMode === "terminate_mtls"
          ? await pki.createPrivateCa({ purpose: "tcp-client", name: `Route ${routeId}` }, tx)
          : plan.mtls
            ? await createHttpClientCa(routeId, tx)
            : null;
      let endpointId = plan.endpoint?.id;
      if (endpointId) {
        const [existing] = await tx
          .select()
          .from(endpoints)
          .where(eq(endpoints.id, endpointId))
          .for("update");
        if (!existing) throw new FrontRouteError(409, "The endpoint was deleted; reload and retry.");
      }
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
        kind: plan.kind,
        endpointId,
        listenPort: plan.listenPort,
        ...(plan.l4
          ? {
              tlsMode: plan.l4.tlsMode,
              sourceCidrs: plan.l4.sourceCidrs,
              allowInternet: plan.l4.allowInternet,
              // Saved under this request's exposure.public grant (`authorize` above).
              internetConfirmedBy: plan.l4.allowInternet ? actor.userId : null,
              internetConfirmedAt: plan.l4.allowInternet ? now : null,
              protocolAuthConfirmed: plan.l4.protocolAuthConfirmed,
              tcpOptions: plan.l4.limits,
              clientCaId: clientCa?.id ?? null,
              compatPort: plan.l4.compatPort,
            }
          : plan.kind === "http"
            ? { clientCaId: clientCa?.id ?? null, rateLimit: plan.rateLimit }
            : {}),
        targetInput: plan.targetInput,
        targetNodeStableId: plan.pinned.stableId,
        targetIp: plan.pinned.ip,
        targetPort: plan.targetPort,
        accessMode: plan.accessMode,
        bypassPaths: plan.bypassPaths,
        httpOptions: {
          ...(plan.redirectTo ? { redirectTo: plan.redirectTo } : {}),
          ...(plan.allowedOrigins.length ? { allowedOrigins: plan.allowedOrigins } : {}),
        },
        enabled: false,
        status: "draft",
        createdBy: actor.userId,
        createdAt: now,
        updatedAt: now,
      });
      await ensureEndpointDnsRecords(tx, plan.domain.id, plan.hostname, records);
      await auditRoute(
        actor,
        "front_route.create",
        routeId,
        {
          kind: plan.kind,
          hostname: plan.hostname,
          listenPort: plan.listenPort,
          domainId: plan.domain.id,
          target: plan.targetInput,
          targetPort: plan.targetPort,
          pinned: plan.pinned,
          ...(plan.kind === "http"
            ? {
                accessMode: plan.accessMode,
                bypassPaths: plan.bypassPaths,
                allowedOrigins: plan.allowedOrigins,
                redirectTo: plan.redirectTo,
                rateLimit: plan.rateLimit,
                mtls: plan.mtls,
                clientCaId: clientCa?.id ?? null,
              }
            : { l4: plan.l4, clientCaId: clientCa?.id ?? null }),
          records,
          status: "draft",
        },
        undefined,
        tx,
      );
      await tx
        .update(frontRoutes)
        .set({ status: "awaiting_acl", updatedAt: new Date() })
        .where(eq(frontRoutes.id, routeId));
      await auditRoute(
        actor,
        "front_route.awaiting_acl",
        routeId,
        { from: "draft", to: "awaiting_acl", reason: "acl_snippet_issued" },
        undefined,
        tx,
      );
    });
  } catch (error) {
    if (isUniqueViolation(error)) {
      throw new FrontRouteError(
        409,
        plan.kind === "tcp" || plan.l4?.compatPort != null
          ? `Port ${plan.kind === "tcp" ? plan.listenPort : plan.l4!.compatPort} or ${plan.hostname} is already taken; reload and retry.`
          : `${plan.hostname} already has a route or endpoint; reload and retry.`,
      );
    }
    throw error;
  }
  // The committed awaiting_acl row is also picked up by the periodic observer after a crash here.
  const observe = await enqueue({ kind: "edge.observe", targetIds: [EDGE_OBSERVE_TARGET] });
  return { routeId, records, observeOperationId: idOf(observe) ?? null };
}

// ---- Update -----------------------------------------------------------------------------------

export type RouteUpdatePlan = Awaited<ReturnType<typeof prepareRouteUpdate>>;

/** Every check for `PATCH /api/front/routes/:id`, with no writes. */
export async function prepareRouteUpdate(routeId: string, input: FrontRouteUpdateInput) {
  const { route, endpoint, domain, version } = await loadRoute(routeId);
  requireManaged(route);
  l4Check(() => assertFieldsForKind(route.kind as SupportedRouteKind, input));
  if (input.accessMode !== undefined) assertSupportedAccessMode(input.accessMode, "update");
  let l4: { current: L4RouteSettings; next: L4RouteSettings } | null = null;
  if (isL4Kind(route.kind)) {
    const current = currentL4(route);
    const next = l4Check(() =>
      checkL4RouteSettings({
        kind: current.kind,
        listenPort: current.listenPort,
        tlsMode: input.tlsMode ?? current.tlsMode,
        sourceCidrs: input.sourceCidrs ?? current.sourceCidrs,
        allowInternet: input.allowInternet ?? current.allowInternet,
        // A tcp route was created with allowPlaintext: true; the confirmation stands.
        allowPlaintext: current.kind === "tcp" ? true : undefined,
        protocolAuthConfirmed:
          current.kind === "tcp"
            ? (input.protocolAuthConfirmed ?? current.protocolAuthConfirmed)
            : input.protocolAuthConfirmed,
        limits: { ...current.limits, ...input.limits },
        compatPort: input.compatPort === undefined ? current.compatPort : input.compatPort,
      }),
    );
    if (next.compatPort !== null && next.compatPort !== current.compatPort)
      await assertRawPortFree(db, next.compatPort, route.id);
    l4 = { current, next };
  }
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
  const accessMode = input.accessMode ?? route.accessMode;
  const currentGate = { bypassPaths: route.bypassPaths, allowedOrigins: allowedOriginsOf(route) };
  const gate =
    route.kind === "http"
      ? gateSettings(accessMode, input, currentGate)
      : { bypassPaths: [], allowedOrigins: [] };
  // FD-23: an invalid stored limit counts as none, so replacing it is never mistaken for tightening.
  const currentRateLimit = route.kind === "http" ? (storedRateLimit(route) ?? null) : null;
  const rateLimit =
    route.kind === "http" && input.rateLimit !== undefined
      ? requestedRateLimit(input.rateLimit)
      : currentRateLimit;
  const currentMtls = route.kind === "http" && route.clientCaId !== null;
  const mtls = route.kind === "http" ? (input.mtls ?? currentMtls) : false;
  const current = {
    targetInput: route.targetInput,
    targetPort: route.targetPort,
    accessMode: route.accessMode,
    redirectTo: redirectOf(route),
    status: route.status,
    ...currentGate,
    rateLimit: currentRateLimit,
    mtls: currentMtls,
  };
  const loosening = looseningChanges(current, {
    targetInput: input.target === undefined ? undefined : targetInput,
    targetPort: input.targetPort,
    accessMode: input.accessMode,
    redirectTo: input.redirectTo === undefined ? undefined : redirectTo,
    allowSensitivePort: input.allowSensitivePort,
    bypassPaths: gate.bypassPaths,
    allowedOrigins: gate.allowedOrigins,
    rateLimit: input.rateLimit === undefined ? undefined : rateLimit,
    mtls: input.mtls === undefined ? undefined : mtls,
  });
  if (l4) loosening.push(...l4LooseningChanges(l4.current, l4.next));
  // Tightening the gate of a route that may have open upgraded connections (§3.9.3).
  // Switching client certificates on (FD-23) also ends connections admitted without one.
  const gateTightened =
    route.kind === "http" &&
    ((accessMode === "sso" && route.accessMode !== "sso") ||
      (mtls && !currentMtls) ||
      currentGate.bypassPaths.some((path) => !gate.bypassPaths.includes(path)) ||
      currentGate.allowedOrigins.some((origin) => !gate.allowedOrigins.includes(origin)));
  const repin = loosening.some((item) => ["target", "targetPort", "reconfirmTarget"].includes(item));
  const pinned = repin ? await pinTarget(targetInput, targetPort, input.allowSensitivePort) : null;
  const changes: Record<string, { from: unknown; to: unknown }> = {};
  if (targetInput !== route.targetInput) changes.target = { from: route.targetInput, to: targetInput };
  if (targetPort !== route.targetPort) changes.targetPort = { from: route.targetPort, to: targetPort };
  if (input.accessMode !== undefined && input.accessMode !== route.accessMode)
    changes.accessMode = { from: route.accessMode, to: input.accessMode };
  if (redirectTo !== redirectOf(route)) changes.redirectTo = { from: redirectOf(route), to: redirectTo };
  if (l4) {
    const { current: before, next } = l4;
    for (const key of [
      "tlsMode",
      "sourceCidrs",
      "allowInternet",
      "protocolAuthConfirmed",
      "limits",
      "compatPort",
    ] as const) {
      if (JSON.stringify(before[key]) !== JSON.stringify(next[key]))
        changes[key] = { from: before[key], to: next[key] };
    }
  }
  if (JSON.stringify(gate.bypassPaths) !== JSON.stringify(currentGate.bypassPaths))
    changes.bypassPaths = { from: currentGate.bypassPaths, to: gate.bypassPaths };
  if (JSON.stringify(gate.allowedOrigins) !== JSON.stringify(currentGate.allowedOrigins))
    changes.allowedOrigins = { from: currentGate.allowedOrigins, to: gate.allowedOrigins };
  if (JSON.stringify(rateLimit) !== JSON.stringify(currentRateLimit))
    changes.rateLimit = { from: currentRateLimit, to: rateLimit };
  if (mtls !== currentMtls) changes.mtls = { from: currentMtls, to: mtls };
  if (pinned && (pinned.stableId !== route.targetNodeStableId || pinned.ip !== route.targetIp))
    changes.pinned = {
      from: { stableId: route.targetNodeStableId, ip: route.targetIp },
      to: { stableId: pinned.stableId, ip: pinned.ip },
    };
  return {
    route,
    endpoint,
    version,
    targetInput,
    targetPort,
    accessMode,
    ...gate,
    gateTightened,
    redirectTo,
    rateLimit,
    mtls,
    pinned,
    loosening,
    changes,
    l4: l4?.next ?? null,
  };
}

/** Applies a prepared update, re-pins and restarts the lifecycle at `awaiting_acl` on a new target. */
export async function commitRouteUpdate(
  plan: RouteUpdatePlan,
  actor: RouteActor,
  enqueue: RouteEnqueue,
  authorize?: RouteAuthorize,
) {
  const { route } = plan;
  const status = plan.pinned ? "awaiting_acl" : route.status;
  const httpOptions = { ...route.httpOptions };
  if (plan.redirectTo) httpOptions.redirectTo = plan.redirectTo;
  else delete httpOptions.redirectTo;
  const l4 = plan.l4;
  const now = new Date();
  if (plan.allowedOrigins.length) httpOptions.allowedOrigins = plan.allowedOrigins;
  else delete httpOptions.allowedOrigins;
  await db.transaction(async (tx) => {
    await authorize?.(tx);
    if (l4?.compatPort != null && l4.compatPort !== route.compatPort) {
      await lockRawPorts(tx);
      await assertRawPortFree(tx, l4.compatPort, route.id);
    }
    // Switching to terminate_mtls gives the route its own client CA (kept if it already has one).
    const clientCaId =
      l4?.tlsMode === "terminate_mtls" && !route.clientCaId
        ? (await pki.createPrivateCa({ purpose: "tcp-client", name: `Route ${route.id}` }, tx)).id
        : route.clientCaId;
    // HTTP mTLS (FD-23): a new route CA when switched on, none (and the old CA retired) when off.
    const httpClientCaId =
      route.kind !== "http"
        ? null
        : plan.mtls
          ? (route.clientCaId ?? (await createHttpClientCa(route.id, tx)).id)
          : null;
    const updated = await tx
      .update(frontRoutes)
      .set({
        ...(l4
          ? {
              tlsMode: l4.tlsMode,
              sourceCidrs: l4.sourceCidrs,
              allowInternet: l4.allowInternet,
              // A newly opened route records this request's exposure.public grant (`authorize`).
              internetConfirmedBy: l4.allowInternet
                ? route.allowInternet
                  ? route.internetConfirmedBy
                  : actor.userId
                : null,
              internetConfirmedAt: l4.allowInternet
                ? route.allowInternet
                  ? route.internetConfirmedAt
                  : now
                : null,
              protocolAuthConfirmed: l4.protocolAuthConfirmed,
              tcpOptions: l4.limits,
              clientCaId,
              ...(route.kind === "postgres" ? { compatPort: l4.compatPort } : {}),
            }
          : route.kind === "http"
            ? { clientCaId: httpClientCaId, rateLimit: plan.rateLimit }
            : {}),
        targetInput: plan.targetInput,
        targetPort: plan.targetPort,
        targetNodeStableId: plan.pinned?.stableId ?? route.targetNodeStableId,
        targetIp: plan.pinned?.ip ?? route.targetIp,
        accessMode: plan.accessMode,
        bypassPaths: plan.bypassPaths,
        httpOptions,
        status,
        lastError: plan.pinned ? null : route.lastError,
        updatedAt: new Date(),
      })
      .where(currentRoute(route.id, plan.version))
      .returning({ id: frontRoutes.id });
    if (!updated.length) throw new FrontRouteError(409, "The route changed state; reload and retry.");
    if (route.kind === "http" && route.clientCaId && !httpClientCaId)
      await retireRouteCa(tx, route.clientCaId);
    // Open WebSockets admitted under the looser gate are closed by a forced reload (§3.9.3).
    if (plan.gateTightened) {
      await tx.execute(
        statement`SELECT set_config('ark.gate_revocation_reason', 'route_gate_tightened', true)`,
      );
      await tx.execute(statement`SELECT ark_gate_revoke(${route.id}, 'route_gate_tightened')`);
    }
  });
  const live = route.enabled && route.status === "ready";
  const apply = await enqueue({ kind: "edge.apply", targetIds: ["platform"] });
  // A changed L4 policy renames the route's HAProxy servers: the old ones are fenced and drained.
  const policyChanged = [
    "tlsMode",
    "sourceCidrs",
    "allowInternet",
    "protocolAuthConfirmed",
    "limits",
    "compatPort",
  ].some((key) => key in plan.changes);
  if (live && (plan.pinned || policyChanged)) {
    // The old backend (or policy) stops serving now, not at the next observation.
    await routeDrain(enqueue, route, plan.pinned ? "route_updated" : "route_policy_changed");
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

/**
 * Checks for `enable`: an implemented access mode (HTTP), an L4 route that admits someone (a
 * non-empty allowlist, or `allowInternet` saved with the owner's exposure.public confirmation), and
 * a `ready` route that is not yet enabled.
 */
export async function prepareRouteEnable(routeId: string) {
  const { route, endpoint, version } = await loadRoute(routeId);
  requireManaged(route);
  await publicRouteHostname(endpoint.hostname);
  if (route.enabled) throw new FrontRouteError(409, "The route is already enabled.");
  if (route.kind === "http") {
    assertSupportedAccessMode(route.accessMode, "enable");
    if (storedRateLimit(route) === undefined)
      throw new FrontRouteError(409, "The route's stored rate limit is invalid; set it again first.");
  } else {
    currentL4(route);
    l4Check(() => assertL4Enableable(route));
  }
  if (route.status !== "ready") {
    throw new FrontRouteError(
      409,
      `The route is ${route.status}; it can be enabled once it is ready (ACL probe, DNS and certificate complete).`,
    );
  }
  return { route, endpoint, version };
}

export async function commitRouteEnable(
  plan: Awaited<ReturnType<typeof prepareRouteEnable>>,
  actor: RouteActor,
  enqueue: RouteEnqueue,
  authorize?: RouteAuthorize,
) {
  await db.transaction(async (tx) => {
    await authorize?.(tx);
    const updated = await tx
      .update(frontRoutes)
      .set({ enabled: true, updatedAt: new Date() })
      .where(currentRoute(plan.route.id, plan.version))
      .returning({ id: frontRoutes.id });
    if (!updated.length) throw new FrontRouteError(409, "The route changed state; reload and retry.");
  });
  const apply = await enqueue({ kind: "edge.apply", targetIds: ["platform"] });
  await auditRoute(
    actor,
    "front_route.enable",
    plan.route.id,
    plan.route.kind === "http"
      ? { hostname: plan.endpoint.hostname, accessMode: plan.route.accessMode }
      : {
          hostname: plan.endpoint.hostname,
          kind: plan.route.kind,
          listenPort: plan.route.listenPort,
          tlsMode: plan.route.tlsMode,
          sourceCidrs: plan.route.sourceCidrs,
          allowInternet: plan.route.allowInternet,
        },
    idOf(apply),
  );
}

/** Disabling only tightens exposure: no step-up, and the backend is drained at once. */
export async function disableRoute(routeId: string, actor: RouteActor, enqueue: RouteEnqueue) {
  const { route, endpoint } = await loadRoute(routeId);
  requireManaged(route);
  if (!route.enabled) throw new FrontRouteError(409, "The route is already disabled.");
  await db
    .update(frontRoutes)
    .set({ enabled: false, updatedAt: new Date() })
    .where(eq(frontRoutes.id, route.id));
  const apply = await enqueue({ kind: "edge.apply", targetIds: ["platform"] });
  await routeDrain(enqueue, route, "route_disabled");
  await auditRoute(
    actor,
    "front_route.disable",
    route.id,
    { hostname: endpoint.hostname, status: route.status },
    idOf(apply),
  );
}

export async function prepareRouteDelete(routeId: string) {
  const plan = await loadRoute(routeId);
  requireManaged(plan.route);
  return plan;
}

/**
 * Drains and removes the route. Its last endpoint retires the address records into a DNS review
 * so the exact provider records can be withdrawn and checked independently of the route.
 */
export async function commitRouteDelete(
  plan: Awaited<ReturnType<typeof prepareRouteDelete>>,
  actor: RouteActor,
  enqueue: RouteEnqueue,
  authorize?: RouteAuthorize,
) {
  const { route, endpoint } = plan;
  const removedEndpoint = await db.transaction(async (tx) => {
    if (endpoint.domainId) await lockedDnsDomain(tx, endpoint.domainId);
    // Lock the shared endpoint before any route row, including concurrent creates.
    await tx.select().from(endpoints).where(eq(endpoints.id, endpoint.id)).for("update");
    await authorize?.(tx);
    const removed = await tx
      .delete(frontRoutes)
      .where(currentRoute(route.id, plan.version))
      .returning({ id: frontRoutes.id });
    if (!removed.length) throw new FrontRouteError(409, "The route changed state; reload and retry.");
    // The route's own client CA issues nothing more once the route is gone.
    if (route.clientCaId) await retireRouteCa(tx, route.clientCaId);
    const others = await tx
      .select({ id: frontRoutes.id })
      .from(frontRoutes)
      .where(eq(frontRoutes.endpointId, endpoint.id));
    if (others.length || endpoint.kind !== "route") return false;
    if (endpoint.domainId) {
      const records = await tx
        .select()
        .from(dnsRecords)
        .where(endpointDnsScope(endpoint.domainId, endpoint.hostname));
      for (const record of records.filter(
        (item) =>
          (desiredDns(item) || (pendingWithdrawal(item) && item.withdrawalReason === "ipv6")) &&
          item.purpose.startsWith(ROUTE_RECORD_PURPOSE),
      )) {
        await tx
          .update(dnsRecords)
          .set(retireDnsRecord(record, "endpoint_deleted", new Date()))
          .where(eq(dnsRecords.id, record.id));
      }
    }
    await tx.delete(certificates).where(eq(certificates.endpointId, endpoint.id));
    await tx.delete(endpoints).where(eq(endpoints.id, endpoint.id));
    return true;
  });
  const apply = await enqueue({ kind: "edge.apply", targetIds: ["platform"] });
  await routeDrain(enqueue, route, "route_deleted");
  if (removedEndpoint && endpoint.domainId) {
    await enqueue({
      kind: "domain.verify",
      targetIds: [endpoint.domainId],
      payload: { routeEndpointsOnly: true },
    });
  }
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

async function routesOn(endpointId: string, executor: Pick<typeof db, "select"> = db) {
  const rows = await executor
    .select({ route: frontRoutes, version: routeVersion })
    .from(frontRoutes)
    .where(eq(frontRoutes.endpointId, endpointId));
  return rows.map(({ route, version }) => ({ ...route, version }));
}

/**
 * Called by `domain.verify` for a `route` endpoint. When every required address record resolves
 * to this server, routes in `awaiting_dns` move to `issuing_certificate` and the caller requests a
 * certificate; before that, nothing is requested and the route records what DNS still shows.
 */
export async function routesAfterDnsCheck(
  input: {
    endpointId: string;
    verified: boolean;
    pending: Array<{ type: string; name: string; expected: string; observed: string }>;
    blockingError?: string;
    operationId?: string;
    allowCertificateRetry: boolean;
  },
  tx: DbTransaction,
) {
  const routes = await routesOn(input.endpointId, tx);
  const [certificate] = await tx
    .select()
    .from(certificates)
    .where(eq(certificates.endpointId, input.endpointId))
    .orderBy(desc(certificates.lastDeployedAt))
    .limit(1);
  const needsCertificate =
    !certificate ||
    certificate.status !== "issued" ||
    (certificate.expiresAt !== null && certificate.expiresAt.getTime() <= Date.now() + 30 * 86_400_000);
  let issue = false;
  for (const route of routes) {
    // An observer check only starts issuance on the transition; explicit verification may retry it.
    if (route.status === "issuing_certificate") {
      if (input.verified && input.allowCertificateRetry) issue = true;
      else if (input.blockingError && input.blockingError !== route.lastError) {
        await tx
          .update(frontRoutes)
          .set({ lastError: input.blockingError, updatedAt: new Date() })
          .where(currentRoute(route.id, route.version));
      }
      continue;
    }
    if (
      route.status !== "awaiting_dns" &&
      !(route.status === "ready" && needsCertificate && input.allowCertificateRetry)
    )
      continue;
    if (input.verified) {
      const changed = await tx
        .update(frontRoutes)
        .set({ status: "issuing_certificate", lastError: null, updatedAt: new Date() })
        .where(currentRoute(route.id, route.version))
        .returning({ id: frontRoutes.id });
      if (!changed.length) continue;
      await auditRoute(
        null,
        "front_route.issuing_certificate",
        route.id,
        { from: route.status, to: "issuing_certificate", reason: "dns_resolves" },
        input.operationId,
        tx,
      );
      issue = true;
      continue;
    }
    const first = input.pending[0];
    const lastError =
      input.blockingError ??
      (first
        ? `Waiting for DNS: ${first.type} ${first.name} must resolve to ${first.expected} (observed: ${first.observed || "nothing"}).`
        : "Waiting for DNS: the route hostname has no address record to check.");
    if (lastError !== route.lastError) {
      await tx
        .update(frontRoutes)
        .set({ lastError, updatedAt: new Date() })
        .where(currentRoute(route.id, route.version));
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
      .where(currentRoute(route.id, route.version));
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

/** Return pre-order DNS failures to the observer. Failed ACME orders use the explicit retry. */
export async function routesCertificateFailed(endpointId: string, message: string, rejectedOrderId?: string) {
  await db.transaction(async (tx) => {
    const routes = (await routesOn(endpointId, tx)).filter((route) => route.status === "issuing_certificate");
    if (rejectedOrderId && routes.length) {
      await tx
        .update(operations)
        .set({
          payload: statement`${operations.payload} || '{"dnsRecheckRejected": true}'::jsonb`,
        })
        .where(eq(operations.id, rejectedOrderId));
      await tx
        .update(endpoints)
        .set({ status: "awaiting_dns", lastVerifiedAt: null })
        .where(eq(endpoints.id, endpointId));
    }
    for (const route of routes) {
      await tx
        .update(frontRoutes)
        .set({
          ...(rejectedOrderId ? { status: "awaiting_dns" as const } : {}),
          lastError: rejectedOrderId
            ? message.slice(0, 500)
            : `Certificate issuance failed: ${message.slice(0, 500)}. Verify the domain again to retry.`,
          updatedAt: new Date(),
        })
        .where(and(currentRoute(route.id, route.version), eq(frontRoutes.status, "issuing_certificate")));
    }
  });
}

// ---- Route client certificates (terminate_mtls, §3.8.4, FD-14; HTTP mTLS, FD-23) ----------------------

async function mtlsRoute(routeId: string) {
  const { route, endpoint } = await loadRoute(routeId);
  const l4Mtls = (route.kind === "tls" || route.kind === "postgres") && route.tlsMode === "terminate_mtls";
  if (!(l4Mtls || route.kind === "http") || !route.clientCaId) {
    throw new FrontRouteError(
      409,
      "Client certificates exist only for tls or postgres routes in terminate_mtls mode and for HTTP routes with mtls.",
    );
  }
  return { route, endpoint, caId: route.clientCaId };
}

/** The route CA (public certificate) and its client certificates. Never a private key. */
export async function listRouteClientCertificates(routeId: string) {
  const { caId } = await mtlsRoute(routeId);
  const [ca, issued] = await Promise.all([pki.getPrivateCa(caId), pki.listClientCertificates(caId)]);
  return {
    ca: ca
      ? {
          id: ca.id,
          name: ca.name,
          status: ca.status,
          certPem: ca.certPem,
          notAfter: ca.notAfter,
          crlNextUpdate: ca.crlNextUpdate,
        }
      : null,
    certificates: issued.map((item) => ({
      id: item.id,
      subjectCn: item.subjectCn,
      serial: item.serial,
      fingerprintSha256: item.fingerprintSha256,
      notBefore: item.notBefore,
      notAfter: item.notAfter,
      status: item.status,
      revokedAt: item.revokedAt,
      certPem: item.certPem,
      // A generated key is revealed once through POST /api/secrets/:id/reveal (secret.reveal step-up).
      keySecretId: item.keySecretId,
    })),
  };
}

/**
 * Issues a 90-day client certificate from the route CA: a generated key, or the caller's CSR. HTTP
 * routes admit exact certificates (FD-23), so the edge is re-rendered to include the new one.
 */
export async function issueRouteClientCertificate(
  routeId: string,
  input: { name: string; csrPem?: string },
  actor: RouteActor,
  enqueue?: RouteEnqueue,
) {
  const { route, caId } = await mtlsRoute(routeId);
  if (route.kind === "http") {
    // The edge renders each admitted certificate; past the limit it would omit the route instead.
    const [row] = await db
      .select({ n: statement<number>`count(*)::int` })
      .from(clientCertificates)
      .where(
        and(
          eq(clientCertificates.caId, caId),
          eq(clientCertificates.status, "issued"),
          gt(clientCertificates.notAfter, new Date()),
        ),
      );
    if ((row?.n ?? 0) >= HTTP_CLIENT_CERTIFICATE_LIMIT)
      throw new FrontRouteError(
        409,
        `The route already has ${HTTP_CLIENT_CERTIFICATE_LIMIT} client certificates; revoke unused ones first.`,
      );
  }
  let issued: Awaited<ReturnType<typeof pki.issueClientCertificate>>;
  try {
    issued = await pki.issueClientCertificate({
      caId,
      subjectCn: input.name,
      csrPem: input.csrPem,
      keyOwner: { resourceType: "platform", resourceId: "platform" },
    });
  } catch (error) {
    if (error instanceof pki.PkiPolicyError) throw new FrontRouteError(422, error.message);
    throw error;
  }
  await auditRoute(actor, "front_route.client_certificate_issue", routeId, {
    certificateId: issued.certificate.id,
    subjectCn: input.name,
    serial: issued.certificate.serial,
    keySource: input.csrPem === undefined ? "generated" : "csr",
  });
  if (route.kind === "http") await enqueue?.({ kind: "edge.apply", targetIds: ["platform"] });
  return {
    id: issued.certificate.id,
    serial: issued.certificate.serial,
    certPem: issued.certificate.certPem,
    caCertPem: issued.caCertPem,
    keySecretId: issued.certificate.keySecretId,
    notAfter: issued.certificate.notAfter,
  };
}

/**
 * Revokes a route client certificate: the CRL is regenerated, and the serial enters the route's lease
 * policy fingerprint, so its HAProxy servers are fenced and every session drained (current and
 * leaving workers) before the generation with the new CRL is reloaded. Tightening: no step-up.
 *
 * HTTP mTLS routes (FD-23) use the gate revocation journal instead (§3.9.3): its forced reload loads
 * the Caddy config without the certificate, and the route's HAProxy sessions (WebSockets included)
 * are drained around it. If that does not happen within 5 s, the watchdog withdraws the route.
 */
export async function revokeRouteClientCertificate(
  routeId: string,
  certificateId: string,
  actor: RouteActor,
) {
  const { route, caId } = await mtlsRoute(routeId);
  const certificate = await pki.getClientCertificate(certificateId);
  if (!certificate || certificate.caId !== caId)
    throw new FrontRouteError(404, "Client certificate not found.");
  const { revoked, crl } = await db.transaction(async (tx) => {
    // Serialize every CRL writer on the CA before changing certificate status.
    await tx.select().from(privateCas).where(eq(privateCas.id, caId)).for("update");
    const revokedCertificate = await pki.revokeClientCertificate(
      { id: certificateId, reason: "cessationOfOperation" },
      tx,
    );
    const generatedCrl = await pki.generateCaCrl({ caId }, tx);
    if (route.kind === "http") {
      await tx.execute(
        statement`SELECT set_config('ark.gate_revocation_reason', 'client_certificate_revoked', true)`,
      );
      await tx.execute(statement`SELECT ark_gate_revoke(${routeId}, 'client_certificate_revoked')`);
      await auditRoute(
        actor,
        "front_route.client_certificate_revoke",
        routeId,
        { certificateId, serial: revokedCertificate.serial, crlNumber: generatedCrl.crlNumber },
        undefined,
        tx,
      );
      return { revoked: revokedCertificate, crl: generatedCrl };
    }
    // Durable work and the desired policy commit together. No post-commit enqueue gap.
    const payload = {
      routeIds: [routeId],
      backends: [backendKey(route.targetIp, route.targetPort)],
      reason: "client_certificate_revoked",
    };
    for (const kind of ["edge.drain", "edge.apply"] as const) {
      const id = createId("op");
      await tx.insert(operations).values({
        id,
        kind,
        actorId: actor.userId,
        targetIds: kind === "edge.drain" ? ["edge:drain"] : ["platform"],
        idempotencyKey: `route-revoke:${certificateId}:${id}`,
        planHash: planHash(payload),
        payload,
        status: "queued",
      });
    }
    await auditRoute(
      actor,
      "front_route.client_certificate_revoke",
      routeId,
      { certificateId, serial: revokedCertificate.serial, crlNumber: generatedCrl.crlNumber },
      undefined,
      tx,
    );
    return { revoked: revokedCertificate, crl: generatedCrl };
  });
  return {
    id: certificateId,
    status: revoked.status,
    revokedAt: revoked.revokedAt,
    crlNumber: crl.crlNumber,
  };
}
