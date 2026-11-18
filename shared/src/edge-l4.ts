// HAProxy SNI router (`edge-l4`) in front of Caddy on 443 (docs/design/front-door.md §3.8, FD-25), its
// TLS-TCP and raw-TCP routes (FD-14), and the PostgreSQL router on 5432 (FD-26): PgBouncer behind one
// pooler-wide source policy, and `postgres` routes by direct-TLS SNI with an optional compatibility port.
//
// Pure rendering and parsing: the immutable configuration generation `edge.l4_apply` writes, its
// content hash (the generation ID the restricted validator re-checks), the server naming that binds
// a tailnet server to its route identity and admission policy, the launch guard's decision and
// parsers for the master and worker CLI output the withdrawal adapter reads. Socket and file IO live
// in `haproxy-control.ts`.

import { L4_ADMISSION_LUA } from "./l4-admission.ts";
import { assertCidrs, parseCidr } from "./cidr.ts";
import { routeIdentityKey, tailnetDialKey, type EdgePolicyRoute } from "./edge-withdrawal.ts";
import { ValidationError } from "./errors.ts";
import { sha256Hex } from "./hash.ts";
import { normalizeHostname } from "./hostnames.ts";
import { checkTailnetAddress, parseIpLiteral } from "./tailnet.ts";
import { backendKey } from "./tailnet-observe.ts";

/** Supplementary group shared by edge-l4, the validator, the edge watchdog and the domain worker (§3.8.6). */
export const EDGE_L4_SHARED_GID = 4400;
/** Numeric UID of the `haproxy` user in the pinned `haproxy:3.2.26-alpine` image (checked by test:edge). */
export const HAPROXY_IMAGE_UID = 99;
/** Where edge-l4, the validator and the domain worker mount the configuration (identical absolute path). */
export const EDGE_L4_DIR = "/usr/local/etc/haproxy";
/** Caddy's HTTPS listener: loopback only, behind the PROXY v2 wrapper (§3.5). */
export const CADDY_TLS_LISTENER = "127.0.0.1:8443";
/**
 * Connect timeout for the HAProxy -> Caddy loopback hop. A live loopback listener accepts at once, so
 * this only bounds a stalled accept queue; together with `retries 0` a closed listener fails at once.
 */
export const CADDY_CONNECT_TIMEOUT = "1s";
export const HAPROXY_ADMIN_SOCKET = "/var/run/haproxy/admin.sock";
export const HAPROXY_MASTER_SOCKET = "/var/run/haproxy/master.sock";
export const HAPROXY_VALIDATOR_SOCKET = "/var/run/haproxy-validator/validate.sock";
/** Environment variable naming the generation directory relative paths resolve from (`default-path`). */
export const EDGE_L4_GENERATION_ENV = "ARK_EDGE_L4_GENERATION";
/** Marks a tailnet backend in a rendered generation, as `# ark-tailnet-route` does in the Caddyfile. */
export const L4_TAILNET_ROUTE_MARKER = "# ark-tailnet-route";

// ---- Listeners (§3.8.2) -------------------------------------------------------------------------------

/** The always-on SNI router port: HTTP routes, the login origin, the admin site and `tls` routes. */
export const SNI_ROUTER_PORT = 443;
/**
 * Optional shared SNI ports, chosen at install time (each is a published port on `edge-ts`, so
 * changing the set recreates the namespace). Mail's 25, 465, 587 and 993 are never offered.
 */
export const SHARED_SNI_PORTS = [8883, 5671, 636, 6380] as const;
/** Dedicated raw-TCP ports (`tcp` routes, `plain` only): one frontend per port. */
export const TCP_ROUTE_PORTS = { start: 20000, end: 20049 } as const;
/** The PostgreSQL router (`fe_pg5432`): PgBouncer by default, `postgres` routes by SNI (§3.8.3). */
export const POSTGRES_ROUTER_PORT = 5432;
/**
 * Where HAProxy reaches PgBouncer: over the internal `pgbouncer-ingress` network (members edge-ts and
 * pgbouncer-public), resolved through Docker's DNS. The edge namespace never joins
 * `database-management`, so it can never reach `app-postgres`.
 */
export const PGBOUNCER_INGRESS_SERVER = "pgbouncer-public:5432";
/** The pooler allowlist file inside a generation (§3.8.5 `be_pgbouncer`). */
export const POOLER_ALLOWLIST_FILE = "allow/pgbouncer.lst";
/** Platform and mail ports that can never be a route's dedicated port. */
export const RESERVED_ROUTE_PORTS = [25, 80, 443, 465, 587, 993, 2019, 3000, 5432, 41641, 41642] as const;

export function isSharedSniPort(port: number): port is (typeof SHARED_SNI_PORTS)[number] {
  return (SHARED_SNI_PORTS as readonly number[]).includes(port);
}

export function isTcpRoutePort(port: number) {
  return Number.isInteger(port) && port >= TCP_ROUTE_PORTS.start && port <= TCP_ROUTE_PORTS.end;
}

/**
 * Parses the install-time shared SNI port selection (`ARK_EDGE_SNI_PORTS`, comma separated). Only
 * ports from `SHARED_SNI_PORTS` are accepted; anything else is refused rather than ignored, so a
 * typo never publishes a port HAProxy would not serve, or the reverse.
 */
export function parseSniPorts(value: string | undefined | null) {
  const items = (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const ports = new Set<number>();
  for (const item of items) {
    const port = Number(item);
    if (!/^\d+$/.test(item) || !isSharedSniPort(port)) {
      throw new ValidationError(
        `Shared SNI port ${JSON.stringify(item)} is not one of ${SHARED_SNI_PORTS.join(", ")}.`,
      );
    }
    ports.add(port);
  }
  return [...ports].toSorted((a, b) => a - b);
}

// ---- Route admission policy (§3.8.4, §3.8.6) ----------------------------------------------------------

export type EdgeL4TlsMode = "passthrough" | "terminate" | "terminate_mtls";

/** Per-route connection limits: a total cap and per-source concurrent and 10-second rate limits. */
export type L4Limits = { maxConn: number; perSourceConn: number; perSourceRate: number };

/** The L4 route kinds HAProxy serves. */
export type L4RouteKind = "tls" | "tcp" | "postgres";

/**
 * Defaults from §3.8.5: TLS-TCP routes 50/10/20, raw-TCP routes 20/5/10. Postgres routes use the
 * §3.8.3 recommendation (`maxconn` ≤ 50, per-source `conn_cur` ≤ 10 and `conn_rate` ≤ 20/10 s).
 */
export const L4_LIMIT_DEFAULTS: Record<L4RouteKind, L4Limits> = {
  tls: { maxConn: 50, perSourceConn: 10, perSourceRate: 20 },
  tcp: { maxConn: 20, perSourceConn: 5, perSourceRate: 10 },
  postgres: { maxConn: 50, perSourceConn: 10, perSourceRate: 20 },
};

export const L4_LIMIT_BOUNDS: Record<keyof L4Limits, { min: number; max: number }> = {
  maxConn: { min: 1, max: 1000 },
  perSourceConn: { min: 1, max: 200 },
  perSourceRate: { min: 1, max: 2000 },
};

/** The effective limits: defaults for the kind, overridden by valid stored values only. */
export function l4Limits(kind: L4RouteKind, stored?: Partial<Record<keyof L4Limits, unknown>> | null) {
  const limits = { ...L4_LIMIT_DEFAULTS[kind] };
  for (const key of Object.keys(L4_LIMIT_BOUNDS) as Array<keyof L4Limits>) {
    const value = stored?.[key];
    if (value === undefined || value === null) continue;
    const { min, max } = L4_LIMIT_BOUNDS[key];
    if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
      throw new ValidationError(`${key} must be an integer from ${min} to ${max}.`);
    }
    limits[key] = value;
  }
  return limits;
}

/** The two allowlist entries that open a route to every source. Rendered only for `allowInternet`. */
export const OPEN_CIDRS = ["0.0.0.0/0", "::/0"] as const;
/** Shortest prefixes accepted in a restricted allowlist; anything broader needs `allowInternet`. */
export const MIN_RESTRICTED_PREFIX = { 4: 8, 6: 16 } as const;

/**
 * The allowlist a route renders (§3.8.6). Empty means deny all. Only an explicit `allowInternet`
 * (saved under an owner `exposure.public` step-up) renders `0.0.0.0/0` and `::/0`; a stored list
 * can never smuggle an open or near-open prefix past that contract.
 */
export function routeAllowlist(input: { sourceCidrs: string[]; allowInternet?: boolean }) {
  if (input.allowInternet) return [...OPEN_CIDRS];
  const cidrs = assertCidrs(input.sourceCidrs);
  for (const cidr of cidrs) {
    const parsed = parseCidr(cidr);
    const prefix = Number(cidr.slice(cidr.lastIndexOf("/") + 1));
    if (parsed.ok && prefix < MIN_RESTRICTED_PREFIX[parsed.version]) {
      throw new ValidationError(
        `${cidr} is broader than /${MIN_RESTRICTED_PREFIX[parsed.version]}; opening a route to the internet needs allowInternet with an exposure.public step-up.`,
      );
    }
  }
  return [...new Set(cidrs)].toSorted();
}

/**
 * The policy fingerprint of an L4 route (`EdgePolicyRoute.policy`). Every input that decides who is
 * admitted is included, so a change (including a client certificate revocation) renames the route's
 * HAProxy servers and the old ones are fenced and drained in every worker (§3.8.6).
 */
export function l4PolicyFingerprint(input: {
  kind: L4RouteKind;
  listenPort: number;
  tlsMode: EdgeL4TlsMode | "plain";
  sourceCidrs: string[];
  allowInternet: boolean;
  limits: L4Limits;
  clientCaId?: string | null;
  revokedSerials?: string[];
  /** Postgres routes: the opt-in compatibility port (null when off). Part of who is admitted where. */
  compatPort?: number | null;
}) {
  return sha256Hex(
    JSON.stringify([
      input.kind,
      input.listenPort,
      input.tlsMode,
      input.allowInternet
        ? [...OPEN_CIDRS]
        : [...new Set(input.sourceCidrs.map((cidr) => cidr.trim()))].toSorted(),
      [input.limits.maxConn, input.limits.perSourceConn, input.limits.perSourceRate],
      input.clientCaId ?? null,
      [...new Set(input.revokedSerials ?? [])].toSorted(),
      // Appended for postgres only, so existing tls/tcp fingerprints (and server names) are unchanged.
      ...(input.kind === "postgres" ? [input.compatPort ?? null] : []),
    ]),
  ).slice(0, 16);
}

// ---- Rendering input ----------------------------------------------------------------------------------

type L4RouteBase = Pick<EdgePolicyRoute, "id" | "hostname" | "stableId" | "ip" | "port" | "policy"> & {
  /** Stored allowlist; empty = deny all. Ignored when `allowInternet` opens the route. */
  sourceCidrs: string[];
  allowInternet?: boolean;
  limits?: Partial<L4Limits>;
};

/**
 * A TLS-from-the-first-byte route to a tailnet backend, selected by SNI on 443 or on an enabled
 * shared SNI port. `passthrough` relays the client's TLS to the target; `terminate` and
 * `terminate_mtls` use the loop-back pattern (§3.8.4): the SNI backend admits the source, then sends
 * the connection with PROXY v2 to an abstract socket whose frontend terminates TLS (and requires a
 * route-CA client certificate checked against the CRL), restoring the original source address.
 */
export type EdgeL4TlsRoute = L4RouteBase & {
  /** 443 (default) or an enabled shared SNI port. */
  listenPort?: number;
  /** Default `passthrough`. */
  tlsMode?: EdgeL4TlsMode;
  /** terminate*: the public certificate chain followed by its private key (PEM). */
  certificatePem?: string;
  /** terminate_mtls: the route CA certificate and its current CRL (PEM). */
  clientCaPem?: string;
  clientCrlPem?: string;
};

/** A raw-TCP route on a dedicated port from `TCP_ROUTE_PORTS` (`plain`, no TLS at the edge). */
export type EdgeL4TcpRoute = L4RouteBase & { listenPort: number };

/**
 * A `postgres` route on 5432, selected by the SNI of a direct-TLS ClientHello (`sslnegotiation=direct`,
 * §3.8.3). `passthrough` relays to a PG ≥ 17 target, which terminates TLS itself; `terminate` and
 * `terminate_mtls` terminate at the edge with ALPN `postgresql` for older targets and forward plaintext
 * over WireGuard. The optional compatibility port (passthrough only) relays raw TCP from a port of
 * the dedicated range to the target, which then answers classic `SSLRequest` itself.
 */
export type EdgeL4PostgresRoute = L4RouteBase & {
  /** Default `passthrough`. */
  tlsMode?: EdgeL4TlsMode;
  compatPort?: number | null;
  certificatePem?: string;
  clientCaPem?: string;
  clientCrlPem?: string;
};

/**
 * PgBouncer behind `fe_pg5432` (§3.8.3). Rendered only while at least one database is published, so
 * with no public database `SSLRequest` connections are rejected. One explicit pooler-wide source
 * policy: classic negotiation carries no database name, so it is never a per-database allowlist.
 */
export type EdgeL4Pooler = {
  /** The Ark database hostname: direct TLS with this SNI (or with none) goes to PgBouncer. */
  hostname?: string | null;
  /** `pooler_source_cidrs`; empty = deny all. */
  sourceCidrs: string[];
  /** `pooler_allow_internet`, saved under an owner exposure.public confirmation. */
  allowInternet?: boolean;
  /** Default `PGBOUNCER_INGRESS_SERVER`. */
  server?: string;
};

export type EdgeL4Input = {
  /** Hostnames Caddy serves (HTTP routes, the admin site and the login origin). */
  httpHostnames: string[];
  /** Issued front-door routes. Omitted only by the bootstrap and legacy fixtures. */
  httpRoutes?: EdgeL4HttpRoute[];
  tlsRoutes?: EdgeL4TlsRoute[];
  tcpRoutes?: EdgeL4TcpRoute[];
  postgresRoutes?: EdgeL4PostgresRoute[];
  /** PgBouncer on 5432; null or omitted while no database is published. */
  pooler?: EdgeL4Pooler | null;
  /** Shared SNI ports enabled at install time (and published on edge-ts). */
  sniPorts?: number[];
};

export type EdgeL4HttpRoute = Pick<EdgePolicyRoute, "id" | "hostname" | "stableId" | "ip" | "port">;

export function haproxyHttpServerName(route: EdgeL4HttpRoute) {
  return `h_${identityHash(route)}`;
}

export function haproxyHttpBackendName(hostname: string) {
  return `be_http_${hostname}`;
}

const HTTP_SERVER = /^h_[a-f0-9]{32}$/;
const HTTP_BACKEND_PREFIX = "be_http_";

export function haproxyHttpHostname(server: { backend: string; server: string }) {
  return server.backend.startsWith(HTTP_BACKEND_PREFIX) && HTTP_SERVER.test(server.server)
    ? server.backend.slice(HTTP_BACKEND_PREFIX.length)
    : null;
}

/** One route in a generation's manifest; prior generations' manifests name the backends to drain. */
export type EdgeL4ManifestRoute = {
  id: string;
  kind: L4RouteKind;
  hostname: string;
  stableId: string;
  target: string;
  listenPort: number;
  mode: EdgeL4TlsMode | "plain";
  backend: string;
  server: string;
  /** Terminated routes: the pre-termination loop server, fenced with the target server. */
  loop?: { backend: string; server: string };
  /** Postgres routes with a compatibility port: its backend, whose server is the same target server. */
  compat?: { listenPort: number; backend: string; server: string };
};

export type EdgeL4Manifest = {
  version: 2;
  httpHostnames: string[];
  sniPorts: number[];
  routes: EdgeL4ManifestRoute[];
  /** PgBouncer on 5432 (FD-26): null while no database is published. */
  pooler?: { hostname: string | null; server: string; admits: "internet" | "allowlist" | "nobody" } | null;
};

/** The files of one generation, by path relative to the generation directory. */
export type EdgeL4Generation = { id: string; files: Record<string, string>; manifest: EdgeL4Manifest };

const GENERATION_PATH = /^[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)*$/;
/** A generation ID is the SHA-256 of its contents (see `generationId`). */
export const GENERATION_ID = /^[a-f0-9]{64}$/;
const ROUTE_ID = /^rt_[a-z0-9]+$/;
/** Tailnet target servers: `t_<hash>`; terminated routes' loop servers: `l_<same hash>`. */
export const TAILNET_SERVER = /^t_([a-f0-9]{32})$/;
export const LOOP_SERVER = /^l_([a-f0-9]{32})$/;

function identityHash(
  route: Pick<EdgePolicyRoute, "id" | "hostname" | "stableId" | "ip" | "port" | "policy">,
) {
  return sha256Hex(routeIdentityKey(route)).slice(0, 32);
}

/**
 * The HAProxy server name for a tailnet route. It is derived from the full route identity (route ID,
 * hostname, StableID, pinned backend and, for L4 routes, the admission policy fingerprint), so the
 * withdrawal adapter and the launch guard can tell from a running worker's `show servers state`
 * whether a server is still authorised, in any generation.
 */
export function haproxyServerName(
  route: Pick<EdgePolicyRoute, "id" | "hostname" | "stableId" | "ip" | "port" | "policy">,
) {
  return `t_${identityHash(route)}`;
}

/** The loop server of a terminated route: authorised exactly when its target server is. */
export function haproxyLoopServerName(
  route: Pick<EdgePolicyRoute, "id" | "hostname" | "stableId" | "ip" | "port" | "policy">,
) {
  return `l_${identityHash(route)}`;
}

/** The target server a loop server belongs to, or null for any other name. */
export function loopTargetServer(name: string) {
  const match = LOOP_SERVER.exec(name);
  return match ? `t_${match[1]}` : null;
}

function checkedHostname(hostname: string) {
  if (normalizeHostname(hostname) !== hostname) {
    throw new ValidationError(`Edge hostname ${JSON.stringify(hostname)} is not normalized.`);
  }
  return hostname;
}

function checkedPem(value: string | undefined, labels: string[], what: string, routeId: string) {
  const text = value?.trim() ?? "";
  for (const label of labels) {
    if (!text.includes(`-----BEGIN ${label}-----`)) {
      throw new ValidationError(`Route ${routeId} needs ${what} (PEM ${label}).`);
    }
  }
  // Printable ASCII and line breaks only: nothing that could end a directive or smuggle bytes.
  if ([...text].some((char) => (char < " " && !"\t\n\r".includes(char)) || char > "~"))
    throw new ValidationError(`Route ${routeId}: ${what} is not PEM.`);
  return `${text}\n`;
}

function checkedBase(route: L4RouteBase, kind: L4RouteKind) {
  if (!ROUTE_ID.test(route.id)) throw new ValidationError(`Route id ${JSON.stringify(route.id)} is invalid.`);
  const ip = parseIpLiteral(route.ip);
  if (!ip || checkTailnetAddress(ip) || ip.canonical !== route.ip) {
    throw new ValidationError(
      `Tailnet route target ${JSON.stringify(route.ip)} is not a canonical Tailscale address.`,
    );
  }
  if (!Number.isInteger(route.port) || route.port < 1 || route.port > 65535) {
    throw new ValidationError(`Tailnet route port ${JSON.stringify(route.port)} is invalid.`);
  }
  if (!/^[A-Za-z0-9_-]+$/.test(route.stableId)) {
    throw new ValidationError(`StableID ${JSON.stringify(route.stableId)} is invalid.`);
  }
  if (route.policy !== undefined && !/^[a-f0-9]{8,64}$/.test(route.policy)) {
    throw new ValidationError(`Route ${route.id} has an invalid policy fingerprint.`);
  }
  return {
    id: route.id,
    hostname: checkedHostname(route.hostname),
    stableId: route.stableId,
    cidrs: routeAllowlist(route),
    limits: l4Limits(kind, route.limits),
    target: backendKey(ip.canonical, route.port),
    server: haproxyServerName(route),
    loopServer: haproxyLoopServerName(route),
  };
}

function checkedTlsRoute(route: EdgeL4TlsRoute, sniPorts: number[]) {
  const base = checkedBase(route, "tls");
  const listenPort = route.listenPort ?? SNI_ROUTER_PORT;
  if (listenPort !== SNI_ROUTER_PORT && !sniPorts.includes(listenPort)) {
    throw new ValidationError(
      `Route ${route.id}: port ${listenPort} is not 443 or an enabled shared SNI port (${sniPorts.join(", ") || "none"}).`,
    );
  }
  const mode = route.tlsMode ?? "passthrough";
  if (!["passthrough", "terminate", "terminate_mtls"].includes(mode)) {
    throw new ValidationError(`Route ${route.id}: TLS mode ${JSON.stringify(mode)} is invalid.`);
  }
  if (mode === "terminate" && (route.allowInternet || !base.cidrs.length)) {
    throw new ValidationError(
      `Route ${route.id}: terminate requires a restricted, non-empty CIDR allowlist.`,
    );
  }
  const terminated = mode !== "passthrough";
  return {
    ...base,
    kind: "tls" as const,
    listenPort,
    mode,
    backend: `be_${route.id}_tls`,
    inner: terminated ? { frontend: `fe_${route.id}_tls`, backend: `be_${route.id}` } : null,
    abns: `ark_${base.server.slice(2)}`,
    certificate: terminated
      ? checkedPem(route.certificatePem, ["CERTIFICATE", "PRIVATE KEY"], "its certificate and key", route.id)
      : null,
    clientCa:
      mode === "terminate_mtls"
        ? {
            ca: checkedPem(route.clientCaPem, ["CERTIFICATE"], "its route CA", route.id),
            crl: checkedPem(route.clientCrlPem, ["X509 CRL"], "the route CA's CRL", route.id),
          }
        : null,
  };
}

function checkedPostgresRoute(route: EdgeL4PostgresRoute) {
  const base = checkedBase(route, "postgres");
  const mode = route.tlsMode ?? "passthrough";
  if (!["passthrough", "terminate", "terminate_mtls"].includes(mode)) {
    throw new ValidationError(`Route ${route.id}: TLS mode ${JSON.stringify(mode)} is invalid.`);
  }
  if (mode === "terminate" && (route.allowInternet || !base.cidrs.length)) {
    throw new ValidationError(
      `Route ${route.id}: terminate requires a restricted, non-empty CIDR allowlist.`,
    );
  }
  const compatPort = route.compatPort ?? null;
  if (compatPort !== null) {
    if (!isTcpRoutePort(compatPort)) {
      throw new ValidationError(
        `Route ${route.id}: compatibility port ${compatPort} is outside ${TCP_ROUTE_PORTS.start}-${TCP_ROUTE_PORTS.end}.`,
      );
    }
    // The compatibility port relays raw TCP to the target. With edge termination it would bypass the
    // edge's TLS (and client certificate check), so it exists for passthrough routes only.
    if (mode !== "passthrough") {
      throw new ValidationError(`Route ${route.id}: a compatibility port needs tlsMode passthrough.`);
    }
  }
  const terminated = mode !== "passthrough";
  return {
    ...base,
    kind: "postgres" as const,
    listenPort: POSTGRES_ROUTER_PORT,
    mode,
    backend: `be_${route.id}_pg`,
    inner: terminated ? { frontend: `fe_${route.id}_pg`, backend: `be_${route.id}` } : null,
    abns: `ark_${base.server.slice(2)}`,
    compat:
      compatPort === null
        ? null
        : { listenPort: compatPort, frontend: `fe_${route.id}_compat`, backend: `be_${route.id}_compat` },
    certificate: terminated
      ? checkedPem(route.certificatePem, ["CERTIFICATE", "PRIVATE KEY"], "its certificate and key", route.id)
      : null,
    clientCa:
      mode === "terminate_mtls"
        ? {
            ca: checkedPem(route.clientCaPem, ["CERTIFICATE"], "its route CA", route.id),
            crl: checkedPem(route.clientCrlPem, ["X509 CRL"], "the route CA's CRL", route.id),
          }
        : null,
  };
}

const POOLER_SERVER =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*:\d{1,5}$/;

function checkedPooler(pooler: EdgeL4Pooler) {
  const server = pooler.server ?? PGBOUNCER_INGRESS_SERVER;
  const port = Number(server.slice(server.lastIndexOf(":") + 1));
  if (!POOLER_SERVER.test(server) || port < 1 || port > 65535) {
    throw new ValidationError(`PgBouncer address ${JSON.stringify(server)} is not a hostname:port.`);
  }
  // A tailnet address would make PgBouncer look like a guarded route backend; it never is one.
  if (tailnetDialKey(server) !== null) throw new ValidationError("PgBouncer cannot be a tailnet address.");
  const cidrs = routeAllowlist({ sourceCidrs: pooler.sourceCidrs, allowInternet: pooler.allowInternet });
  return {
    hostname: pooler.hostname ? checkedHostname(pooler.hostname) : null,
    server,
    cidrs,
    admits: (pooler.allowInternet ? "internet" : cidrs.length ? "allowlist" : "nobody") as
      | "internet"
      | "allowlist"
      | "nobody",
  };
}

function checkedTcpRoute(route: EdgeL4TcpRoute) {
  const base = checkedBase(route, "tcp");
  if (!isTcpRoutePort(route.listenPort)) {
    throw new ValidationError(
      `Route ${route.id}: raw TCP port ${route.listenPort} is outside ${TCP_ROUTE_PORTS.start}-${TCP_ROUTE_PORTS.end}.`,
    );
  }
  return {
    ...base,
    kind: "tcp" as const,
    listenPort: route.listenPort,
    mode: "plain" as const,
    frontend: `fe_${route.id}`,
    backend: `be_${route.id}`,
  };
}

type TlsRoute = ReturnType<typeof checkedTlsRoute>;
type TcpRoute = ReturnType<typeof checkedTcpRoute>;
type PostgresRoute = ReturnType<typeof checkedPostgresRoute>;
type Pooler = ReturnType<typeof checkedPooler>;

/** Admission before forwarding: in each TLS backend and dedicated raw frontend (§3.8.6). */
function admissionRules(route: TlsRoute | TcpRoute | PostgresRoute) {
  return [
    "    tcp-request inspect-delay 2s",
    `    tcp-request content reject if !{ src -f allow/${route.id}.lst }`,
    `    tcp-request content track-sc1 src table ad_src_${route.id}`,
    `    tcp-request content track-sc2 int(1) table ad_total_${route.id}`,
    "    tcp-request content reject unless { sc1_conn_cur gt 0 } { sc2_conn_cur gt 0 }",
    `    tcp-request content lua.ark-admit ${route.id} ${route.limits.maxConn} ${route.limits.perSourceConn} ${route.limits.perSourceRate}`,
    "    tcp-request content reject unless { var(txn.ark_admitted) -m bool }",
  ];
}

function admissionTables(route: TlsRoute | TcpRoute | PostgresRoute) {
  return `backend ad_src_${route.id}
    stick-table type ipv6 size 10k expire 10m store conn_cur,conn_rate(10s)

backend ad_total_${route.id}
    stick-table type integer size 1 store conn_cur
`;
}

function renderTlsRoute(route: TlsRoute) {
  const header = [
    `${L4_TAILNET_ROUTE_MARKER} ${route.id} ${route.target}`,
    `# ${route.id} ${route.hostname}:${route.listenPort} -> ${route.target} (StableID ${route.stableId}), ${route.mode}`,
  ];
  if (!route.inner) {
    return [
      ...header,
      `backend ${route.backend}`,
      ...admissionRules(route),
      `    server ${route.server} ${route.target} maxconn ${route.limits.maxConn}`,
      "",
    ].join("\n");
  }
  const bind = [
    `bind abns@${route.abns} accept-proxy ssl crt certs/${route.id}.pem`,
    ...(route.clientCa ? [`ca-file cas/${route.id}.pem verify required crl-file cas/${route.id}.crl`] : []),
  ].join(" ");
  return [
    ...header,
    "# Admission (allowlist, per-source and total limits) before TLS termination, on the original source.",
    `backend ${route.backend}`,
    ...admissionRules(route),
    `    server ${route.loopServer} abns@${route.abns} send-proxy-v2 maxconn ${route.limits.maxConn}`,
    "",
    `frontend ${route.inner.frontend}`,
    `    ${bind}`,
    // One slot of headroom: the outer backend, not the accept queue, refuses excess connections.
    `    maxconn ${route.limits.maxConn + 1}`,
    `    default_backend ${route.inner.backend}`,
    "",
    `backend ${route.inner.backend}`,
    `    server ${route.server} ${route.target} maxconn ${route.limits.maxConn}`,
    "",
  ].join("\n");
}

function renderTcpRoute(route: TcpRoute) {
  return [
    `# ---- ${route.listenPort}: raw TCP route (no TLS) ${"-".repeat(Math.max(4, 40 - String(route.listenPort).length))}`,
    `${L4_TAILNET_ROUTE_MARKER} ${route.id} ${route.target}`,
    `# ${route.id} ${route.hostname}:${route.listenPort} -> ${route.target} (StableID ${route.stableId}), plain`,
    `frontend ${route.frontend}`,
    `    bind :${route.listenPort}`,
    // One slot of headroom so admission refuses the excess connection instead of queueing it.
    `    maxconn ${route.limits.maxConn + 1}`,
    ...admissionRules(route),
    `    default_backend ${route.backend}`,
    "",
    `backend ${route.backend}`,
    `    server ${route.server} ${route.target} maxconn ${route.limits.maxConn}`,
    "",
  ].join("\n");
}

function renderPostgresRoute(route: PostgresRoute) {
  const header = [
    `${L4_TAILNET_ROUTE_MARKER} ${route.id} ${route.target}`,
    `# ${route.id} ${route.hostname}:${route.listenPort} -> ${route.target} (StableID ${route.stableId}), ${route.mode}${route.mode === "passthrough" ? " (PG >= 17)" : ""}`,
  ];
  const compat = route.compat
    ? [
        "",
        `# ---- ${route.compat.listenPort}: compatibility port for ${route.id} (classic SSLRequest, raw TCP) ----`,
        "# Off by default. The target answers SSLRequest and terminates TLS itself; admission is the route's.",
        `frontend ${route.compat.frontend}`,
        `    bind :${route.compat.listenPort}`,
        `    maxconn ${route.limits.maxConn + 1}`,
        ...admissionRules(route),
        `    default_backend ${route.compat.backend}`,
        "",
        `backend ${route.compat.backend}`,
        `    server ${route.server} ${route.target} maxconn ${route.limits.maxConn}`,
      ]
    : [];
  if (!route.inner) {
    return [
      ...header,
      `backend ${route.backend}`,
      ...admissionRules(route),
      `    server ${route.server} ${route.target} maxconn ${route.limits.maxConn}`,
      ...compat,
      "",
    ].join("\n");
  }
  // Direct TLS needs the server to select ALPN `postgresql`; libpq refuses the connection otherwise.
  const bind = [
    `bind abns@${route.abns} accept-proxy ssl crt certs/${route.id}.pem alpn postgresql`,
    ...(route.clientCa ? [`ca-file cas/${route.id}.pem verify required crl-file cas/${route.id}.crl`] : []),
  ].join(" ");
  return [
    ...header,
    "# Admission (allowlist, per-source and total limits) before TLS termination, on the original source.",
    `backend ${route.backend}`,
    ...admissionRules(route),
    `    server ${route.loopServer} abns@${route.abns} send-proxy-v2 maxconn ${route.limits.maxConn}`,
    "",
    `frontend ${route.inner.frontend}`,
    `    ${bind}`,
    `    maxconn ${route.limits.maxConn + 1}`,
    `    default_backend ${route.inner.backend}`,
    "",
    "# Plaintext over WireGuard: the target's pg_hba.conf needs a `host` line for the edge node only.",
    `backend ${route.inner.backend}`,
    `    server ${route.server} ${route.target} maxconn ${route.limits.maxConn}`,
    ...compat,
    "",
  ].join("\n");
}

/**
 * `fe_pg5432` (§3.8.3, §3.8.5). Classic `SSLRequest`, `GSSENCRequest` and plaintext `CancelRequest` go to
 * PgBouncer, as does direct TLS with the Ark database hostname or no SNI; a `postgres` route's SNI goes
 * to that route; everything else (unknown SNI, a plaintext StartupMessage, garbage, nothing within 5 s)
 * is rejected. Without a published database there is no PgBouncer rule, so classic clients are rejected.
 */
function renderPg5432Frontend(pooler: Pooler | null, routes: PostgresRoute[]) {
  const poolerRules = pooler
    ? [
        "    # Ark databases via PgBouncer: classic negotiation, or direct TLS for the DB hostname / no SNI.",
        "    use_backend be_pgbouncer if pg_ssl_request || pg_gssenc_request || pg_cancel_request",
        ...(pooler.hostname
          ? [`    use_backend be_pgbouncer if tls_client_hello { req.ssl_sni -i ${pooler.hostname} }`]
          : []),
        "    use_backend be_pgbouncer if tls_client_hello !{ req.ssl_sni -m found }",
      ]
    : ["    # No database is published: classic and no-SNI connections have no backend and are rejected."];
  const routeRules = routes.length
    ? [
        "    # Postgres routes by SNI (direct TLS).",
        ...routes.map(
          (route) =>
            `    use_backend ${route.backend} if tls_client_hello { req.ssl_sni -i ${route.hostname} }`,
        ),
      ]
    : [];
  return [
    `# ---- ${POSTGRES_ROUTER_PORT}: PostgreSQL router ----------------------------------------------`,
    "frontend fe_pg5432",
    `    bind :${POSTGRES_ROUTER_PORT}`,
    "    maxconn 2000",
    "    tcp-request inspect-delay 5s",
    "    acl pg_ssl_request req.payload(0,8) -m bin 0000000804d2162f",
    "    acl pg_gssenc_request req.payload(0,8) -m bin 0000000804d21630",
    "    acl pg_cancel_request req.payload(0,8) -m bin 0000001004d2162e",
    "    acl tls_client_hello req.ssl_hello_type 1",
    "    tcp-request content accept if pg_ssl_request || pg_gssenc_request || pg_cancel_request || tls_client_hello",
    "    tcp-request content reject",
    ...poolerRules,
    ...routeRules,
    "    default_backend be_reject",
    "",
  ].join("\n");
}

function renderPoolerBackend(pooler: Pooler) {
  return [
    "backend be_pgbouncer",
    "    # One explicit pooler-wide policy (pooler_source_cidrs), never a union advertised as per-database",
    "    # isolation: classic SSLRequest carries no database name. Empty = deny all; open CIDRs require",
    "    # pooler_allow_internet saved under an owner exposure.public confirmation.",
    `    tcp-request content reject if !{ src -f ${POOLER_ALLOWLIST_FILE} }`,
    "    # No PROXY protocol: PgBouncer does not support it and sees HAProxy's address.",
    `    server pgbouncer ${pooler.server} maxconn 2000 init-addr last,none resolvers docker`,
    "",
  ].join("\n");
}

/** A shared SNI port's frontend: TLS only, aggregate per-source limits, unknown SNI rejected. */
function renderSniFrontend(port: number, routes: TlsRoute[]) {
  return [
    `# ---- ${port}: shared SNI port ${"-".repeat(56)}`,
    `frontend fe_tls${port}`,
    `    bind :${port}`,
    "    maxconn 2000",
    "    tcp-request inspect-delay 5s",
    "    stick-table type ipv6 size 100k expire 10m store conn_cur,conn_rate(10s)",
    "    tcp-request connection track-sc0 src",
    "    tcp-request connection reject if { sc0_conn_cur gt 64 } || { sc0_conn_rate gt 200 }",
    "    tcp-request content accept if { req.ssl_hello_type 1 }",
    "    tcp-request content reject",
    "    # Backend rules enforce each matched route policy. Content rules after accept are unreachable.",
    ...routes.map((route) => `    use_backend ${route.backend} if { req.ssl_sni -i ${route.hostname} }`),
    "    default_backend be_reject",
    "",
  ].join("\n");
}

function renderConfig(input: {
  httpHostnames: string[];
  httpRoutes?: EdgeL4HttpRoute[];
  routes: TlsRoute[];
  tcpRoutes: TcpRoute[];
  postgresRoutes: PostgresRoute[];
  pooler: Pooler | null;
}) {
  const on443 = input.routes.filter((route) => route.listenPort === SNI_ROUTER_PORT);
  const sharedPorts = [...new Set(input.routes.map((route) => route.listenPort))]
    .filter((port) => port !== SNI_ROUTER_PORT)
    .toSorted((a, b) => a - b);
  const routeRules = on443.map(
    (route) => `    use_backend ${route.backend} if { req.ssl_sni -i ${route.hostname} }`,
  );
  const scoped = input.httpRoutes !== undefined;
  const httpRoutes = input.httpRoutes ?? [];
  const protectedHosts = new Set(httpRoutes.map((route) => route.hostname));
  const platformHosts = input.httpHostnames.filter((hostname) => !protectedHosts.has(hostname));
  const httpRule = platformHosts.length
    ? [
        "    # Platform HTTPS sites terminate in Caddy.",
        `    acl ark_http_sni req.ssl_sni -i ${platformHosts.join(" ")}`,
        "    use_backend be_caddy if ark_http_sni",
      ]
    : [];
  const httpRules = httpRoutes.map(
    (route) =>
      `    use_backend ${haproxyHttpBackendName(route.hostname)} if { req.ssl_sni -i ${route.hostname} }`,
  );
  const caddyBackends = [
    renderCaddyBackend("be_caddy", scoped ? "caddy_platform" : "caddy"),
    ...httpRoutes.map(
      (route) =>
        `# ark-http-route ${route.hostname}\n${renderCaddyBackend(haproxyHttpBackendName(route.hostname), haproxyHttpServerName(route))}`,
    ),
  ];
  const sharedFrontends = sharedPorts.map((port) =>
    renderSniFrontend(
      port,
      input.routes.filter((route) => route.listenPort === port),
    ),
  );
  const backends = input.routes.map(renderTlsRoute);
  const pg5432 = Boolean(input.pooler || input.postgresRoutes.length);
  const reject =
    scoped || sharedPorts.length || pg5432
      ? ["backend be_reject", "    tcp-request content reject", ""].join("\n")
      : "";
  // PgBouncer is the only backend addressed by name: Docker's DNS on the pgbouncer-ingress network.
  const resolvers = input.pooler
    ? `
# PgBouncer is reached by name; start even if it does not resolve yet and re-resolve through Docker's DNS.
resolvers docker
    nameserver dns 127.0.0.11:53
    hold valid 10s
`
    : "";
  const postgres = pg5432
    ? [
        renderPg5432Frontend(input.pooler, input.postgresRoutes),
        ...(input.pooler ? [renderPoolerBackend(input.pooler)] : []),
        ...input.postgresRoutes.map(renderPostgresRoute),
      ]
    : [];
  return `# Ark edge-l4 generation, rendered by edge.l4_apply (docs/design/front-door.md §3.8.5).
# Immutable: edge.l4_apply writes a new generation, has it validated and swaps \`current\`.
global
    log stdout format raw local0
    maxconn 4000
    ssl-default-bind-options ssl-min-ver TLSv1.2
    tune.lua.bool-sample-conversion normal
    lua-load "\${${EDGE_L4_GENERATION_ENV}}/admission.lua"
    # Allowlists, certificates and CRLs are referenced relative to this generation's directory, which
    # the executor names: the validator its candidate, the edge-l4 launch guard \`current\` (resolved
    # at every reload, after the swap). \`config\` would resolve from the guard's symlink instead.
    default-path origin "\${${EDGE_L4_GENERATION_ENV}}"
    stats socket ${HAPROXY_ADMIN_SOCKET} mode 660 gid ${EDGE_L4_SHARED_GID} level admin
    hard-stop-after 30m

defaults
    mode tcp
    log global
    option tcplog
    timeout connect 5s
    timeout client 1h
    timeout server 1h
    timeout client-fin 30s
${resolvers}
# ---- 443: SNI router -------------------------------------------------------
frontend fe_tls443
    bind :443
    maxconn 2000
    tcp-request inspect-delay 5s
    stick-table type ipv6 size 100k expire 10m store conn_cur,conn_rate(10s)
    tcp-request connection track-sc0 src
    tcp-request connection reject if { sc0_conn_cur gt 64 } || { sc0_conn_rate gt 200 }
    # Only a TLS ClientHello is accepted; anything else (or nothing) is rejected within 5 s.
    tcp-request content accept if { req.ssl_hello_type 1 }
    tcp-request content reject
    # Backend rules enforce each matched route policy. Content rules after accept are unreachable.
${[...routeRules, ...httpRules, ...httpRule, `    default_backend ${scoped ? "be_reject" : "be_caddy"}`].join("\n")}

${[...caddyBackends, ...[...input.routes, ...input.postgresRoutes, ...input.tcpRoutes].map(admissionTables), ...backends, ...sharedFrontends, ...postgres, reject, ...input.tcpRoutes.map(renderTcpRoute)].filter(Boolean).join("\n")}`;
}

function renderCaddyBackend(backend: string, server: string) {
  return `backend ${backend}
    # PROXY v2 carries the client address. A refused loopback connect fails immediately.
    retries 0
    timeout connect ${CADDY_CONNECT_TIMEOUT}
    server ${server} ${CADDY_TLS_LISTENER} send-proxy-v2
`;
}

/** Content hash of a generation: sorted `path NUL sha256(content)` lines. */
export function generationId(files: Record<string, string | Uint8Array>) {
  const entries = Object.keys(files).toSorted();
  for (const path of entries) {
    if (!GENERATION_PATH.test(path) || path.split("/").includes("..")) {
      throw new ValidationError(`Generation path ${JSON.stringify(path)} is invalid.`);
    }
  }
  return sha256Hex(entries.map((path) => `${path}\0${sha256Hex(files[path]!)}\n`).join(""));
}

/**
 * Renders one immutable generation: `haproxy.cfg`, the closed variant without tailnet routes that the
 * launch guard starts from without a valid lease, route allowlists, terminated routes' certificates,
 * route CAs and CRLs, and a manifest.
 */
export function renderEdgeL4Generation(input: EdgeL4Input): EdgeL4Generation {
  const httpHostnames = [...new Set(input.httpHostnames.map(checkedHostname))].toSorted();
  const httpRoutes = input.httpRoutes?.toSorted((a, b) => a.hostname.localeCompare(b.hostname));
  if (httpRoutes) {
    const hosts = new Set<string>();
    for (const route of httpRoutes) {
      if (!httpHostnames.includes(route.hostname) || hosts.has(route.hostname))
        throw new ValidationError(
          `Unexpected or duplicate HTTP route hostname ${JSON.stringify(route.hostname)}.`,
        );
      hosts.add(route.hostname);
    }
  }
  const sniPorts = [...new Set(input.sniPorts ?? [])].toSorted((a, b) => a - b);
  for (const port of sniPorts) {
    if (!isSharedSniPort(port)) throw new ValidationError(`Shared SNI port ${port} is not supported.`);
  }
  const routes = (input.tlsRoutes ?? [])
    .map((route) => checkedTlsRoute(route, sniPorts))
    .toSorted((a, b) => a.id.localeCompare(b.id));
  const tcpRoutes = (input.tcpRoutes ?? [])
    .map(checkedTcpRoute)
    .toSorted((a, b) => a.listenPort - b.listenPort || a.id.localeCompare(b.id));
  const postgresRoutes = (input.postgresRoutes ?? [])
    .map(checkedPostgresRoute)
    .toSorted((a, b) => a.id.localeCompare(b.id));
  const pooler = input.pooler ? checkedPooler(input.pooler) : null;
  const ids = new Set<string>();
  const listeners = new Set<string>();
  for (const route of [...routes, ...tcpRoutes, ...postgresRoutes]) {
    if (ids.has(route.id)) throw new ValidationError(`Route ${route.id} appears twice.`);
    ids.add(route.id);
  }
  for (const route of routes) {
    const key = `${route.listenPort}/${route.hostname}`;
    if (
      listeners.has(key) ||
      (route.listenPort === SNI_ROUTER_PORT && httpHostnames.includes(route.hostname))
    ) {
      throw new ValidationError(
        `Route ${route.id} (${route.hostname}) collides with another ${route.listenPort} route.`,
      );
    }
    listeners.add(key);
  }
  for (const route of postgresRoutes) {
    const key = `${POSTGRES_ROUTER_PORT}/${route.hostname}`;
    if (listeners.has(key) || route.hostname === pooler?.hostname) {
      throw new ValidationError(
        `Route ${route.id} (${route.hostname}) collides with another ${POSTGRES_ROUTER_PORT} route or the database hostname.`,
      );
    }
    listeners.add(key);
  }
  for (const port of [
    ...tcpRoutes.map((route) => ({ id: route.id, port: route.listenPort })),
    ...postgresRoutes.flatMap((route) =>
      route.compat ? [{ id: route.id, port: route.compat.listenPort }] : [],
    ),
  ]) {
    if (listeners.has(`tcp/${port.port}`)) {
      throw new ValidationError(`Route ${port.id}: port ${port.port} already has a raw TCP route.`);
    }
    listeners.add(`tcp/${port.port}`);
  }
  const manifest: EdgeL4Manifest = {
    version: 2,
    httpHostnames,
    sniPorts,
    routes: [
      ...routes.map((route) => ({
        id: route.id,
        kind: route.kind,
        hostname: route.hostname,
        stableId: route.stableId,
        target: route.target,
        listenPort: route.listenPort,
        mode: route.mode,
        backend: route.inner?.backend ?? route.backend,
        server: route.server,
        ...(route.inner ? { loop: { backend: route.backend, server: route.loopServer } } : {}),
      })),
      ...postgresRoutes.map((route) => ({
        id: route.id,
        kind: route.kind,
        hostname: route.hostname,
        stableId: route.stableId,
        target: route.target,
        listenPort: route.listenPort,
        mode: route.mode,
        backend: route.inner?.backend ?? route.backend,
        server: route.server,
        ...(route.inner ? { loop: { backend: route.backend, server: route.loopServer } } : {}),
        ...(route.compat
          ? {
              compat: {
                listenPort: route.compat.listenPort,
                backend: route.compat.backend,
                server: route.server,
              },
            }
          : {}),
      })),
      ...tcpRoutes.map((route) => ({
        id: route.id,
        kind: route.kind,
        hostname: route.hostname,
        stableId: route.stableId,
        target: route.target,
        listenPort: route.listenPort,
        mode: route.mode,
        backend: route.backend,
        server: route.server,
      })),
    ],
    pooler: pooler ? { hostname: pooler.hostname, server: pooler.server, admits: pooler.admits } : null,
  };
  const files: Record<string, string> = {
    "haproxy.cfg": renderConfig({ httpHostnames, httpRoutes, routes, tcpRoutes, postgresRoutes, pooler }),
    // PgBouncer is not a tailnet backend: the closed configuration keeps serving it without a lease.
    "haproxy.closed.cfg": renderConfig({
      httpHostnames,
      // HTTP admission is also guarded at Caddy. Keep SNI routing available when this variant is
      // selected for an L4 lease denial so it cannot drop unrelated HTTP routes on reload.
      httpRoutes,
      routes: [],
      tcpRoutes: [],
      postgresRoutes: [],
      pooler,
    }),
    "admission.lua": L4_ADMISSION_LUA,
    "manifest.json": `${JSON.stringify(manifest, null, 2)}\n`,
  };
  for (const route of [...routes, ...tcpRoutes, ...postgresRoutes])
    files[`allow/${route.id}.lst`] = route.cidrs.map((cidr) => `${cidr}\n`).join("");
  if (pooler) files[POOLER_ALLOWLIST_FILE] = pooler.cidrs.map((cidr) => `${cidr}\n`).join("");
  for (const route of [...routes, ...postgresRoutes]) {
    if (route.certificate) files[`certs/${route.id}.pem`] = route.certificate;
    if (route.clientCa) {
      files[`cas/${route.id}.pem`] = route.clientCa.ca;
      files[`cas/${route.id}.crl`] = route.clientCa.crl;
    }
  }
  return { id: generationId(files), files, manifest };
}

/** A server line of a rendered or running configuration. */
export type HaproxyServer = { backend: string; server: string; key: string | null };

/** Tailnet `server` lines in a configuration text, with their enclosing backend. */
export function haproxyConfigServers(config: string): HaproxyServer[] {
  const servers: HaproxyServer[] = [];
  let backend = "";
  for (const line of config.split("\n")) {
    const section = /^(backend|frontend|listen|defaults|global|resolvers|peers)\b\s*(\S*)/.exec(line);
    if (section) backend = section[1] === "backend" || section[1] === "listen" ? section[2]! : "";
    const server = /^\s+server\s+(\S+)\s+(\S+)/.exec(line);
    if (server) servers.push({ backend, server: server[1]!, key: tailnetDialKey(server[2]!) });
  }
  return servers;
}

/** Allowed identities indexed by their server name, with the pinned backend each authorises. */
export function allowedServerIndex(allowed: ReadonlySet<string>) {
  const index = new Map<string, string>();
  for (const identity of allowed) {
    try {
      const [id, hostname, stableId, target, policy] = JSON.parse(decodeURIComponent(identity)) as string[];
      const match = /^\[?([^\]]+?)\]?:(\d+)$/.exec(String(target));
      if (!match) continue;
      index.set(
        haproxyServerName({
          id,
          hostname,
          stableId,
          ip: match[1]!,
          port: Number(match[2]),
          ...(typeof policy === "string" ? { policy } : {}),
        }),
        target!,
      );
      index.set(`h_${sha256Hex(identity).slice(0, 32)}`, hostname!);
    } catch {
      // Malformed identities authorise nothing.
    }
  }
  return index;
}

/** A tailnet server is allowed only when its name matches an allowed identity with the same pin. */
export function haproxyServerAllowed(
  server: { server: string; key: string | null },
  index: ReadonlyMap<string, string>,
) {
  return server.key !== null && index.get(server.server) === server.key;
}

/**
 * Servers the withdrawal adapter must fence when `index` no longer authorises them: tailnet target
 * servers whose identity or pin is not allowed, and the loop servers of terminated routes (FD-14)
 * whose target server is not allowed. Protected HTTP route servers carry their own route identity.
 * The platform Caddy backend is outside the lease.
 */
export function haproxyServerProtected(server: { backend: string; server: string; key: string | null }) {
  return server.key !== null || LOOP_SERVER.test(server.server) || haproxyHttpHostname(server) !== null;
}

export function haproxyServerDenied(
  server: { backend: string; server: string; key: string | null },
  index: ReadonlyMap<string, string>,
) {
  if (server.key !== null) return !haproxyServerAllowed(server, index);
  const hostname = haproxyHttpHostname(server);
  if (hostname !== null) return index.get(server.server) !== hostname;
  const target = loopTargetServer(server.server);
  return target !== null && !index.has(target);
}

/**
 * The HAProxy launch guard's decision for the full configuration: `open` when it has no tailnet
 * server, or when every one is authorised by a currently valid lease. Otherwise the guard starts from
 * `haproxy.closed.cfg`.
 */
export function haproxyLaunchDecision(config: string, allowed: ReadonlySet<string>) {
  const index = allowedServerIndex(allowed);
  const tailnet = haproxyConfigServers(config).filter((server) => server.key !== null);
  const denied = tailnet.filter((server) => !haproxyServerAllowed(server, index));
  const marked = config
    .split("\n")
    .some((line) => line.startsWith(`${L4_TAILNET_ROUTE_MARKER} `) || line.startsWith("# ark-http-route "));
  return {
    open: denied.length === 0,
    guarded: marked || tailnet.length > 0,
    backends: [...new Set(tailnet.map((server) => server.key!))].toSorted(),
    denied: [...new Set(denied.map((server) => server.key!))].toSorted(),
  };
}

// ---- Master and worker CLI output ---------------------------------------------------------------------

export type HaproxyProcess = {
  pid: number;
  type: string;
  reloads: number;
  /** `show proc` section. After a failed reload the still-serving worker is listed as old. */
  section: "current" | "old" | "programs" | "master";
};

/** Parses master CLI `show proc` (HAProxy 3.2). */
export function parseShowProc(text: string): HaproxyProcess[] {
  const processes: HaproxyProcess[] = [];
  let section: HaproxyProcess["section"] = "master";
  for (const line of text.split("\n")) {
    if (/^#\s*workers/.test(line)) section = "current";
    else if (/^#\s*old workers/.test(line)) section = "old";
    else if (/^#\s*programs/.test(line)) section = "programs";
    const match = /^(\d+)\s+(\S+)\s+(\d+)/.exec(line);
    if (match) {
      processes.push({
        pid: Number(match[1]),
        type: match[2]!,
        reloads: Number(match[3]),
        section: match[2] === "master" ? "master" : section,
      });
    }
  }
  return processes;
}

export type ServerState = {
  backend: string;
  server: string;
  addr: string;
  port: number;
  adminState: number;
  operState: number;
  /** Canonical tailnet backend key, or null for non-tailnet servers (Caddy, PgBouncer). */
  key: string | null;
};

/** `srv_admin_state` bit set by `disable server` (SRV_ADMF_FMAINT). */
export const SERVER_FORCED_MAINT = 0x01;

/** Parses worker CLI `show servers state` (format version 1). */
export function parseServersState(text: string): ServerState[] {
  const lines = text.split("\n");
  const header = lines.find((line) => line.startsWith("# be_id"));
  if (!header) {
    if (lines.some((line) => /^\d+ \S+ \d+ /.test(line))) throw new Error("show servers state has no header");
    return [];
  }
  const fields = header.slice(2).trim().split(/\s+/);
  const at = (name: string) => fields.indexOf(name);
  const states: ServerState[] = [];
  for (const line of lines) {
    if (!/^\d+\s/.test(line)) continue;
    const values = line.trim().split(/\s+/);
    const addr = values[at("srv_addr")] ?? "";
    const port = Number(values[at("srv_port")]);
    const parsed = parseIpLiteral(addr);
    states.push({
      backend: values[at("be_name")] ?? "",
      server: values[at("srv_name")] ?? "",
      addr,
      port,
      adminState: Number(values[at("srv_admin_state")]),
      operState: Number(values[at("srv_op_state")]),
      key: parsed ? tailnetDialKey(backendKey(parsed.canonical, port)) : null,
    });
  }
  return states;
}

export type SessionInfo = { id: string; frontend: string; backend: string; server: string };

/** Parses worker CLI `show sess`. */
export function parseShowSess(text: string): SessionInfo[] {
  const sessions: SessionInfo[] = [];
  for (const line of text.split("\n")) {
    const match = /^(0x[0-9a-f]+):.*?\bfe=(\S+)\s+be=(\S+)\s+srv=(\S+)/.exec(line);
    if (match) sessions.push({ id: match[1]!, frontend: match[2]!, backend: match[3]!, server: match[4]! });
  }
  return sessions;
}

/** Parses worker CLI `show stat` CSV into rows keyed by column name. */
export function parseShowStat(text: string) {
  const lines = text.split("\n").filter(Boolean);
  const header = lines.find((line) => line.startsWith("# "));
  if (!header) return [];
  const columns = header.slice(2).split(",");
  return lines
    .filter((line) => !line.startsWith("#"))
    .map((line) => {
      const values = line.split(",");
      return Object.fromEntries(columns.map((column, index) => [column, values[index] ?? ""]));
    });
}

/** Parses the master CLI answer to `reload`: `Success=1|0`, then the startup log. */
export function parseReload(text: string) {
  const match = /^Success=(\d)/m.exec(text);
  const log = text.split("\n--\n").slice(1).join("\n--\n").trim();
  return { success: match?.[1] === "1", answered: Boolean(match), log: log.slice(-4_000) };
}
