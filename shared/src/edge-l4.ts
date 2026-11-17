// HAProxy SNI router (`edge-l4`) in front of Caddy on 443 (docs/design/front-door.md §3.8, FD-25), and
// its TLS-TCP and raw-TCP routes (FD-14).
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

/** Defaults from §3.8.5: TLS-TCP routes 50/10/20, raw-TCP routes 20/5/10. */
export const L4_LIMIT_DEFAULTS: Record<"tls" | "tcp", L4Limits> = {
  tls: { maxConn: 50, perSourceConn: 10, perSourceRate: 20 },
  tcp: { maxConn: 20, perSourceConn: 5, perSourceRate: 10 },
};

export const L4_LIMIT_BOUNDS: Record<keyof L4Limits, { min: number; max: number }> = {
  maxConn: { min: 1, max: 1000 },
  perSourceConn: { min: 1, max: 200 },
  perSourceRate: { min: 1, max: 2000 },
};

/** The effective limits: defaults for the kind, overridden by valid stored values only. */
export function l4Limits(kind: "tls" | "tcp", stored?: Partial<Record<keyof L4Limits, unknown>> | null) {
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
  kind: "tls" | "tcp";
  listenPort: number;
  tlsMode: EdgeL4TlsMode | "plain";
  sourceCidrs: string[];
  allowInternet: boolean;
  limits: L4Limits;
  clientCaId?: string | null;
  revokedSerials?: string[];
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

export type EdgeL4Input = {
  /** Hostnames Caddy serves (HTTP routes, the admin site and the login origin). */
  httpHostnames: string[];
  tlsRoutes?: EdgeL4TlsRoute[];
  tcpRoutes?: EdgeL4TcpRoute[];
  /** Shared SNI ports enabled at install time (and published on edge-ts). */
  sniPorts?: number[];
};

/** One route in a generation's manifest; prior generations' manifests name the backends to drain. */
export type EdgeL4ManifestRoute = {
  id: string;
  kind: "tls" | "tcp";
  hostname: string;
  stableId: string;
  target: string;
  listenPort: number;
  mode: EdgeL4TlsMode | "plain";
  backend: string;
  server: string;
  /** Terminated routes: the pre-termination loop server, fenced with the target server. */
  loop?: { backend: string; server: string };
};

export type EdgeL4Manifest = {
  version: 2;
  httpHostnames: string[];
  sniPorts: number[];
  routes: EdgeL4ManifestRoute[];
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

function checkedBase(route: L4RouteBase, kind: "tls" | "tcp") {
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

/** Admission before forwarding: in each TLS backend and dedicated raw frontend (§3.8.6). */
function admissionRules(route: TlsRoute | TcpRoute) {
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

function admissionTables(route: TlsRoute | TcpRoute) {
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

function renderConfig(input: { httpHostnames: string[]; routes: TlsRoute[]; tcpRoutes: TcpRoute[] }) {
  const on443 = input.routes.filter((route) => route.listenPort === SNI_ROUTER_PORT);
  const sharedPorts = [...new Set(input.routes.map((route) => route.listenPort))]
    .filter((port) => port !== SNI_ROUTER_PORT)
    .toSorted((a, b) => a - b);
  const routeRules = on443.map(
    (route) => `    use_backend ${route.backend} if { req.ssl_sni -i ${route.hostname} }`,
  );
  const httpRule = input.httpHostnames.length
    ? [
        "    # HTTP routes, the admin site and the login origin terminate in Caddy.",
        `    acl ark_http_sni req.ssl_sni -i ${input.httpHostnames.join(" ")}`,
        "    use_backend be_caddy if ark_http_sni",
      ]
    : [];
  const sharedFrontends = sharedPorts.map((port) =>
    renderSniFrontend(
      port,
      input.routes.filter((route) => route.listenPort === port),
    ),
  );
  const backends = input.routes.map(renderTlsRoute);
  const reject = sharedPorts.length
    ? ["backend be_reject", "    tcp-request content reject", ""].join("\n")
    : "";
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
${[...routeRules, ...httpRule].join("\n")}${routeRules.length || httpRule.length ? "\n" : ""}    # Everything else, including unknown SNI, goes to Caddy. Caddy has certificates only for
    # configured names, so unknown SNI fails the handshake there.
    default_backend be_caddy

backend be_caddy
    # PROXY v2 carries the real client address; Caddy requires it on this loopback listener.
    # Fail fast on the loopback hop: a refused connect means Caddy's listener is down (fail-closed
    # stop, restart), and retrying it only delays the client's reset by about a second per attempt.
    # Caddy reloads keep the listener open, so they need no retry; no redispatch (one server).
    retries 0
    timeout connect ${CADDY_CONNECT_TIMEOUT}
    server caddy ${CADDY_TLS_LISTENER} send-proxy-v2

${[...[...input.routes, ...input.tcpRoutes].map(admissionTables), ...backends, ...sharedFrontends, reject, ...input.tcpRoutes.map(renderTcpRoute)].filter(Boolean).join("\n")}`;
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
  const ids = new Set<string>();
  const listeners = new Set<string>();
  for (const route of [...routes, ...tcpRoutes]) {
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
  for (const route of tcpRoutes) {
    if (listeners.has(`tcp/${route.listenPort}`)) {
      throw new ValidationError(`Route ${route.id}: port ${route.listenPort} already has a raw TCP route.`);
    }
    listeners.add(`tcp/${route.listenPort}`);
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
  };
  const files: Record<string, string> = {
    "haproxy.cfg": renderConfig({ httpHostnames, routes, tcpRoutes }),
    "haproxy.closed.cfg": renderConfig({ httpHostnames, routes: [], tcpRoutes: [] }),
    "admission.lua": L4_ADMISSION_LUA,
    "manifest.json": `${JSON.stringify(manifest, null, 2)}\n`,
  };
  for (const route of [...routes, ...tcpRoutes])
    files[`allow/${route.id}.lst`] = route.cidrs.map((cidr) => `${cidr}\n`).join("");
  for (const route of routes) {
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
 * whose target server is not allowed. Caddy and every other server are never affected.
 */
export function haproxyServerProtected(server: { server: string; key: string | null }) {
  return server.key !== null || LOOP_SERVER.test(server.server);
}

export function haproxyServerDenied(
  server: { server: string; key: string | null },
  index: ReadonlyMap<string, string>,
) {
  if (server.key !== null) return !haproxyServerAllowed(server, index);
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
  const marked = config.split("\n").some((line) => line.startsWith(`${L4_TAILNET_ROUTE_MARKER} `));
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
