// HAProxy SNI router (`edge-l4`) in front of Caddy on 443 (docs/design/front-door.md §3.8, FD-25).
//
// Pure rendering and parsing: the immutable configuration generation `edge.l4_apply` writes, its
// content hash (the generation ID the restricted validator re-checks), the server naming that binds
// a tailnet server to its route identity, the launch guard's decision and parsers for the master and
// worker CLI output the withdrawal adapter reads. Socket and file IO live in `haproxy-control.ts`.

import { assertCidrs } from "./cidr.ts";
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

/** A generation ID is the SHA-256 of its contents (see `generationId`). */
export const GENERATION_ID = /^[a-f0-9]{64}$/;
const GENERATION_PATH = /^[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)*$/;
const ROUTE_ID = /^rt_[a-z0-9]+$/;

/**
 * A TLS-from-the-first-byte route to a tailnet backend, relayed by SNI (passthrough). This is the
 * foundation FD-14 extends with termination, per-route limits from the data model and dedicated
 * ports; `edge.l4_apply` renders none until then. Its backend already applies the route allowlist
 * (empty = deny all) and a per-source stick table before forwarding (§3.8.6).
 */
export type EdgeL4TlsRoute = Pick<EdgePolicyRoute, "id" | "hostname" | "stableId" | "ip" | "port"> & {
  sourceCidrs: string[];
};

export type EdgeL4Input = {
  /** Hostnames Caddy serves (HTTP routes, the admin site and the login origin). */
  httpHostnames: string[];
  tlsRoutes?: EdgeL4TlsRoute[];
};

/** One route in a generation's manifest; prior generations' manifests name the backends to drain. */
export type EdgeL4ManifestRoute = {
  id: string;
  hostname: string;
  stableId: string;
  target: string;
  backend: string;
  server: string;
};

export type EdgeL4Manifest = {
  version: 1;
  httpHostnames: string[];
  routes: EdgeL4ManifestRoute[];
};

/** The files of one generation, by path relative to the generation directory. */
export type EdgeL4Generation = { id: string; files: Record<string, string>; manifest: EdgeL4Manifest };

/**
 * The HAProxy server name for a tailnet route. It is derived from the full route identity (route ID,
 * hostname, StableID and pinned backend), so the withdrawal adapter and the launch guard can tell from
 * a running worker's `show servers state` whether a server is still authorised, in any generation.
 */
export function haproxyServerName(
  route: Pick<EdgePolicyRoute, "id" | "hostname" | "stableId" | "ip" | "port">,
) {
  return `t_${sha256Hex(routeIdentityKey(route)).slice(0, 32)}`;
}

function checkedHostname(hostname: string) {
  if (normalizeHostname(hostname) !== hostname) {
    throw new ValidationError(`Edge hostname ${JSON.stringify(hostname)} is not normalized.`);
  }
  return hostname;
}

function checkedTlsRoute(route: EdgeL4TlsRoute) {
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
  return {
    ...route,
    hostname: checkedHostname(route.hostname),
    cidrs: assertCidrs(route.sourceCidrs),
    target: backendKey(ip.canonical, route.port),
    backend: `be_${route.id}_tls`,
    server: haproxyServerName(route),
  };
}

function renderConfig(input: { httpHostnames: string[]; routes: ReturnType<typeof checkedTlsRoute>[] }) {
  const routeRules = input.routes.map(
    (route) => `    use_backend ${route.backend} if { req.ssl_sni -i ${route.hostname} }`,
  );
  const httpRule = input.httpHostnames.length
    ? [
        "    # HTTP routes, the admin site and the login origin terminate in Caddy.",
        `    acl ark_http_sni req.ssl_sni -i ${input.httpHostnames.join(" ")}`,
        "    use_backend be_caddy if ark_http_sni",
      ]
    : [];
  const backends = input.routes.map((route) =>
    [
      `${L4_TAILNET_ROUTE_MARKER} ${route.id} ${route.target}`,
      `# ${route.id} ${route.hostname}:443 -> ${route.target} (StableID ${route.stableId}), passthrough`,
      `backend ${route.backend}`,
      `    tcp-request content reject if !{ src -f allow/${route.id}.lst }`,
      "    stick-table type ipv6 size 10k expire 10m store conn_cur,conn_rate(10s)",
      "    tcp-request content track-sc1 src",
      "    tcp-request content reject if { sc1_conn_cur gt 10 } || { sc1_conn_rate gt 20 }",
      `    server ${route.server} ${route.target} maxconn 50`,
      "",
    ].join("\n"),
  );
  return `# Ark edge-l4 generation, rendered by edge.l4_apply (docs/design/front-door.md §3.8.5).
# Immutable: edge.l4_apply writes a new generation, has it validated and swaps \`current\`.
global
    log stdout format raw local0
    maxconn 4000
    ssl-default-bind-options ssl-min-ver TLSv1.2
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

${backends.join("\n")}`;
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
 * launch guard starts from without a valid lease, route allowlists and a manifest.
 */
export function renderEdgeL4Generation(input: EdgeL4Input): EdgeL4Generation {
  const httpHostnames = [...new Set(input.httpHostnames.map(checkedHostname))].toSorted();
  const routes = (input.tlsRoutes ?? []).map(checkedTlsRoute).toSorted((a, b) => a.id.localeCompare(b.id));
  const seen = new Set<string>();
  for (const route of routes) {
    if (seen.has(route.id) || seen.has(route.hostname) || httpHostnames.includes(route.hostname)) {
      throw new ValidationError(`Route ${route.id} (${route.hostname}) collides with another 443 route.`);
    }
    seen.add(route.id);
    seen.add(route.hostname);
  }
  const manifest: EdgeL4Manifest = {
    version: 1,
    httpHostnames,
    routes: routes.map(({ id, hostname, stableId, target, backend, server }) => ({
      id,
      hostname,
      stableId,
      target,
      backend,
      server,
    })),
  };
  const files: Record<string, string> = {
    "haproxy.cfg": renderConfig({ httpHostnames, routes }),
    "haproxy.closed.cfg": renderConfig({ httpHostnames, routes: [] }),
    "manifest.json": `${JSON.stringify(manifest, null, 2)}\n`,
  };
  for (const route of routes)
    files[`allow/${route.id}.lst`] = route.cidrs.map((cidr) => `${cidr}\n`).join("");
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
      const [id, hostname, stableId, target] = JSON.parse(decodeURIComponent(identity)) as string[];
      const match = /^\[?([^\]]+?)\]?:(\d+)$/.exec(String(target));
      if (!match) continue;
      index.set(
        haproxyServerName({ id, hostname, stableId, ip: match[1]!, port: Number(match[2]) }),
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
