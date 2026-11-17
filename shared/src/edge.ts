import { routeIdentityKey } from "./edge-withdrawal.ts";
import type { AdminMode } from "./dns-plan.ts";
import { ValidationError } from "./errors.ts";
import { normalizeHostname } from "./hostnames.ts";
import { checkTailnetAddress, parseIpLiteral } from "./tailnet.ts";
import { backendKey } from "./tailnet-observe.ts";

/** Where the `edge` container mounts Ark's lego certificates (read-only), one directory per hostname. */
export const EDGE_CERT_DIR = "/var/lib/ark/certs";

/** The certificate files Ark writes for a hostname, as seen from inside the edge container. */
export function edgeCertificatePaths(hostname: string, certDir = EDGE_CERT_DIR) {
  const root = `${certDir.replace(/\/$/, "")}/${hostname}`;
  return { fullchain: `${root}/fullchain.pem`, privkey: `${root}/privkey.pem` };
}

/** The current certificate for a hostname. Only `issued` certificates are ever served. */
export type EdgeCertificate = {
  hostname: string;
  status: string;
  fullchain: string;
  privkey: string;
};

/**
 * A public HTTP route. `upstream` is a `host:port` the edge can reach; a route without one is
 * "unrouted" and answers with a fixed 503 that names no internal host.
 */
export type EdgeAppRoute = { hostname: string; upstream?: string };

/**
 * A front-door HTTP route to a tailnet backend (docs/design/front-door.md §3.2, FD-06). Only routes
 * that are enabled, `ready` and allowed by a fresh lease are passed in. The pinned IP is the only
 * address dialed; route and stable-ID metadata authorise that exact pin. FD-09 adds the gate, header
 * policy and per-route options.
 */
export type EdgeTailnetRoute = { id: string; hostname: string; stableId: string; ip: string; port: number };

/**
 * The Caddyfile global block (docs/design/front-door.md §3.5, FD-25). HAProxy (`edge-l4`) owns public
 * 443 and forwards HTTP hostnames to Caddy's loopback HTTPS listener with PROXY v2. That listener
 * requires a PROXY header (`fallback_policy require`, no `allow` list, which would select optional
 * USE instead); the loopback bind is what restricts who can send one. The scoped server block keeps
 * the public `:80` server from ever parsing PROXY headers. HTTP/3 is off: UDP 443 is not behind the
 * router, and `Alt-Svc` would advertise the internal port.
 */
export const CADDY_GLOBAL_BLOCK = `{
  admin edge-admin:2019
  # Ark issues every certificate with lego and loads it per site with \`tls\`. Caddy must never
  # obtain certificates itself, and the :80 block below owns the HTTP-to-HTTPS redirects.
  auto_https off
  # A reload (route withdrawal included) gives in-flight requests on the old server 5 s, so a
  # withdrawn route stops serving promptly (docs/design/front-door.md §3.2).
  grace_period 5s
  # HTTPS is reached only through the HAProxy SNI router on 443 (PROXY v2 over loopback).
  # https_port is internal only; it does not change the port clients use.
  https_port 8443
  servers {
    timeouts {
      read_header 10s
      idle 2m
    }
    # HTTP/3 off: UDP 443 is not behind the SNI router, and Alt-Svc would advertise 8443.
    protocols h1 h2
  }
  # Scoped to the loopback HTTPS listener so the public :80 server never parses PROXY headers.
  # No trusted_proxies: the PROXY header already sets the real client address.
  servers 127.0.0.1:8443 {
    # Caddy applies only the most specific servers block, so the timeouts are repeated here.
    timeouts {
      read_header 10s
      idle 2m
    }
    listener_wrappers {
      proxy_protocol {
        # No allow list: it would select optional USE instead of REQUIRE.
        fallback_policy require
      }
      tls
    }
    strict_sni_host on
    protocols h1 h2
  }
}`;

/** Marks a tailnet route's site so the launch guard and audits can find it in the Caddyfile. */
export const TAILNET_ROUTE_MARKER = "# ark-tailnet-route";

const UNROUTED_BODY = "This hostname is not routed yet.";
const PATH = /^\/[A-Za-z0-9._/-]+$/;
const UPSTREAM = /^[A-Za-z0-9.-]+:\d{1,5}$/;

function checkedHostname(hostname: string) {
  if (normalizeHostname(hostname) !== hostname) {
    throw new ValidationError(`Edge hostname ${JSON.stringify(hostname)} is not normalized.`);
  }
  return hostname;
}

const ROUTE_ID = /^rt_[a-z0-9]+$/;

function checkedTailnetRoute(route: EdgeTailnetRoute) {
  const ip = parseIpLiteral(route.ip);
  if (!ip || checkTailnetAddress(ip) || ip.canonical !== route.ip) {
    throw new ValidationError(
      `Tailnet route target ${JSON.stringify(route.ip)} is not a canonical Tailscale address.`,
    );
  }
  if (!Number.isInteger(route.port) || route.port < 1 || route.port > 65535) {
    throw new ValidationError(`Tailnet route port ${JSON.stringify(route.port)} is invalid.`);
  }
  if (!ROUTE_ID.test(route.id)) throw new ValidationError(`Route id ${JSON.stringify(route.id)} is invalid.`);
  return { ...route, upstream: backendKey(ip.canonical, route.port) };
}

function checkedPath(path: string) {
  if (!PATH.test(path) || path.split("/").includes("..")) {
    throw new ValidationError(`Edge certificate path ${JSON.stringify(path)} is not a plain absolute path.`);
  }
  return path;
}

function tlsLine(certificate: EdgeCertificate) {
  return `tls ${checkedPath(certificate.fullchain)} ${checkedPath(certificate.privkey)}`;
}

/**
 * Selects the current certificate for each endpoint: the most recently deployed row. Older rows
 * are history; the files on disk always belong to the latest issuance, so an older `issued` row
 * never makes a hostname servable when the latest one is not.
 */
export function currentEdgeCertificates(input: {
  endpoints: Array<{ id: string; hostname: string }>;
  certificates: Array<{ endpointId: string; status: string; lastDeployedAt: Date | null }>;
  certDir?: string;
}): EdgeCertificate[] {
  const result: EdgeCertificate[] = [];
  for (const endpoint of input.endpoints) {
    const latest = input.certificates
      .filter((item) => item.endpointId === endpoint.id)
      .reduce<(typeof input.certificates)[number] | undefined>(
        (current, item) =>
          !current || (item.lastDeployedAt?.getTime() ?? 0) > (current.lastDeployedAt?.getTime() ?? 0)
            ? item
            : current,
        undefined,
      );
    if (!latest) continue;
    result.push({
      hostname: endpoint.hostname,
      status: latest.status,
      ...edgeCertificatePaths(endpoint.hostname, input.certDir),
    });
  }
  return result;
}

/**
 * What the edge should serve, from the endpoint and certificate rows. Public `http` endpoints have
 * no upstream yet (tailnet routes arrive with the front door), so they are rendered as unrouted.
 */
export function planEdge(input: {
  adminMode: AdminMode;
  adminHostname?: string | null;
  endpoints: Array<{ id: string; kind: string; hostname: string; exposure: string }>;
  certificates: Array<{ endpointId: string; status: string; lastDeployedAt: Date | null }>;
  certDir?: string;
  /** Tailnet HTTP routes allowed by the current lease (§3.2); every other route is omitted. */
  tailnetRoutes?: EdgeTailnetRoute[];
}) {
  const appRoutes: EdgeAppRoute[] = input.endpoints
    .filter((item) => item.kind === "http" && item.exposure === "public")
    .map((item) => ({ hostname: item.hostname }));
  const tailnetRoutes = (input.tailnetRoutes ?? []).toSorted((a, b) => a.hostname.localeCompare(b.hostname));
  const adminHostname = input.adminMode === "public" ? (input.adminHostname ?? undefined) : undefined;
  const wanted = new Set([
    ...(adminHostname ? [adminHostname] : []),
    ...appRoutes.map((r) => r.hostname),
    ...tailnetRoutes.map((r) => r.hostname),
  ]);
  const certificates = currentEdgeCertificates(input).filter((item) => wanted.has(item.hostname));
  const issued = new Set(
    certificates.filter((item) => item.status === "issued").map((item) => item.hostname),
  );
  return {
    adminMode: input.adminMode,
    adminHostname,
    certificates,
    appRoutes,
    tailnetRoutes,
    awaitingCertificate: [...wanted].filter((hostname) => !issued.has(hostname)).toSorted(),
  };
}

/**
 * Renders the public edge Caddyfile. Every HTTPS site loads the certificate Ark issued with
 * `tls <fullchain> <privkey>`; a hostname without an `issued` certificate is not rendered as a
 * site at all, and Caddy's own certificate automation and redirects are off (`auto_https off`).
 * The `:80` block serves ACME HTTP-01 challenges, redirects served hostnames to HTTPS with 308 and
 * answers 404 for every other host.
 *
 * Tailnet routes are preceded by a `# ark-tailnet-route <id> <ip:port>` marker. Rendering with
 * `tailnetRoutes` omitted gives the closed variant the Caddy launch guard starts from when the lease
 * is not valid (§3.2).
 */
export function renderCaddyfile(input: {
  adminMode: AdminMode;
  adminHostname?: string;
  challengeDir: string;
  apiUpstream: string;
  certificates?: EdgeCertificate[];
  appRoutes?: EdgeAppRoute[];
  tailnetRoutes?: EdgeTailnetRoute[];
}) {
  const issued = new Map<string, EdgeCertificate>();
  const seen = new Set<string>();
  for (const certificate of input.certificates ?? []) {
    const hostname = checkedHostname(certificate.hostname);
    if (seen.has(hostname)) {
      throw new ValidationError(`Edge certificate for ${hostname} is listed more than once.`);
    }
    seen.add(hostname);
    if (certificate.status === "issued") issued.set(hostname, certificate);
  }
  const served: string[] = [];
  const site = (hostname: string, body: string, marker = "") => {
    const certificate = issued.get(checkedHostname(hostname));
    if (!certificate || served.includes(hostname)) return "";
    served.push(hostname);
    // HTTPS sites listen on loopback only, behind the HAProxy SNI router on 443 (§3.5, §3.8).
    return `${marker}${hostname} {
  bind 127.0.0.1
  ${tlsLine(certificate)}
${body}}
`;
  };
  const admin =
    input.adminMode === "public" && input.adminHostname
      ? site(
          input.adminHostname,
          `  encode gzip
  route {
    @internal path /api/internal/* /api/metrics/prometheus /api/platform/maintain
    respond @internal 404
    @browserApi path /api/auth/* /api/setup/status /api/state /api/me /api/wizard /api/step-up /api/domains* /api/projects* /api/databases* /api/mailboxes* /api/aliases* /api/services* /api/sql/* /api/mail/* /api/devices/* /api/secrets/* /api/backups* /api/ses/* /api/updates/* /api/import/* /api/alerts/* /api/settings* /api/front/* /api/metrics
    reverse_proxy @browserApi ${input.apiUpstream} {
      header_up -X-Forwarded-Host
      header_up X-Forwarded-Proto https
      header_up Host ${input.adminHostname}
    }
    @unknownApi path /api/*
    respond @unknownApi 404
    reverse_proxy ${input.apiUpstream}
  }
`,
        )
      : "";
  const routes = (input.appRoutes ?? [])
    .map((route) => {
      if (route.upstream !== undefined && !UPSTREAM.test(route.upstream)) {
        throw new ValidationError(`Edge upstream ${JSON.stringify(route.upstream)} is not host:port.`);
      }
      return site(
        route.hostname,
        route.upstream
          ? `  reverse_proxy ${route.upstream}
`
          : `  header -Server
  respond "${UNROUTED_BODY}" 503
`,
      );
    })
    .filter(Boolean)
    .join("\n");
  const tailnet = (input.tailnetRoutes ?? [])
    .map(checkedTailnetRoute)
    .map((route) =>
      site(
        route.hostname,
        `  route {
    vars ark_tailnet_route ${routeIdentityKey(route)}
    reverse_proxy ${route.upstream}
  }
`,
        `${TAILNET_ROUTE_MARKER} ${route.id} ${route.upstream}
`,
      ),
    )
    .filter(Boolean)
    .join("\n");
  const sites = [admin, routes, tailnet].filter(Boolean).join("\n");
  const known = served.length
    ? `  @known host ${served.join(" ")}
  handle @known {
    redir https://{host}{uri} 308
  }
`
    : "";
  return `${CADDY_GLOBAL_BLOCK}

:80 {
  @challenge path /.well-known/acme-challenge/*
  handle @challenge {
    root * ${input.challengeDir}
    file_server
  }
${known}  handle {
    respond "Ark Stack challenge edge" 404
  }
}

${sites}`;
}

export function renderTailscaleServe(upstream = "http://127.0.0.1:8080") {
  return {
    TCP: { "443": { HTTPS: true } },
    Web: {
      "${TS_CERT_DOMAIN}:443": {
        Handlers: {
          "/": { Proxy: upstream },
        },
      },
    },
    AllowFunnel: {},
  };
}

export function funnelDisabled(config: { AllowFunnel?: Record<string, unknown> }) {
  return !config.AllowFunnel || Object.keys(config.AllowFunnel).length === 0;
}
