import type { AdminMode } from "./dns-plan.ts";
import {
  EDGE_ERRORS_DIR,
  HTTP_ROUTE_SNIPPETS,
  checkedHttpRoute,
  httpRouteSiteBody,
  httpRouteTlsOptions,
  type EdgeHttpRoute,
} from "./edge-http.ts";
import { ValidationError } from "./errors.ts";
import { ADMIN_CLIENT_IP_AUTH_PATHS, GATE_LOGIN_AUTH_PATHS } from "./gate-login.ts";
import { normalizeHostname } from "./hostnames.ts";
import { IPV6_PREFLIGHT_HTTP_PATH } from "./ipv6-preflight.ts";

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

/** A route `planEdge` left out, and why (an unimplemented access mode, invalid stored options). */
export type OmittedHttpRoute = { id: string; hostname: string; reason: string };

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

function checkedPath(path: string) {
  if (!PATH.test(path) || path.split("/").includes("..")) {
    throw new ValidationError(`Edge certificate path ${JSON.stringify(path)} is not a plain absolute path.`);
  }
  return path;
}

function tlsLine(certificate: EdgeCertificate) {
  return `tls ${checkedPath(certificate.fullchain)} ${checkedPath(certificate.privkey)}`;
}

function checkedUpstream(upstream: string) {
  if (!UPSTREAM.test(upstream)) {
    throw new ValidationError(`Edge upstream ${JSON.stringify(upstream)} is not host:port.`);
  }
  return upstream;
}

/** The comment line that introduces the login-origin site in the Caddyfile. */
export const GATE_LOGIN_SITE_COMMENT = "# Gate login origin: only login, MFA and gate endpoints";

/**
 * The login-origin site body (docs/design/front-door.md §3.5, §3.9.1, FD-10). Only the exact Better
 * Auth paths in `GATE_LOGIN_AUTH_PATHS` and the `/gate/*` pages reach the API; everything else,
 * including `/api/state`, `/api/internal/*` and `/api/gate/check`, is answered 404 by the edge. The
 * edge token goes only with the allowlisted login API requests, where the API uses it to trust the
 * `X-Forwarded-For` that Caddy wrote from the PROXY v2 client address. `ark_route_base` removes
 * client-forged `X-Ark-*` headers (a forged token included) before any handler runs. The token is a
 * runtime placeholder, so it never appears in the rendered file.
 */
export function gateLoginSiteBody(apiUpstream: string) {
  const upstream = checkedUpstream(apiUpstream);
  return `  import ark_route_base
  header Strict-Transport-Security "max-age=31536000"
  request_body {
    max_size 64KB
  }
  @gateApi path ${GATE_LOGIN_AUTH_PATHS.join(" ")}
  @gatePages path /gate/*
  handle @gateApi {
    reverse_proxy ${upstream} {
      header_up X-Ark-Edge-Token {env.ARK_EDGE_GATE_TOKEN}
    }
  }
  handle @gatePages {
    reverse_proxy ${upstream}
  }
  handle {
    respond 404
  }
`;
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
 * no upstream yet, so they are rendered as unrouted. Front-door HTTP routes come from `front_routes`
 * through the lease policy (§3.2): only enabled, `ready` routes with a valid pin reach this point.
 * A route whose stored values fail validation (for example an SSO bypass of `/`, or an SSO
 * `streamCloseDelay` over 5m) is listed in `omitted` and served nowhere, so neither Caddy nor the
 * HAProxy 443 map names it. The login origin (`gateHostname`, FD-10) is served like
 * the admin hostname: only once its certificate is issued.
 */
export function planEdge(input: {
  adminMode: AdminMode;
  adminHostname?: string | null;
  /** The public gate login origin (`gate_login_mode = 'public'`), or none. */
  gateHostname?: string | null;
  endpoints: Array<{ id: string; kind: string; hostname: string; exposure: string }>;
  certificates: Array<{ endpointId: string; status: string; lastDeployedAt: Date | null }>;
  certDir?: string;
  /** Front-door HTTP routes allowed by the current lease (§3.2); every other route is omitted. */
  httpRoutes?: EdgeHttpRoute[];
}) {
  const appRoutes: EdgeAppRoute[] = input.endpoints
    .filter((item) => item.kind === "http" && item.exposure === "public")
    .map((item) => ({ hostname: item.hostname }));
  const omitted: OmittedHttpRoute[] = [];
  const httpRoutes = (input.httpRoutes ?? [])
    .filter((route) => {
      try {
        checkedHttpRoute(route);
        return true;
      } catch (error) {
        omitted.push({ id: route.id, hostname: route.hostname, reason: (error as Error).message });
        return false;
      }
    })
    .toSorted((a, b) => a.hostname.localeCompare(b.hostname));
  const adminHostname = input.adminMode === "public" ? (input.adminHostname ?? undefined) : undefined;
  const gateHostname = input.gateHostname ?? undefined;
  const wanted = new Set([
    ...(adminHostname ? [adminHostname] : []),
    ...(gateHostname ? [gateHostname] : []),
    ...appRoutes.map((r) => r.hostname),
    ...httpRoutes.map((r) => r.hostname),
  ]);
  const certificates = currentEdgeCertificates(input).filter((item) => wanted.has(item.hostname));
  const issued = new Set(
    certificates.filter((item) => item.status === "issued").map((item) => item.hostname),
  );
  return {
    adminMode: input.adminMode,
    adminHostname,
    gateHostname,
    certificates,
    appRoutes,
    httpRoutes,
    omitted,
    awaitingCertificate: [...wanted].filter((hostname) => !issued.has(hostname)).toSorted(),
  };
}

/**
 * The HTTP hostnames for the HAProxy 443 map (`edge.l4_apply`, FD-09): exactly the hostnames the same
 * plan gives Caddy a site for, so an omitted or unservable route is in neither config.
 */
export function servedHttpHostnames(plan: { certificates: Array<{ hostname: string; status: string }> }) {
  return plan.certificates.filter((item) => item.status === "issued").map((item) => item.hostname);
}

export function servedHttpRoutes(
  plan: Parameters<typeof servedHttpHostnames>[0] & { httpRoutes?: EdgeHttpRoute[] },
) {
  const hosts = new Set(servedHttpHostnames(plan));
  return (plan.httpRoutes ?? []).filter((route) => hosts.has(route.hostname));
}

/**
 * Renders the public edge Caddyfile. Every HTTPS site loads the certificate Ark issued with
 * `tls <fullchain> <privkey>`; a hostname without an `issued` certificate is not rendered as a
 * site at all, and Caddy's own certificate automation and redirects are off (`auto_https off`).
 * The `:80` block serves ACME HTTP-01 challenges, redirects served hostnames to HTTPS with 308 and
 * answers 404 for every other host.
 *
 * Front-door HTTP routes (§3.5, FD-09) are rendered by `httpRouteSiteBody` (edge-http.ts): no-leak
 * headers, static error pages from `errorsDir`, Location and Set-Cookie rewriting, WebSocket and
 * timeout settings, HSTS, a body limit, or the apex redirect. Proxying routes are preceded by a
 * `# ark-tailnet-route <id> <ip:port>` marker. Rendering with `httpRoutes` omitted gives the closed
 * variant the Caddy launch guard starts from when the lease is not valid (§3.2). `sso` routes (FD-11)
 * add the exact gate handlers, the guarded bypass paths and `forward_auth` to `apiUpstream`; an
 * unknown access mode fails the render.
 *
 * `gate` renders the public login origin (§3.5, FD-10, `gateLoginSiteBody`) when its certificate is
 * issued. It is not a tailnet route, so the closed variant keeps it.
 */
export function renderCaddyfile(input: {
  adminMode: AdminMode;
  adminHostname?: string;
  challengeDir: string;
  apiUpstream: string;
  /** The public gate login origin (§3.9.1); rendered only with an issued certificate. */
  gate?: { hostname: string };
  certificates?: EdgeCertificate[];
  appRoutes?: EdgeAppRoute[];
  httpRoutes?: EdgeHttpRoute[];
  /** Static 502/503/504 pages inside the edge container (infra/platform/edge-errors). */
  errorsDir?: string;
  /** Binds the full and closed files to one apply, including route-free configurations. */
  generation?: string;
}) {
  const errorsDir = checkedPath(input.errorsDir ?? EDGE_ERRORS_DIR);
  if (input.generation && !/^[a-zA-Z0-9-]+$/.test(input.generation))
    throw new ValidationError("Invalid edge generation.");
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
  const site = (hostname: string, body: string, marker = "", tlsOptions = "") => {
    hostname = checkedHostname(hostname);
    const certificate = issued.get(hostname);
    if (!certificate) return "";
    if (served.includes(hostname))
      throw new ValidationError(`Edge hostname ${hostname} is listed more than once.`);
    served.push(hostname);
    // HTTPS sites listen on loopback only, behind the HAProxy SNI router on 443 (§3.5, §3.8).
    return `${marker}${hostname} {
  bind 127.0.0.1
  ${tlsLine(certificate)}${tlsOptions}
${body}}
`;
  };
  const admin =
    input.adminMode === "public" && input.adminHostname
      ? site(
          input.adminHostname,
          `  encode gzip
  route {
    request_header -X-Ark-*
    @internal path /api/internal/* /api/metrics/prometheus /api/platform/maintain
    respond @internal 404
    @adminAuth path ${ADMIN_CLIENT_IP_AUTH_PATHS.join(" ")}
    reverse_proxy @adminAuth ${input.apiUpstream} {
      header_up -X-Forwarded-Host
      header_up X-Forwarded-Proto https
      header_up Host ${input.adminHostname}
      header_up X-Ark-Edge-Token {env.ARK_EDGE_GATE_TOKEN}
    }
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
  const gate = input.gate
    ? site(input.gate.hostname, gateLoginSiteBody(input.apiUpstream), `${GATE_LOGIN_SITE_COMMENT}\n`)
    : "";
  const routes = (input.appRoutes ?? [])
    .map((route) => {
      if (route.upstream !== undefined) checkedUpstream(route.upstream);
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
  const checkedRoutes = (input.httpRoutes ?? []).map(checkedHttpRoute);
  const ids = new Set<string>();
  for (const route of checkedRoutes) {
    if (ids.has(route.id)) throw new ValidationError(`Route ${route.id} is listed more than once.`);
    ids.add(route.id);
  }
  const http = checkedRoutes
    .map((route) =>
      site(
        route.hostname,
        httpRouteSiteBody(route, checkedUpstream(input.apiUpstream)),
        // Redirect-only routes dial nothing, so they carry no tailnet marker.
        route.redirectTo
          ? `# ${route.id} ${route.hostname}: canonical redirect to ${route.redirectTo}${route.clientAuth ? " (client certificate required)" : ""}
`
          : `# ${route.id} ${route.hostname}: ${route.access === "sso" ? "SSO" : "public access"}${route.clientAuth ? " with a client certificate" : ""}
${TAILNET_ROUTE_MARKER} ${route.id} ${route.upstream}
`,
        // HTTP mTLS (FD-23): the client certificate is checked in the TLS handshake, before HTTP.
        httpRouteTlsOptions(route),
      ),
    )
    .filter(Boolean)
    .join("\n");
  const sites = [admin, gate, routes, http].filter(Boolean).join("\n");
  const known = served.length
    ? `  @known host ${served.join(" ")}
  handle @known {
    redir https://{host}{uri} 308
  }
`
    : "";
  const snippets = http || gate ? `${HTTP_ROUTE_SNIPPETS(errorsDir)}\n` : "";
  return `${CADDY_GLOBAL_BLOCK}

${snippets}:80 {
  log
  @otherRequests not path ${IPV6_PREFLIGHT_HTTP_PATH}*
  log_skip @otherRequests
${input.generation ? `  vars ark_edge_generation ${input.generation}\n` : ""}  @challenge path /.well-known/acme-challenge/*
  handle @challenge {
    root * ${input.challengeDir}
    # Explicit hides keep CLI and admin-API adaptation identical for guarded restoration.
    file_server {
      hide /etc/caddy/ark/Caddyfile /etc/caddy/ark/Caddyfile.closed ./Caddyfile
    }
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
