import type { AdminMode } from "./dns-plan.ts";
import { ValidationError } from "./errors.ts";
import { normalizeHostname } from "./hostnames.ts";

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
}) {
  const appRoutes: EdgeAppRoute[] = input.endpoints
    .filter((item) => item.kind === "http" && item.exposure === "public")
    .map((item) => ({ hostname: item.hostname }));
  const adminHostname = input.adminMode === "public" ? (input.adminHostname ?? undefined) : undefined;
  const wanted = new Set([...(adminHostname ? [adminHostname] : []), ...appRoutes.map((r) => r.hostname)]);
  const certificates = currentEdgeCertificates(input).filter((item) => wanted.has(item.hostname));
  const issued = new Set(certificates.filter((item) => item.status === "issued").map((item) => item.hostname));
  return {
    adminMode: input.adminMode,
    adminHostname,
    certificates,
    appRoutes,
    awaitingCertificate: [...wanted].filter((hostname) => !issued.has(hostname)).toSorted(),
  };
}

/**
 * Renders the public edge Caddyfile. Every HTTPS site loads the certificate Ark issued with
 * `tls <fullchain> <privkey>`; a hostname without an `issued` certificate is not rendered as a
 * site at all, and Caddy's own certificate automation and redirects are off (`auto_https off`).
 * The `:80` block serves ACME HTTP-01 challenges, redirects served hostnames to HTTPS with 308 and
 * answers 404 for every other host.
 */
export function renderCaddyfile(input: {
  adminMode: AdminMode;
  adminHostname?: string;
  challengeDir: string;
  apiUpstream: string;
  certificates?: EdgeCertificate[];
  appRoutes?: EdgeAppRoute[];
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
  const site = (hostname: string, body: string) => {
    const certificate = issued.get(checkedHostname(hostname));
    if (!certificate || served.includes(hostname)) return "";
    served.push(hostname);
    return `${hostname} {
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
    @browserApi path /api/auth/* /api/setup/status /api/state /api/me /api/wizard /api/step-up /api/domains* /api/projects* /api/databases* /api/mailboxes* /api/aliases* /api/services* /api/sql/* /api/mail/* /api/devices/* /api/secrets/* /api/backups* /api/ses/* /api/updates/* /api/import/* /api/alerts/* /api/settings* /api/metrics
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
  const known = served.length
    ? `  @known host ${served.join(" ")}
  handle @known {
    redir https://{host}{uri} 308
  }
`
    : "";
  return `{
  admin edge-admin:2019
  # Ark issues every certificate with lego and loads it per site with \`tls\`. Caddy must never
  # obtain certificates itself, and the :80 block below owns the HTTP-to-HTTPS redirects.
  auto_https off
}

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

${admin}${admin && routes ? "\n" : ""}${routes}`;
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
