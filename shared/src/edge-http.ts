// Edge rendering for front-door HTTP routes (docs/design/front-door.md §3.5, FD-09).
//
// One Caddy site block per servable route, behind the HAProxy SNI router on loopback 8443:
// - `ark_route_base`: deferred removal of Server/Via/X-Powered-By, nosniff, a referrer policy, removal
//   of client-forged `X-Ark-*`, and static 502/503/504 pages that name no internal host;
// - HSTS, a request body limit, and the reserved `/.ark/gate/*` namespace;
// - `reverse_proxy` to the pinned tailnet address with the gate cookie stripped upstream, Set-Cookie
//   `Domain=` removed (cookies become host-only on the public name), no buffering for WebSockets,
//   `stream_close_delay` across reloads, and dial/response-header timeouts;
// - the Location policy below;
// - or, for an apex route with `redirectTo`, a 308 to the canonical hostname and nothing else.
//
// Only `public` access is implemented. The login origin exists (FD-10, `gateLoginSiteBody` in edge.ts),
// but the gate handshake and forward_auth (FD-11) do not yet, so an `sso` route is never rendered:
// `planEdge` omits it and `renderCaddyfile` refuses it (fail closed).
//
// Location policy. Caddy evaluates it on the raw upstream value in `handle_response`, before the
// `header_down` rewrite runs. In order:
// 1. `malformed`: anything that is not one of the supported forms is answered with the static 502.
//    Supported: empty; path-absolute (`/x`, not `//`); query- or fragment-only; a relative path
//    whose first segment has no `:`; a non-authority URI with a scheme (`mailto:`, `app:/cb`); an
//    absolute or scheme-relative http(s) URL whose authority is a known internal authority (below);
//    or one whose authority is a DNS name with at least two labels and a top-level label that starts
//    with a letter, and an optional port. Control characters and backslashes are never supported
//    (browsers strip tabs and newlines and treat `\` as `/`), nor are userinfo, IP literals other
//    than the target's, percent-encoded or IDN hosts, empty authorities (`///x`) and IPv4 forms
//    browsers would normalise (`//1684366951/`, `//100.101.102.0x67/`).
// 2. `scheme`: a special scheme (http, https, ws, wss, ftp, file) not followed by `//`. Browsers
//    read `http:host/x` and `https:/x` as authority-bearing.
// 3. `internal`: a known internal token anywhere, unless the Location is a rewritable internal URL.
//    Tokens are the target's tailnet IPs (IPv6 in compressed, expanded and zero-padded form), its
//    fully-qualified MagicDNS names, any dotted quad in 100.64.0.0/10, anything with the Tailscale
//    ULA prefix `fd7a:115c:a1e0:`, and any `.ts.net` name.
// 4. `suffix`: a known internal token after the authority, for example in `?next=`.
// Then the known internal authority is rewritten to `https://<public hostname>`, preserving path,
// query and fragment (also authority-only and query-only suffixes). Known internal authorities: the
// target's IPv4, bracketed IPv6 (compressed, expanded or zero-padded), MagicDNS name (optional final
// dot) and short name, with no port or the target port. Caddy joins repeated upstream Location
// values with "," in `{rp.header.Location}`; the checks run on that joined value, the upstream header
// is dropped (`header_down -Location`) and exactly the checked value is sent once, so a second
// Location line can never bypass them.
//
// Audit boundary. This is a guarantee about edge-controlled headers only: Server, Via, X-Powered-By,
// Location and Set-Cookie Domain. Response bodies (HTML, scripts, JSON with absolute URLs), other
// headers that carry URLs (Content-Location, Refresh, Link), the upstream application's own
// public-URL setting and the certificates it presents are passed through unchanged. The owner must
// audit them before exposing a service; the UI says so when a route is created.

import { routeIdentityKey } from "./edge-withdrawal.ts";
import { ValidationError } from "./errors.ts";
import { normalizeHostname } from "./hostnames.ts";
import { checkTailnetAddress, parseIpLiteral } from "./tailnet.ts";
import { backendKey } from "./tailnet-observe.ts";

/** Where the `edge` container mounts the static error pages (infra/platform/edge-errors). */
export const EDGE_ERRORS_DIR = "/etc/caddy/errors";

/** Per-route HTTP options (`front_routes.http_options`), with the §3.5 defaults. */
export type HttpRouteOptions = {
  /** Request body limit in MB. */
  maxBodyMb: number;
  /** `Strict-Transport-Security: max-age=31536000` (no includeSubDomains or preload). */
  hsts: boolean;
  /** `public` forwards the public Host (Caddy's default for HTTP upstreams); `target` sends ip:port. */
  upstreamHost: "public" | "target";
  /** Rewrite internal Location authorities to the public origin. Off: they are answered with 502. */
  rewriteLocation: boolean;
  responseHeaderTimeout: string;
  /** How long upgraded connections (WebSockets) survive a Caddy reload. */
  streamCloseDelay: string;
  /** Hard limit on upgraded connections; none by default. */
  streamTimeout?: string;
};

export const HTTP_ROUTE_DEFAULTS: HttpRouteOptions = {
  maxBodyMb: 25,
  hsts: true,
  upstreamHost: "public",
  rewriteLocation: true,
  responseHeaderTimeout: "60s",
  streamCloseDelay: "5m",
};

/**
 * A servable front-door HTTP route (front door §3.2, §3.5). Only routes that are enabled, `ready`
 * and allowed by a fresh lease reach the renderer. The pinned IP is the only address dialed; route
 * and stable-ID metadata authorise that exact pin.
 */
export type EdgeHttpRoute = {
  id: string;
  hostname: string;
  stableId: string;
  ip: string;
  port: number;
  /** Only `public` is rendered before FD-11; anything else fails the render. */
  access: "public" | "sso";
  /** SSO bypass paths (FD-11); validated, never rendered for public routes. */
  bypassPaths?: string[];
  /** Apex canonicalisation: answer every request with a 308 to this hostname. */
  redirectTo?: string | null;
  options?: Partial<HttpRouteOptions>;
  /** Further tailnet names of the target (MagicDNS FQDN, short name, the operator's input). */
  internalNames?: string[];
  /** Further tailnet addresses of the target node (its other address family). */
  internalIps?: string[];
};

const ROUTE_ID = /^rt_[a-z0-9]+$/;
/** Tailscale StableNodeIDs are alphanumeric (`nAbC123CNTRL`); anything else is refused, not escaped. */
const STABLE_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const BYPASS_PATH = /^\/[A-Za-z0-9._~\-/]*\*?$/;
const DURATION = /^(0|[1-9][0-9]{0,5})(ms|s|m|h)$/;
const NAME = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/;
const UNIT_MS = { ms: 1, s: 1_000, m: 60_000, h: 3_600_000 } as const;
const DAY_MS = 86_400_000;

function durationMs(value: unknown, field: string, min: number) {
  const match = typeof value === "string" ? DURATION.exec(value) : null;
  const ms = match ? Number(match[1]) * UNIT_MS[match[2] as keyof typeof UNIT_MS] : Number.NaN;
  if (!match || ms < min || ms > DAY_MS) {
    throw new ValidationError(
      `HTTP option ${field} ${JSON.stringify(value)} must be a duration such as 60s, at most 24h.`,
    );
  }
  return value as string;
}

/**
 * Parses `front_routes.http_options` into rendered options. Unknown keys (such as `redirectTo`, which
 * is read separately) are ignored; a present but invalid value is refused, never defaulted.
 */
export function httpRouteOptions(value: Record<string, unknown> | null | undefined): HttpRouteOptions {
  const input = value ?? {};
  const options = { ...HTTP_ROUTE_DEFAULTS };
  if (input.maxBodyMb !== undefined) {
    const mb = input.maxBodyMb;
    if (typeof mb !== "number" || !Number.isInteger(mb) || mb < 1 || mb > 10_240)
      throw new ValidationError(`HTTP option maxBodyMb ${JSON.stringify(mb)} must be an integer 1-10240.`);
    options.maxBodyMb = mb;
  }
  for (const key of ["hsts", "rewriteLocation"] as const) {
    if (input[key] === undefined) continue;
    if (typeof input[key] !== "boolean")
      throw new ValidationError(`HTTP option ${key} must be true or false.`);
    options[key] = input[key];
  }
  if (input.upstreamHost !== undefined) {
    if (input.upstreamHost !== "public" && input.upstreamHost !== "target")
      throw new ValidationError('HTTP option upstreamHost must be "public" or "target".');
    options.upstreamHost = input.upstreamHost;
  }
  if (input.responseHeaderTimeout !== undefined)
    options.responseHeaderTimeout = durationMs(input.responseHeaderTimeout, "responseHeaderTimeout", 1_000);
  if (input.streamCloseDelay !== undefined)
    options.streamCloseDelay = durationMs(input.streamCloseDelay, "streamCloseDelay", 0);
  if (input.streamTimeout !== undefined && input.streamTimeout !== null)
    options.streamTimeout = durationMs(input.streamTimeout, "streamTimeout", 1_000);
  return options;
}

function checkedName(hostname: string, what: string) {
  let normalized: string;
  try {
    normalized = normalizeHostname(hostname);
  } catch (error) {
    throw new ValidationError(`${what} ${JSON.stringify(hostname)}: ${(error as Error).message}`);
  }
  if (normalized !== hostname)
    throw new ValidationError(`${what} ${JSON.stringify(hostname)} is not normalized.`);
  return hostname;
}

function tailnetIp(value: string, what: string) {
  const ip = parseIpLiteral(value);
  if (!ip || checkTailnetAddress(ip) || ip.canonical !== value) {
    throw new ValidationError(`${what} ${JSON.stringify(value)} is not a canonical Tailscale address.`);
  }
  return ip;
}

/** Validates every interpolated value of a route (§3.5) and fills in the option defaults. */
export function checkedHttpRoute(route: EdgeHttpRoute) {
  if (typeof route.id !== "string" || !ROUTE_ID.test(route.id))
    throw new ValidationError(`Route id ${JSON.stringify(route.id)} is invalid.`);
  if (route.access !== "public") {
    // Fail closed: before FD-11 there is no forward_auth to render, and a gated route must never be
    // served as public.
    throw new ValidationError(
      `Route ${route.id} has access mode ${JSON.stringify(route.access)}, which this release cannot serve.`,
    );
  }
  const hostname = checkedName(route.hostname, "Route hostname");
  if (hostname.endsWith(".ts.net"))
    throw new ValidationError(`Route hostname ${hostname} is a tailnet name.`);
  const ip = tailnetIp(route.ip, "Tailnet route target");
  if (!Number.isInteger(route.port) || route.port < 1 || route.port > 65535)
    throw new ValidationError(`Tailnet route port ${JSON.stringify(route.port)} is invalid.`);
  if (typeof route.stableId !== "string" || !STABLE_ID.test(route.stableId))
    throw new ValidationError(`Route ${route.id} has no valid pinned StableID.`);
  for (const path of route.bypassPaths ?? []) {
    if (typeof path !== "string" || !BYPASS_PATH.test(path) || path.split("/").includes(".."))
      throw new ValidationError(`Bypass path ${JSON.stringify(path)} is invalid.`);
  }
  const redirectTo = route.redirectTo ? checkedName(route.redirectTo, "redirectTo") : null;
  if (redirectTo?.endsWith(".ts.net"))
    throw new ValidationError(`redirectTo ${redirectTo} is a tailnet name.`);
  if (redirectTo === hostname) throw new ValidationError(`Route ${route.id} redirects to itself.`);
  const options = httpRouteOptions(route.options as Record<string, unknown> | undefined);
  const ips = new Map([[ip.canonical, ip]]);
  for (const extra of route.internalIps ?? []) {
    const parsed = tailnetIp(extra, "Internal address");
    ips.set(parsed.canonical, parsed);
  }
  const names = new Set<string>();
  for (const name of route.internalNames ?? []) {
    const value = name.trim().toLowerCase().replace(/\.$/, "");
    // Names that cannot form a valid authority never pass the supported-forms check; skip them.
    if (value && NAME.test(value) && !parseIpLiteral(value)) names.add(value);
  }
  return {
    id: route.id,
    hostname,
    stableId: route.stableId,
    ip: ip.canonical,
    port: route.port,
    upstream: backendKey(ip.canonical, route.port),
    redirectTo,
    options,
    internalIps: [...ips.values()],
    internalNames: [...names].toSorted(),
  };
}

export type CheckedHttpRoute = ReturnType<typeof checkedHttpRoute>;

// ---- Location policy ---------------------------------------------------------------------------------------
// Pattern sources are valid both as Go RE2 (rendered with `(?i)`) and JavaScript (flag `i`), so the
// unit tests evaluate exactly what Caddy runs. No `{` or `}`: they would read as Caddyfile placeholders.

const escape = (value: string) => value.replace(/[.\\[\]()|?*+^$]/g, (char) => `\\${char}`);
const any = (items: string[]) => `(?:${items.join("|")})`;

/** Characters allowed after the authority: no controls, no backslash. */
const TAIL = "[^\\x00-\\x1f\\x7f\\x5c]*";
const LABEL = "[a-z0-9](?:[a-z0-9-]*[a-z0-9])?";
const TOP_LABEL = "[a-z](?:[a-z0-9-]*[a-z0-9])?";
const AUTHORITY_PREFIX = "(?:https?:)?//";
const END = `(?:[/?#]${TAIL})?$`;
/** A dotted quad in 100.64.0.0/10. */
const TAILSCALE_V4_TOKEN = "100\\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.[0-9]+\\.[0-9]+";

function ipv6Forms(bytes: Uint8Array, canonical: string) {
  const groups = Array.from({ length: 8 }, (_, i) => ((bytes[i * 2] ?? 0) << 8) | (bytes[i * 2 + 1] ?? 0));
  return [
    ...new Set([
      canonical,
      groups.map((group) => group.toString(16)).join(":"),
      groups.map((group) => group.toString(16).padStart(4, "0")).join(":"),
    ]),
  ];
}

export type LocationReject = { name: string; match?: string; notMatch?: string };

export type LocationPolicy = {
  /** `header_down Location <pattern> <replacement>`; null when rewriting is off. */
  rewrite: { pattern: string; replacement: string } | null;
  /** Checked in order on the raw upstream value; the first that applies answers with the static 502. */
  rejects: LocationReject[];
};

export function locationPolicy(route: CheckedHttpRoute): LocationPolicy {
  const ipAuthorities = route.internalIps.flatMap((ip) =>
    ip.version === 4
      ? [escape(ip.canonical)]
      : ipv6Forms(ip.bytes, ip.canonical).map((form) => `\\[${form}\\]`),
  );
  const nameAuthorities = route.internalNames.map((name) => `${escape(name)}\\.?`);
  const known = any([...ipAuthorities, ...nameAuthorities]);
  const internalUrl = `^${AUTHORITY_PREFIX}${known}(?::${route.port})?`;
  const tokens = any([
    ...route.internalIps.flatMap((ip) =>
      ip.version === 4 ? [escape(ip.canonical)] : ipv6Forms(ip.bytes, ip.canonical),
    ),
    ...route.internalNames.filter((name) => name.includes(".")).map(escape),
    // Any Tailscale address or MagicDNS name, not only this target's.
    TAILSCALE_V4_TOKEN,
    "fd7a:115c:a1e0:",
    "\\.ts\\.net(?:[^a-z0-9-]|$)",
  ]);
  const rewrite = route.options.rewriteLocation;
  const supported = any([
    "$",
    `/(?:[^/\\x00-\\x1f\\x7f\\x5c]${TAIL})?$`,
    `[?#]${TAIL}$`,
    `[^/?#:\\x00-\\x20\\x7f\\x5c]+(?:[/?#]${TAIL})?$`,
    `[a-z][a-z0-9+.-]*:(?:/?[^/\\x00-\\x1f\\x7f\\x5c]${TAIL})?$`,
    ...(rewrite ? [`${AUTHORITY_PREFIX}${known}(?::${route.port})?${END}`] : []),
    `${AUTHORITY_PREFIX}(?:${LABEL}\\.)+${TOP_LABEL}\\.?(?::[0-9]+)?${END}`,
  ]);
  return {
    rewrite: rewrite
      ? {
          pattern: `${internalUrl}([/?#].*|$)`,
          replacement: `https://${route.hostname}\${1}`,
        }
      : null,
    rejects: [
      { name: "malformed", notMatch: `^${supported}` },
      { name: "scheme", match: "^(?:https?|wss?|ftp|file):", notMatch: "^https?://" },
      { name: "internal", match: tokens, ...(rewrite ? { notMatch: `${internalUrl}(?:[/?#]|$)` } : {}) },
      { name: "suffix", match: `^${AUTHORITY_PREFIX}[^/?#]*[/?#].*${tokens}` },
    ],
  };
}

/**
 * What a browser receives for an upstream `Location`, evaluated the way the rendered Caddy config
 * does it: `{ status: 502 }` when a reject applies, otherwise the (possibly rewritten) value.
 */
export function evaluateLocation(policy: LocationPolicy, location: string) {
  const test = (pattern: string) => new RegExp(pattern, "i").test(location);
  for (const reject of policy.rejects) {
    if (
      (reject.match === undefined || test(reject.match)) &&
      (reject.notMatch === undefined || !test(reject.notMatch))
    )
      return { status: 502 as const, reject: reject.name };
  }
  if (!policy.rewrite) return { location };
  return {
    location: location.replace(
      new RegExp(policy.rewrite.pattern, "i"),
      policy.rewrite.replacement.replace("${1}", "$1"),
    ),
  };
}

// ---- Caddyfile ---------------------------------------------------------------------------------------------

/** Quotes a validated regular expression or value as one Caddyfile token. */
function token(value: string) {
  // The only brace allowed is the `${1}` capture reference of the Location replacement.
  const unbraced = value.replaceAll("${1}", "");
  const control = [...value].some((char) => char.charCodeAt(0) < 0x20 || char.charCodeAt(0) === 0x7f);
  // A final backslash would escape the closing quote.
  if (unbraced.endsWith("\\") || /["{}`]/.test(unbraced) || control)
    throw new ValidationError(`Refusing to render ${JSON.stringify(value)} into the Caddyfile.`);
  return `"${value}"`;
}

/** Snippets shared by every route site (§3.5). Rendered once, before the sites. */
export const HTTP_ROUTE_SNIPPETS = (errorsDir: string) => `(ark_route_base) {
  header {
    -Server
    -Via
    -X-Powered-By
    X-Content-Type-Options nosniff
    Referrer-Policy strict-origin-when-cross-origin
    defer
  }
  # Client-forged identity headers are removed before any handler (and any forward_auth) runs.
  request_header -X-Ark-*
  handle_errors 502 503 504 {
    header -Server
    root * ${errorsDir}
    rewrite * /{err.status_code}.html
    # Keep startup (Caddyfile.closed) and admin /adapt output identical for guarded restoration.
    file_server {
      hide /etc/caddy/ark/Caddyfile /etc/caddy/ark/Caddyfile.closed ./Caddyfile
    }
  }
}

(ark_upstream) {
  header_up Cookie "(^|;\\s*)__Host-ark_gate[^;]*" ""
  # Stripping the first cookie leaves its following separator; remove it as a second pass.
  header_up Cookie "^;\\s*" ""
  header_down -Server
  header_down Set-Cookie "(?i);\\s*domain=[^;]*" ""
  flush_interval -1
}
`;

/** The site body (after `bind` and `tls`) of one checked route. */
export function httpRouteSiteBody(route: CheckedHttpRoute) {
  const { options } = route;
  const hsts = options.hsts ? '  header Strict-Transport-Security "max-age=31536000"\n' : "";
  if (route.redirectTo) {
    return `  import ark_route_base
${hsts}  redir https://${route.redirectTo}{uri} 308
`;
  }
  const policy = locationPolicy(route);
  const matchers = policy.rejects
    .map((reject) => {
      const lines = [
        ...(reject.match ? [`vars_regexp {rp.header.Location} ${token(`(?i)${reject.match}`)}`] : []),
        ...(reject.notMatch
          ? [`not vars_regexp {rp.header.Location} ${token(`(?i)${reject.notMatch}`)}`]
          : []),
      ];
      return `          @ark_location_${reject.name} {\n${lines.map((line) => `            ${line}\n`).join("")}          }\n`;
    })
    .join("");
  const errors = policy.rejects
    .map((reject) => `          error @ark_location_${reject.name} 502\n`)
    .join("");
  return `  import ark_route_base
${hsts}  request_body {
    max_size ${options.maxBodyMb}MB
  }
  # Reserved for the login gate (FD-11).
  handle /.ark/gate/* {
    respond 404
  }
  handle {
    vars ark_tailnet_route ${routeIdentityKey(route)}
    reverse_proxy ${route.upstream} {
      import ark_upstream
${options.upstreamHost === "target" ? "      header_up Host {upstream_hostport}\n" : ""}      stream_close_delay ${options.streamCloseDelay}
${options.streamTimeout ? `      stream_timeout ${options.streamTimeout}\n` : ""}      transport http {
        dial_timeout 5s
        response_header_timeout ${options.responseHeaderTimeout}
        keepalive 90s
      }
      # Location (docs/design/front-door.md §3.5): Caddy joins repeated upstream values with "," in
      # {rp.header.Location}, which is what the checks see. The upstream header is dropped and exactly
      # that checked value is sent, once, after the rewrite; anything unsupported gets the static 502.
      header_down -Location
      @ark_location header Location *
      handle_response @ark_location {
        route {
${matchers}${errors}          header Location {rp.header.Location}
${policy.rewrite ? `          header Location ${token(`(?i)${policy.rewrite.pattern}`)} ${token(policy.rewrite.replacement)}\n` : ""}          copy_response
        }
      }
    }
  }
`;
}
