// Route lifecycle inputs and policy (docs/design/front-door.md §3.3, §3.8, §3.13, FD-08, FD-14).
//
// Pure helpers shared by the API and its tests: request schemas, the access-mode guard that holds
// until the login gate ships (FD-11), the domain claim a hostname belongs to, which updates loosen
// exposure and therefore need an `exposure.public` step-up grant, and the listener, TLS-mode and
// allowlist rules for `tls` and `tcp` routes (§3.8.2, §3.8.4, §3.8.6).

import { z } from "zod";

import {
  L4_LIMIT_BOUNDS,
  RESERVED_ROUTE_PORTS,
  SHARED_SNI_PORTS,
  SNI_ROUTER_PORT,
  TCP_ROUTE_PORTS,
  isSharedSniPort,
  isTcpRoutePort,
  l4Limits,
  routeAllowlist,
  type EdgeL4TlsMode,
  type L4Limits,
} from "./edge-l4.ts";
import { ValidationError } from "./errors.ts";
import { normalizeHostname } from "./hostnames.ts";

/** Kinds this release can create. Postgres routes arrive with FD-26. */
export const SUPPORTED_ROUTE_KINDS = ["http", "tls", "tcp"] as const;
export type SupportedRouteKind = (typeof SUPPORTED_ROUTE_KINDS)[number];

/** Access modes this release can serve. `sso` needs the login gate (FD-10, FD-11). */
export const SUPPORTED_ACCESS_MODES = ["public"] as const;

/** The lifecycle a new route moves through before it may be enabled. */
export const ROUTE_LIFECYCLE = [
  "draft",
  "awaiting_acl",
  "awaiting_dns",
  "issuing_certificate",
  "ready",
] as const;

/** Listener for HTTP routes: Host-routed behind the 443 SNI router (§3.1). */
export const HTTP_LISTEN_PORT = 443;

/** Purpose stored on the route's address records, so deletion removes exactly these rows. */
export const ROUTE_RECORD_PURPOSE = "Public route hostname";

export class UnsupportedRouteError extends ValidationError {
  constructor(message: string) {
    super(message);
    this.name = "UnsupportedRouteError";
  }
}

const target = z.string().trim().min(1).max(253);
const port = z.number().int().min(1).max(65535);
const routeHostname = z.string().trim().min(1).max(253);
const limitsInput = z
  .object({
    maxConn: z.number().int().optional(),
    perSourceConn: z.number().int().optional(),
    perSourceRate: z.number().int().optional(),
  })
  .strict();
const cidrList = z.array(z.string().trim().min(1).max(64)).max(64);
const tlsModeInput = z.enum(["passthrough", "terminate", "terminate_mtls", "plain"]);

export const frontRouteCreateInput = z
  .object({
    kind: z.string().optional(),
    hostname: routeHostname,
    target,
    targetPort: port,
    // No default: the schema default (`sso`) cannot be served before FD-11, so it is refused.
    accessMode: z.enum(["public", "sso"]).optional(),
    allowSensitivePort: z.boolean().optional(),
    // Apex `www` canonicalisation (§3.5): answer with a redirect to this hostname instead.
    redirectTo: routeHostname.nullable().optional(),
    // `tls` and `tcp` routes (FD-14).
    listenPort: port.optional(),
    tlsMode: tlsModeInput.optional(),
    sourceCidrs: cidrList.optional(),
    allowInternet: z.boolean().optional(),
    allowPlaintext: z.boolean().optional(),
    protocolAuthConfirmed: z.boolean().optional(),
    limits: limitsInput.optional(),
  })
  .strict();

export const frontRouteUpdateInput = z
  .object({
    target: target.optional(),
    targetPort: port.optional(),
    accessMode: z.enum(["public", "sso"]).optional(),
    allowSensitivePort: z.boolean().optional(),
    redirectTo: routeHostname.nullable().optional(),
    // `tls` and `tcp` routes (FD-14). The listener and kind never change; recreate the route.
    tlsMode: tlsModeInput.optional(),
    sourceCidrs: cidrList.optional(),
    allowInternet: z.boolean().optional(),
    protocolAuthConfirmed: z.boolean().optional(),
    limits: limitsInput.optional(),
  })
  .strict()
  .refine((value) => Object.values(value).some((item) => item !== undefined), {
    message:
      "Change at least one of target, targetPort, accessMode, redirectTo, tlsMode, sourceCidrs, allowInternet, protocolAuthConfirmed or limits.",
  });

export type FrontRouteCreateInput = z.infer<typeof frontRouteCreateInput>;
export type FrontRouteUpdateInput = z.infer<typeof frontRouteUpdateInput>;

export function assertSupportedRouteKind(kind: string | undefined): SupportedRouteKind {
  if (kind === undefined) return "http";
  if (!(SUPPORTED_ROUTE_KINDS as readonly string[]).includes(kind)) {
    throw new UnsupportedRouteError(
      kind === "postgres"
        ? 'Route kind "postgres" is not supported yet (FD-26); create "http", "tls" or "tcp" routes.'
        : `Route kind ${JSON.stringify(kind)} is not supported; create "http", "tls" or "tcp" routes.`,
    );
  }
  return kind as SupportedRouteKind;
}

/**
 * Until FD-11 ships there is no login gate, so an `sso` route would be served ungated. Creating,
 * enabling or switching a route into `sso`, or omitting the mode (whose schema default is `sso`),
 * is refused rather than silently treated as public.
 */
export function assertSupportedAccessMode(mode: string | undefined, action: "create" | "enable" | "update") {
  if (mode !== undefined && (SUPPORTED_ACCESS_MODES as readonly string[]).includes(mode)) return;
  const reason =
    mode === undefined
      ? 'accessMode is required. The default, "sso", is not supported yet.'
      : `Access mode ${JSON.stringify(mode)} is not supported yet.`;
  const verb = action === "enable" ? "enabled" : action === "create" ? "created" : "switched into it";
  throw new UnsupportedRouteError(
    `${reason} The login gate (FD-11) has not shipped, so an SSO route cannot be ${verb}. Choose accessMode "public".`,
  );
}

/** Normalises a public route hostname; tailnet names can never be public hostnames. */
export function normalizeRouteHostname(value: string) {
  const hostname = normalizeHostname(value);
  if (hostname === "ts.net" || hostname.endsWith(".ts.net")) {
    throw new ValidationError("Tailnet (ts.net) names cannot be public route hostnames.");
  }
  return hostname;
}

export type DomainClaimRef = { id: string; name: string; status: string };

/** The most specific domain claim containing the hostname (the apex itself included), if any. */
export function routeDomainFor<T extends DomainClaimRef>(hostname: string, claims: T[]): T | null {
  const matching = claims.filter((claim) => hostname === claim.name || hostname.endsWith(`.${claim.name}`));
  return matching.toSorted((a, b) => b.name.length - a.name.length)[0] ?? null;
}

/** A redirect target must be another hostname inside the same domain claim. */
export function normalizeRedirectTo(value: string, input: { hostname: string; zone: string }) {
  const redirect = normalizeRouteHostname(value);
  if (redirect === input.hostname) {
    throw new ValidationError("redirectTo must name a different hostname than the route itself.");
  }
  if (redirect !== input.zone && !redirect.endsWith(`.${input.zone}`)) {
    throw new ValidationError(`redirectTo must be inside the route's domain, ${input.zone}.`);
  }
  return redirect;
}

export type RouteExposure = {
  targetInput: string;
  targetPort: number;
  accessMode: string;
  redirectTo: string | null;
  /** Re-confirming a pin after an identity change re-exposes whatever the name now points at. */
  status: string;
};

/**
 * Which changes loosen exposure (§3.3: target, access mode and the like). Each needs an
 * `exposure.public` grant; tightening changes (adding a redirect, switching to a stricter mode)
 * need none.
 */
export function looseningChanges(
  current: RouteExposure,
  next: Partial<RouteExposure> & { allowSensitivePort?: boolean },
) {
  const changes: string[] = [];
  if (next.targetInput !== undefined && next.targetInput !== current.targetInput) changes.push("target");
  if (next.targetPort !== undefined && next.targetPort !== current.targetPort) changes.push("targetPort");
  if (
    next.targetInput !== undefined &&
    next.targetInput === current.targetInput &&
    (current.status === "identity_mismatch" || current.status === "error")
  ) {
    changes.push("reconfirmTarget");
  }
  if (next.accessMode === "public" && current.accessMode !== "public") changes.push("accessMode");
  if (next.redirectTo === null && current.redirectTo !== null) changes.push("redirectRemoved");
  if (next.allowSensitivePort === true) changes.push("allowSensitivePort");
  return changes;
}

// ---- TLS-TCP and raw-TCP routes (§3.8.2, §3.8.4, §3.8.6, FD-14) ------------------------------------------

/** The stored L4 settings of a `tls` or `tcp` route, after validation. */
export type L4RouteSettings = {
  kind: "tls" | "tcp";
  listenPort: number;
  tlsMode: EdgeL4TlsMode | "plain";
  sourceCidrs: string[];
  allowInternet: boolean;
  protocolAuthConfirmed: boolean;
  limits: L4Limits;
};

/** HTTP-only fields a `tls` or `tcp` route must not carry, and L4 fields an HTTP route must not. */
const HTTP_ONLY = ["accessMode", "redirectTo"] as const;
const L4_ONLY = [
  "listenPort",
  "tlsMode",
  "sourceCidrs",
  "allowInternet",
  "allowPlaintext",
  "protocolAuthConfirmed",
  "limits",
] as const;

export function assertFieldsForKind(kind: SupportedRouteKind, input: Record<string, unknown>) {
  const foreign = (kind === "http" ? L4_ONLY : HTTP_ONLY).filter((key) => input[key] !== undefined);
  if (foreign.length) {
    throw new ValidationError(`${foreign.join(", ")} cannot be set on a "${kind}" route.`);
  }
}

/**
 * Which port a route listens on, refused when it is not a listener this kind may use: `tcp` only on
 * the dedicated range, `tls` only on 443 or an enabled shared SNI port, never on a raw port, and
 * never on a platform or mail port (§3.8.2).
 */
export function routeListenPort(
  kind: "tls" | "tcp",
  requested: number | undefined,
  sniPorts: readonly number[],
) {
  if (kind === "tcp") {
    if (requested === undefined) {
      throw new ValidationError(
        `A tcp route needs a dedicated listenPort from ${TCP_ROUTE_PORTS.start}-${TCP_ROUTE_PORTS.end}.`,
      );
    }
    if ((RESERVED_ROUTE_PORTS as readonly number[]).includes(requested)) {
      throw new ValidationError(
        `Port ${requested} is a platform or mail port and cannot be a dedicated port.`,
      );
    }
    if (!isTcpRoutePort(requested)) {
      throw new ValidationError(
        `tcp routes use a dedicated port from ${TCP_ROUTE_PORTS.start}-${TCP_ROUTE_PORTS.end}; ${requested} is outside it.`,
      );
    }
    return requested;
  }
  const listenPort = requested ?? SNI_ROUTER_PORT;
  if (listenPort === SNI_ROUTER_PORT) return listenPort;
  if (isTcpRoutePort(listenPort)) {
    throw new ValidationError(
      `Port ${listenPort} is a raw TCP port; tls routes use 443 or an enabled shared SNI port.`,
    );
  }
  if ((RESERVED_ROUTE_PORTS as readonly number[]).includes(listenPort)) {
    throw new ValidationError(`Port ${listenPort} is a platform or mail port and cannot carry a tls route.`);
  }
  if (!isSharedSniPort(listenPort)) {
    throw new ValidationError(
      `tls routes use 443 or a shared SNI port (${SHARED_SNI_PORTS.join(", ")}); ${listenPort} is neither.`,
    );
  }
  if (!sniPorts.includes(listenPort)) {
    throw new ValidationError(
      `Shared SNI port ${listenPort} was not enabled at install time (enabled: ${sniPorts.join(", ") || "none"}).`,
    );
  }
  return listenPort;
}

/**
 * Validates a `tls` or `tcp` route's settings (§3.8.4): `tcp` is `plain` only, needs
 * `allowPlaintext: true`, and opens to the internet only with owner-confirmed protocol
 * authentication; `terminate` needs a restricted, non-empty allowlist. An empty list is stored and
 * means deny all; enabling then refuses (`assertL4Enableable`).
 */
export function checkL4RouteSettings(input: {
  kind: "tls" | "tcp";
  listenPort: number;
  tlsMode: string | undefined;
  sourceCidrs: string[] | undefined;
  allowInternet: boolean | undefined;
  allowPlaintext?: boolean | undefined;
  protocolAuthConfirmed: boolean | undefined;
  limits: Partial<L4Limits> | undefined;
}): L4RouteSettings {
  const sourceCidrs = [...new Set((input.sourceCidrs ?? []).map((cidr) => cidr.trim()))];
  const allowInternet = input.allowInternet === true;
  const protocolAuthConfirmed = input.protocolAuthConfirmed === true;
  // Validates the list (shape, no near-open prefixes); allowInternet is the only way to open it.
  routeAllowlist({ sourceCidrs, allowInternet: false });
  const limits = l4Limits(input.kind, input.limits);
  if (input.kind === "tcp") {
    if (input.tlsMode !== undefined && input.tlsMode !== "plain") {
      throw new ValidationError('tcp routes relay raw TCP; their tlsMode is always "plain".');
    }
    if (input.allowPlaintext !== true) {
      throw new ValidationError(
        "A plain (unencrypted) tcp route needs allowPlaintext: true, confirming the protocol may cross the internet without TLS.",
      );
    }
    if (allowInternet && !protocolAuthConfirmed) {
      throw new ValidationError(
        "Opening a plain tcp route to the internet needs protocolAuthConfirmed: true (the protocol authenticates itself, as SSH does).",
      );
    }
    return {
      kind: "tcp",
      listenPort: input.listenPort,
      tlsMode: "plain",
      sourceCidrs,
      allowInternet,
      protocolAuthConfirmed,
      limits,
    };
  }
  if (input.allowPlaintext !== undefined || input.protocolAuthConfirmed !== undefined) {
    throw new ValidationError("allowPlaintext and protocolAuthConfirmed apply to plain tcp routes only.");
  }
  const tlsMode = input.tlsMode;
  if (tlsMode === "plain") {
    throw new ValidationError('"plain" is only for tcp routes on a dedicated port; tls routes carry TLS.');
  }
  if (tlsMode !== "passthrough" && tlsMode !== "terminate" && tlsMode !== "terminate_mtls") {
    throw new ValidationError('tls routes need tlsMode "passthrough", "terminate" or "terminate_mtls".');
  }
  if (tlsMode === "terminate" && (allowInternet || !sourceCidrs.length)) {
    throw new ValidationError(
      "terminate (no client certificates) needs a restricted, non-empty sourceCidrs list and no allowInternet.",
    );
  }
  return {
    kind: "tls",
    listenPort: input.listenPort,
    tlsMode,
    sourceCidrs,
    allowInternet,
    protocolAuthConfirmed: false,
    limits,
  };
}

/**
 * Enable is refused for an L4 route that would admit nobody (empty list, no `allowInternet`), and
 * for one whose `allowInternet` was not saved under an owner `exposure.public` confirmation.
 */
export function assertL4Enableable(route: {
  kind: string;
  sourceCidrs: string[];
  allowInternet: boolean;
  internetConfirmedAt: Date | null;
  protocolAuthConfirmed: boolean;
  tlsMode: string | null;
}) {
  if (route.kind !== "tls" && route.kind !== "tcp") return;
  if (route.allowInternet) {
    if (!route.internetConfirmedAt) {
      throw new ValidationError(
        "allowInternet was not saved with an owner exposure.public confirmation; save it again with step-up.",
      );
    }
    if (route.kind === "tcp" && !route.protocolAuthConfirmed) {
      throw new ValidationError(
        "A plain tcp route open to the internet needs owner-confirmed protocol authentication.",
      );
    }
    if (route.tlsMode === "terminate") {
      throw new ValidationError(
        "terminate needs a restricted CIDR allowlist; it cannot be open to the internet.",
      );
    }
    return;
  }
  if (!route.sourceCidrs.length) {
    throw new ValidationError(
      "The route's sourceCidrs list is empty, which denies every source. Add CIDRs, or set allowInternet with an exposure.public step-up.",
    );
  }
}

/** Which L4 policy changes loosen exposure, and therefore need an `exposure.public` grant. */
export function l4LooseningChanges(current: L4RouteSettings, next: L4RouteSettings) {
  const changes: string[] = [];
  const known = new Set(current.sourceCidrs);
  if (next.sourceCidrs.some((cidr) => !known.has(cidr))) changes.push("sourceCidrs");
  if (next.allowInternet && !current.allowInternet) changes.push("allowInternet");
  if (next.protocolAuthConfirmed && !current.protocolAuthConfirmed) changes.push("protocolAuthConfirmed");
  for (const key of Object.keys(L4_LIMIT_BOUNDS) as Array<keyof L4Limits>) {
    if (next.limits[key] > current.limits[key]) changes.push(`limits.${key}`);
  }
  const strength = { terminate_mtls: 3, passthrough: 2, terminate: 1, plain: 0 } as const;
  if (next.tlsMode !== current.tlsMode && strength[next.tlsMode] < strength[current.tlsMode])
    changes.push("tlsMode");
  return changes;
}

/** The protocol guidance shown in the UI (§3.8.2): which protocols can be routed by name. */
export const PROTOCOL_GUIDANCE = [
  {
    protocol: "HTTPS, WebSocket over TLS",
    tlsFirst: "yes",
    byName: "yes (443)",
    kind: "http",
    notes: "Through Caddy.",
  },
  {
    protocol: "PostgreSQL ≥ 17 with sslnegotiation=direct",
    tlsFirst: "yes",
    byName: "yes (5432)",
    kind: "postgres",
    notes: "Postgres routes arrive with FD-26.",
  },
  {
    protocol: "PostgreSQL classic (SSLRequest)",
    tlsFirst: "no: 8-byte preamble first",
    byName: "no",
    kind: null,
    notes: "Goes to PgBouncer; a compatibility port serves tailnet targets (FD-26).",
  },
  {
    protocol: "MQTT over TLS, AMQPS, LDAPS, Redis/Valkey TLS",
    tlsFirst: "yes",
    byName: "yes (443 or the protocol's shared port)",
    kind: "tls",
    notes: "Standard implicit TLS.",
  },
  {
    protocol: "MongoDB TLS",
    tlsFirst: "yes",
    byName: "yes, standalone only",
    kind: "tls",
    notes: "Replica-set discovery returns members' own hostnames, so clients need directConnection=true.",
  },
  {
    protocol: "NATS",
    tlsFirst: "no by default (server sends INFO first)",
    byName: "only with handshake_first",
    kind: "tls",
    notes: "Enable handshake_first on the server and client.",
  },
  {
    protocol: "MySQL / MariaDB",
    tlsFirst: "no (SSLRequest-style upgrade)",
    byName: "no",
    kind: "tcp",
    notes: "Dedicated port with plain mode, or keep it on the tailnet.",
  },
  {
    protocol: "SMTP 25/587, IMAP 143 (STARTTLS)",
    tlsFirst: "no",
    byName: "no",
    kind: null,
    notes: "Not offered (mail is Stalwart's).",
  },
  {
    protocol: "SSH, RDP, game protocols, raw MQTT 1883",
    tlsFirst: "no TLS",
    byName: "no",
    kind: "tcp",
    notes: "Dedicated port from the range.",
  },
] as const;
