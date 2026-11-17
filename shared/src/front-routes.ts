// HTTP route lifecycle inputs and policy (docs/design/front-door.md §3.3, §3.13, FD-08).
//
// Pure helpers shared by the API and its tests: request schemas, the access-mode guard that holds
// until the login gate ships (FD-11), the domain claim a hostname belongs to, and which updates
// loosen exposure and therefore need an `exposure.public` step-up grant.

import { z } from "zod";

import { ValidationError } from "./errors.ts";
import { normalizeHostname } from "./hostnames.ts";

/** Kinds this release can create. TLS, TCP and Postgres routes arrive with FD-14 and FD-26. */
export const SUPPORTED_ROUTE_KINDS = ["http"] as const;

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
  })
  .strict();

export const frontRouteUpdateInput = z
  .object({
    target: target.optional(),
    targetPort: port.optional(),
    accessMode: z.enum(["public", "sso"]).optional(),
    allowSensitivePort: z.boolean().optional(),
    redirectTo: routeHostname.nullable().optional(),
  })
  .strict()
  .refine((value) => Object.values(value).some((item) => item !== undefined), {
    message: "Change at least one of target, targetPort, accessMode or redirectTo.",
  });

export type FrontRouteCreateInput = z.infer<typeof frontRouteCreateInput>;
export type FrontRouteUpdateInput = z.infer<typeof frontRouteUpdateInput>;

export function assertSupportedRouteKind(kind: string | undefined) {
  if (kind !== undefined && !(SUPPORTED_ROUTE_KINDS as readonly string[]).includes(kind)) {
    throw new UnsupportedRouteError(
      `Route kind ${JSON.stringify(kind)} is not supported yet; only "http" routes can be created.`,
    );
  }
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
