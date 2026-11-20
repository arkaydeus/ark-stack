import { repositoryProtectionPolicy } from "@ark-stack/shared";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import {
  assertAliasGraph,
  assertExternalForwarding,
  canTransition,
  canonicalizeComposeSource,
  canViewDomain,
  canViewProject,
  classifySql,
  createId,
  createToken,
  privilegedRequestHash,
  s3TargetInput,
  tailnetRestTargetInput,
  PROVIDER_RECIPES,
  TAILNET_REST_RECIPE,
  writerPolicy,
  localPart,
  normalizeHostname,
  redactValue,
  secureEqual,
  adoptionPreview,
  assertCidrs,
  ipv6ProbeReport,
  canMutateQueue,
  classifyDiscovery,
  checkPoolerPolicy,
  poolerAdmission,
  poolerPolicyInput,
  poolerPolicyLoosens,
  POOLER_POLICY_BOUNDARY,
  POSTGRES_DRIVER_GUIDANCE,
  POSTGRES_ROUTE_NOTES,
  POSTGRES_ROUTER_PORT,
  POSTGRES_TARGET_CHECKLIST,
  maintainInput,
  queueActionInput,
  deviceInput,
  cidrInput,
  adoptInput,
  redactQueueItem,
  validateComposeSource,
  wizardInput,
  domainInput,
  dnsPublishInput,
  mailboxInput,
  aliasInput,
  databaseInput,
  databaseClientInput,
  defaultClientRoleKind,
  earlyRolloverInput,
  rolloverConfirmInput,
  RETIREMENT_ALERT_PREFIX,
  ROLLOVER_ALERT_PREFIX,
  projectInput,
  serviceInput,
  sqlInput,
  sqlCancelInput,
  settingsInput,
  regionSettingsInput,
  regionSummary,
  ingressCounterMetrics,
  mailEnabled,
  rebootRequiredMetrics,
  dbIngressLimitsInput,
  dbIngressLimitsSummary,
  platformDbIngressLimits,
  frontRouteCreateInput,
  frontRouteUpdateInput,
  gateSettingsInput,
  PROTOCOL_GUIDANCE,
  RESERVED_ROUTE_PORTS,
  SHARED_SNI_PORTS,
  TCP_ROUTE_PORTS,
  isGateLoginPath,
  GATE_EDGE_API_PATHS,
  checkLoginNext,
  gateUserCreateBinding,
  gateUserDeleteBinding,
  gateUserInput,
  gateUserRevealBinding,
  GATE_USER_PASSWORD_SECRET_KIND,
  routeAccessInput,
  buildDomainPlan,
  nextBackupStatus,
  redactLogLine,
  ValidationError,
  type Access,
  type BackupStatus,
  type OperationState,
  type Role,
} from "@ark-stack/shared";
import { serveStatic } from "@hono/node-server/serve-static";
import { and, desc, eq, isNull } from "drizzle-orm";
import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import { HTTPException } from "hono/http-exception";
import { z } from "zod";

import { AUTH_COOKIE_KEYS, auth, authCookieName } from "./auth.ts";
import { CLIENT_IP_HEADER, EDGE_TOKEN_HEADER, transportPeer, trustedClientIp } from "./client-ip.ts";
import { originForHost, refreshLoginHost, requestHost } from "./origin-hosts.ts";
import type { SessionOrigin } from "./session-origin.ts";
import {
  GateSettingsError,
  commitGateSettings,
  enqueueGateOperation,
  gateSettingsSummary,
  prepareGateSettings,
} from "./modules/gate-settings.ts";
import {
  assertSecretRevealable,
  grantAccess,
  redactDomain,
  requireDatabaseAccess,
  requireDomain,
  requireDomainMailbox,
  requireMfa,
  requireOperator,
  requireOwner,
  requirePrivileged,
  requireProject,
  type SessionValue,
} from "./access.ts";
import {
  assertExecutionAuthorized,
  claimQueued,
  EDGE_WITHDRAWAL_ALERT,
  enqueue,
  finalizeAgentCompletion,
  heartbeatClaim,
  queuePoolerEdgeApply,
} from "./coordinator.ts";
import { loadPoolerPolicy } from "./modules/pooler-policy.ts";
import { db, sql } from "./db.ts";
import { loadEnv } from "./env.ts";
import {
  ipv6PreflightChallenge,
  ipv6PreflightKey,
  ipv6PreflightKind,
  ipv6PreflightTarget,
  ipv6PreflightResultPath,
  ipv6Settings,
  ipv6Summary,
  verifyIpv6Submission,
} from "./modules/ipv6-preflight.ts";
import { revealSecret } from "./coordinator.ts";
import { getChallenge } from "./modules/certificates.ts";
import { DnsReviewError } from "./modules/cloudflare-dns.ts";
import {
  changeAaaaSetting,
  desiredDns,
  dnsRecordValues,
  domainDnsReview,
  pendingWithdrawal,
  queueDnsPublish,
  dnsPublishStatus,
  revokeAaaaWithdrawal,
  watchManualDns,
} from "./modules/domain-dns.ts";
import { frontAclSnippet } from "./modules/front-acl.ts";
import {
  FrontRouteError,
  commitRouteCreate,
  commitRouteDelete,
  commitRouteEnable,
  commitRouteUpdate,
  disableRoute,
  issueRouteClientCertificate,
  listFrontRoutes,
  listRouteClientCertificates,
  revokeRouteClientCertificate,
  prepareRouteCreate,
  prepareRouteDelete,
  prepareRouteEnable,
  prepareRouteUpdate,
} from "./modules/front-routes.ts";
import { EDGE_OBSERVE_TARGET, tailnetOverview } from "./modules/edge-observe.ts";
import { enabledSniPorts } from "./modules/l4-routes.ts";
import {
  RouteAccessError,
  gateAuthorize,
  gateBypassCheck,
  gateCallback,
  gateCheck,
  gateLogoutRoute,
  listRouteAccess,
  replaceRouteAccess,
  type GateResponse,
} from "./modules/gate.ts";
import { edgeLeaseDocument } from "./modules/gate-revocations.ts";
import {
  enrollPage,
  gateBrandAsset,
  gateMessagePage,
  gateNonce,
  gatePageHeaders,
  loginPage,
} from "./gate-pages.ts";
import {
  createGateUser,
  deleteGateUser,
  listGateUsers,
  revealGateUserPassword,
} from "./modules/gate-users.ts";
import { raiseAlert } from "./modules/alerts.ts";
import {
  backupHealth,
  publicTarget,
  saveS3Target,
  saveTailnetRestTarget,
} from "./modules/offsite-backups.ts";
import { BACKUP_OBSERVE_TARGET, backupTailnetOverview } from "./modules/backup-observe.ts";
import {
  CLIENT_PASSWORD_SECRET_KIND,
  DatabaseClientError,
  databaseClientContext,
  databaseClientVercelGuide,
  getDatabaseClient,
  listDatabaseClients,
  queueClientIssue,
  queueClientRevocation,
  consumeClientIssueAttempt,
  revealDatabaseClient,
} from "./modules/db-clients.ts";
import {
  confirmRolloverDelivery,
  queueEarlyRollover,
  revealRolloverSuccessor,
  rolloverStatus,
} from "./modules/db-client-rollover.ts";
import {
  connectVercel,
  disconnectVercel,
  testVercelConnection,
  vercelConnectInput,
  vercelIntegrationStatus,
} from "./modules/vercel-integrations.ts";
import { vercelConnectBinding } from "./modules/vercel-api.ts";
import { CLIENT_KEY_SECRET_KIND, PkiPolicyError, validateCsr } from "./modules/pki.ts";
import { cancelWorkspaceQuery } from "./modules/database.ts";
import { writeApprovedCompose } from "./modules/docker.ts";
import { dbIngressCountersFile } from "./modules/providers.ts";
import { listMailQueue } from "./modules/queue.ts";
import {
  alerts,
  aliases,
  auditEvents,
  backups,
  certificates,
  clientCertificates,
  databaseClients,
  databaseClusters,
  databaseRoles,
  dnsRecords,
  domainClaims,
  endpoints,
  frontRoutes,
  mailDomains,
  mailboxes,
  mailboxDevices,
  managedDatabases,
  operationSteps,
  operations,
  platformAccess,
  platformSettings,
  backupTargets,
  platformSetup,
  projects,
  secrets,
  services,
  stepUpGrants,
  updateCandidates,
  user,
  workerHeartbeats,
} from "./schema.ts";

type AppEnv = {
  Variables: {
    session: SessionValue;
    access: Access;
    worker: string;
    /** The registered origin of this request's canonical host (origin-hosts.ts), when it has one. */
    requestOrigin: { host: string; origin: SessionOrigin };
  };
};

const env = loadEnv();
export const app = new Hono<AppEnv>();

app.use("/api/*", bodyLimit({ maxSize: 256 * 1024 }));
app.onError((error, c) => {
  if (error instanceof HTTPException) return c.json({ error: error.message }, error.status);
  if (error instanceof z.ZodError) return c.json({ error: z.prettifyError(error) }, 422);
  // Better Auth surfaces its own failures (a wrong step-up password, for example) as APIError.
  // Reporting those as 500 hides an actionable message behind a generic one.
  if (isApiError(error)) {
    const status =
      error.status === 401
        ? 401
        : error.status === 403
          ? 403
          : error.status === 404
            ? 404
            : error.status === 409
              ? 409
              : error.status === 429
                ? 429
                : 422;
    return c.json({ error: redactLogLine(error.message) }, status);
  }
  // Input validators in shared/ reject with plain Errors. They describe a caller mistake, not a
  // server fault, so they belong in the response rather than only in the log.
  if (error instanceof ValidationError) return c.json({ error: error.message }, 422);
  if (error instanceof DatabaseClientError) return c.json({ error: error.message }, error.status);
  if (error instanceof FrontRouteError) return c.json({ error: error.message }, error.status);
  if (error instanceof DnsReviewError) return c.json({ error: error.message }, error.status);
  if (error instanceof GateSettingsError) return c.json({ error: error.message }, error.status);
  if (error instanceof RouteAccessError) return c.json({ error: error.message }, error.status);
  // CSR and CA policy refusals (CsrError included) describe the submitted input; no key material.
  if (error instanceof PkiPolicyError) return c.json({ error: error.message }, 422);
  console.error(error instanceof Error ? error.message : error);
  return c.json({ error: "The request could not be completed." }, 500);
});

const STEP_UP_MAX_FAILURES = 5;
const STEP_UP_LOCKOUT_MS = 15 * 60 * 1000;
const stepUpFailures = new Map<string, { count: number; firstAt: number }>();

function assertStepUpAttemptAllowed(userId: string) {
  const record = stepUpFailures.get(userId);
  if (!record) return;
  if (Date.now() - record.firstAt > STEP_UP_LOCKOUT_MS) {
    stepUpFailures.delete(userId);
    return;
  }
  if (record.count >= STEP_UP_MAX_FAILURES) {
    throw new HTTPException(429, {
      message: "Too many failed verification attempts. Wait before requesting another step-up grant.",
    });
  }
}

function recordStepUpFailure(userId: string) {
  const now = Date.now();
  const record = stepUpFailures.get(userId);
  if (!record || now - record.firstAt > STEP_UP_LOCKOUT_MS) {
    stepUpFailures.set(userId, { count: 1, firstAt: now });
    return;
  }
  record.count += 1;
}

function clearStepUpFailures(userId: string) {
  stepUpFailures.delete(userId);
}

function isApiError(error: unknown): error is Error & { status: number } {
  if (!(error instanceof Error) || !("status" in error)) return false;
  const status = (error as { status: unknown }).status;
  return typeof status === "number" && status >= 400 && status < 500;
}

// Paths served for any Host: they carry their own credentials (worker, watchdog, metrics bearer
// tokens, or the edge token on the gate's edge handlers, which arrive with the route's public Host)
// or none at all (health, ACME), never an admin session, and Docker peers reach them by service name
// (`api:3000`).
function hostIndependent(path: string) {
  return (
    path.startsWith("/api/internal/") ||
    (GATE_EDGE_API_PATHS as readonly string[]).includes(path) ||
    path === "/api/health" ||
    path === "/api/metrics/prometheus" ||
    path.startsWith("/.well-known/acme-challenge/")
  );
}

// Host guard (front door §3.5, §3.9.1, FD-10). The canonical Host must be a registered admin host or
// the login host; unknown, malformed or contradictory hosts are refused before Better Auth runs,
// with no fallback to the admin origin. On the login host only the login allowlist exists: every
// other path, `/api/internal/*` and `/api/health` included, is 404 here as well as at the edge.
app.use("*", async (c, next) => {
  await refreshLoginHost();
  const host = requestHost(c.req.raw);
  const origin = originForHost(host);
  const path = new URL(c.req.url).pathname;
  if (origin === "gate") {
    if (!isGateLoginPath(path)) return c.json({ error: "Not found." }, 404);
  } else if (!origin && !hostIndependent(path)) {
    return c.json({ error: "This host is not a registered Ark origin." }, 421);
  }
  if (host && origin) c.set("requestOrigin", { host, origin });
  await next();
});

/** Refuses a Cookie header that names any Better Auth cookie more than once (§3.9.1). */
function assertSingleAuthCookies(headers: Headers) {
  const names = new Set(AUTH_COOKIE_KEYS.map(authCookieName));
  const seen = new Set<string>();
  for (const pair of (headers.get("cookie") ?? "").split(";")) {
    const name = pair.split("=", 1)[0]!.trim();
    if (!names.has(name)) continue;
    if (seen.has(name)) {
      throw new HTTPException(400, { message: "Duplicate authentication cookies were sent." });
    }
    seen.add(name);
  }
}

/**
 * The headers Better Auth sees for this request: the canonical registered Host (its dynamic base
 * URL is built from it), the trusted client address in `X-Ark-Client-Ip` (client-ip.ts; any
 * client-sent value is replaced or removed) and no edge token.
 */
function authHeaders(c: Context<AppEnv>) {
  const requestOrigin = c.get("requestOrigin");
  if (!requestOrigin) throw new HTTPException(421, { message: "This host is not a registered Ark origin." });
  assertSingleAuthCookies(c.req.raw.headers);
  const headers = new Headers(c.req.raw.headers);
  const { ip } = trustedClientIp({
    path: new URL(c.req.url).pathname,
    origin: requestOrigin.origin,
    headers: c.req.raw.headers,
    peer: transportPeer(c.env, c.req.raw),
    edgeToken: env.edgeGateToken,
    edgePeers: env.edgePeerAddresses,
  });
  headers.delete(CLIENT_IP_HEADER);
  if (ip) headers.set(CLIENT_IP_HEADER, ip);
  headers.delete(EDGE_TOKEN_HEADER);
  headers.set("host", requestOrigin.host);
  return headers;
}

/** The request handed to `auth.handler`, with `authHeaders`. */
function authRequest(c: Context<AppEnv>) {
  const headers = authHeaders(c);
  const requestOrigin = c.get("requestOrigin");
  // The public login origin accepts browser mutations only from itself; Better Auth's own origin
  // check also trusts the admin origins.
  if (
    requestOrigin.origin === "gate" &&
    !["GET", "HEAD", "OPTIONS"].includes(c.req.method) &&
    c.req.header("origin") !== `https://${requestOrigin.host}`
  ) {
    throw new HTTPException(403, { message: "The request origin is not trusted." });
  }
  return new Request(c.req.raw, { headers });
}

// ---- Login gate: edge handlers (front door §3.9, FD-11) ----------------------------------------------
// Only the edge calls these, with `X-Ark-Edge-Token` (and, when `ARK_EDGE_PEER_ADDRESSES` is set, from
// one of those exact peers). They are on no public or tailnet path allowlist: the login origin and
// both gateways answer 404, and route hosts reach only the exact callback and logout rewrites. The
// token authenticates the edge as a caller of these four handlers and grants no other authority.

function edgeGateCaller(c: Context<AppEnv>) {
  if (!env.edgeGateToken) return false;
  if (!secureEqual(c.req.header(EDGE_TOKEN_HEADER) ?? "", env.edgeGateToken)) return false;
  const peer = transportPeer(c.env, c.req.raw);
  return env.edgePeerAddresses.length === 0 || Boolean(peer && env.edgePeerAddresses.includes(peer));
}

function sendGate(result: GateResponse) {
  const headers = new Headers();
  for (const [name, value] of result.headers) headers.append(name, value);
  return new Response(result.body ?? null, { status: result.status, headers });
}

const edgeOnly = (c: Context<AppEnv>) =>
  c.json({ error: "This endpoint is for the edge only." }, 401, {
    "WWW-Authenticate": "Ark-Edge",
    "Cache-Control": "no-store",
  });

/** The client address Caddy wrote from the PROXY v2 header (one address), for gate session records. */
function edgeClientIp(c: Context<AppEnv>) {
  const forwarded = (c.req.header("x-forwarded-for") ?? "").split(",").map((value) => value.trim());
  return forwarded.length === 1 && forwarded[0] ? forwarded[0].slice(0, 64) : null;
}

app.get("/api/gate/check", async (c) => {
  if (!edgeGateCaller(c)) return edgeOnly(c);
  return sendGate(
    await gateCheck({
      routeId: c.req.query("route") ?? null,
      host: requestHost(c.req.raw),
      cookie: c.req.header("cookie") ?? null,
      method: c.req.header("x-forwarded-method") ?? null,
      uri: c.req.header("x-forwarded-uri") ?? null,
      accept: c.req.header("accept") ?? null,
      origin: c.req.header("origin") ?? null,
      upgrade: c.req.header("x-ark-upgrade") || c.req.header("upgrade") || null,
    }),
  );
});

app.get("/api/gate/bypass-check", async (c) => {
  if (!edgeGateCaller(c)) return edgeOnly(c);
  return sendGate(
    await gateBypassCheck({
      routeId: c.req.query("route") ?? null,
      host: requestHost(c.req.raw),
      originalUri: c.req.header("x-ark-original-uri") ?? null,
    }),
  );
});

app.get("/api/gate/callback", async (c) => {
  if (!edgeGateCaller(c)) return edgeOnly(c);
  const url = new URL(c.req.url);
  return sendGate(
    await gateCallback({
      host: requestHost(c.req.raw),
      routeHeader: c.req.header("x-ark-route") ?? null,
      code: url.searchParams.get("code"),
      state: url.searchParams.get("state"),
      cookie: c.req.header("cookie") ?? null,
      ipAddress: edgeClientIp(c),
      userAgent: c.req.header("user-agent") ?? null,
    }),
  );
});

app.post("/api/gate/logout-route", async (c) => {
  if (!edgeGateCaller(c)) return edgeOnly(c);
  return sendGate(
    await gateLogoutRoute({
      host: requestHost(c.req.raw),
      routeHeader: c.req.header("x-ark-route") ?? null,
      origin: c.req.header("origin") ?? null,
      cookie: c.req.header("cookie") ?? null,
    }),
  );
});

// Any other method on the gate's edge handlers (the edge answers 405 before forwarding as well).
app.all("/api/gate/:handler{(check|bypass-check|callback|logout-route)}", (c) =>
  edgeGateCaller(c) ? c.json({ error: "Method not allowed." }, 405) : edgeOnly(c),
);

app.get("/api/health", async (c) => {
  await sql`SELECT 1`;
  return c.json({ status: "ok" });
});

app.get("/.well-known/acme-challenge/:token", (c) => {
  const challenge = getChallenge(c.req.param("token"));
  if (!challenge) return c.text("not found", 404);
  return c.text(challenge.keyAuthorization);
});

app.get("/api/setup/status", async (c) => {
  const [setup] = await db.select().from(platformSetup).where(eq(platformSetup.id, "default"));
  return c.json({
    required: !setup?.completed,
    wizardRequired: Boolean(setup?.completed && !setup.wizardCompleted),
  });
});

app.post("/api/auth/sign-up/email", async (c) => {
  const connection = await sql.reserve();
  await connection`SELECT pg_advisory_lock(8042102)`;
  try {
    const [setup] = await connection`SELECT completed FROM platform_setup WHERE id='default'`;
    const [existing] = await connection`SELECT count(*)::int AS count FROM "user"`;
    if (!setup?.completed && existing.count) {
      await connection`INSERT INTO platform_access(user_id, role) SELECT id, 'owner' FROM "user" ON CONFLICT DO NOTHING`;
      await connection`UPDATE platform_setup SET completed=true, bootstrap_closed_at=now() WHERE id='default'`;
      throw new HTTPException(403, {
        message: "Setup is already complete. Sign in with the existing administrator.",
      });
    }
    if (setup?.completed || !secureEqual(c.req.header("x-setup-token") ?? "", env.setupToken)) {
      throw new HTTPException(403, { message: "Administrator setup is closed or the token is invalid." });
    }
    const response = await auth.handler(authRequest(c));
    if (response.ok) {
      await connection`INSERT INTO platform_access(user_id, role) SELECT id, 'owner' FROM "user" ON CONFLICT DO NOTHING`;
      await connection`UPDATE platform_setup SET completed=true, bootstrap_closed_at=now() WHERE id='default'`;
    }
    return response;
  } finally {
    await connection`SELECT pg_advisory_unlock(8042102)`;
    connection.release();
  }
});

app.all("/api/auth/*", async (c) => {
  const enrollmentVerification = c.req.path.endsWith("/two-factor/verify-totp");
  const request = authRequest(c);
  const sessionBefore = enrollmentVerification
    ? await auth.api.getSession({ headers: request.headers })
    : null;
  const response = await auth.handler(request);
  if (response.ok && enrollmentVerification && sessionBefore?.user.id) {
    const [verifiedUser] = await db.select().from(user).where(eq(user.id, sessionBefore.user.id));
    if (verifiedUser?.twoFactorEnabled && !verifiedUser.mfaEnrolledAt) {
      await sql`
        UPDATE "user"
        SET mfa_enrolled_at = (
          SELECT max(created_at) FROM session WHERE user_id = ${sessionBefore.user.id}
        ), updated_at = now()
        WHERE id = ${sessionBefore.user.id}
          AND two_factor_enabled = true
          AND mfa_enrolled_at IS NULL
      `;
    }
  }
  return response;
});

// `update.apply` belongs to the agent alone: its planning half delegates a compose payload and
// requeues, so a module worker holding the `update.` prefix would re-plan the same operation on
// every poll, minting a deployment revision each time. Module workers get `update.detect` only.
const workerPrefixes: Record<string, string[]> = {
  database: ["database.", "pgbouncer."],
  // `integration.` (front door §3.4): the domain worker is the only worker with external egress.
  domains: ["domain.", "dns.", "certificate.", "edge.", "admin.", "integration.", ipv6PreflightKind],
  mail: ["mail.", "mailbox.", "ses."],
  backup: [
    "backup.",
    "backup.create",
    "backup.restore_test",
    "backup.export",
    "backup.verify_target",
    "backup.observe",
    "update.detect",
    "import.",
  ],
  agent: ["service.", "update.apply"],
  module: [
    "database.",
    "pgbouncer.",
    "mail.",
    "mailbox.",
    "ses.",
    "domain.",
    "dns.",
    "certificate.",
    "edge.",
    "admin.",
    "backup.",
    "update.detect",
    "import.",
  ],
};

function workerCanExecute(identity: string, kind: string) {
  return (workerPrefixes[identity] ?? []).some((prefix) =>
    prefix.endsWith(".") ? kind.startsWith(prefix) : kind === prefix,
  );
}

app.use("/api/internal/*", async (c, next) => {
  const supplied = c.req.header("authorization") ?? "";
  let identity = "";
  if (secureEqual(supplied, `Bearer ${env.agentToken}`)) identity = "agent";
  else {
    for (const name of ["database", "domains", "mail", "backup"] as const) {
      if (
        process.env[`ARK_${name === "domains" ? "DOMAIN" : name.toUpperCase()}_WORKER_TOKEN`] &&
        secureEqual(supplied, `Bearer ${env.workerTokens[name]}`)
      ) {
        identity = name;
        break;
      }
    }
  }
  if (!identity && secureEqual(supplied, `Bearer ${env.internalToken}`)) identity = "module";
  // The edge-local lease watchdog (front door §3.2, FD-06) reads the lease and reports withdrawal
  // events; it may not heartbeat, claim or complete operations.
  const watchdogToken = process.env.ARK_EDGE_WATCHDOG_TOKEN?.trim() ?? "";
  if (!identity && watchdogToken && secureEqual(supplied, `Bearer ${watchdogToken}`)) {
    identity = "edge-watchdog";
  }
  if (!identity) throw new HTTPException(401, { message: "Invalid worker credential." });
  if (identity === "edge-watchdog" && !c.req.path.startsWith("/api/internal/edge/")) {
    throw new HTTPException(403, { message: "The edge watchdog may only read the edge lease." });
  }
  if (identity !== "edge-watchdog" && c.req.path.startsWith("/api/internal/edge/")) {
    throw new HTTPException(403, { message: "Only the edge watchdog reads the edge lease." });
  }
  c.set("worker", identity);
  await next();
});

// Read-only lease and policy for the edge-local watchdog and launch guard (front door §3.2): the
// latest generation's lease and the tailnet backends the proxies may dial right now. Polled every
// second, independently of the operation workers.
app.get("/api/internal/edge/lease", async (c) => {
  c.header("cache-control", "no-store");
  // The lease policy minus routes whose gate revocation is overdue (FD-11, §3.9.3).
  return c.json(await edgeLeaseDocument());
});

app.post("/api/internal/edge/watchdog-event", async (c) => {
  const body = z
    .object({
      event: z.enum(["withdrawn", "withdrawal_failed", "proxy_stopped", "stop_failed", "policy_unavailable"]),
      proxy: z.string().max(40).optional(),
      detail: z.string().max(1000),
    })
    .parse(await c.req.json());
  const detail = String(redactLogLine(body.detail)).slice(0, 500);
  await audit(undefined, `edge.watchdog.${body.event}`, "edge", body.proxy ?? "edge", { detail });
  // Re-render from the current policy, so the files on disk (and the launch guard) agree with what
  // the watchdog left serving, and a route withdrawn on a momentarily stale policy comes back.
  // edge.apply only ever renders what the policy allows; a queued one is reused.
  await enqueue({ kind: "edge.apply", targetIds: ["platform"] });
  if (body.event !== "withdrawn") {
    await raiseAlert({
      severity: "critical",
      title:
        body.event === "proxy_stopped"
          ? `Edge watchdog stopped ${body.proxy ?? "a proxy"} after a failed route withdrawal`
          : `Edge watchdog: ${body.event.replaceAll("_", " ")} (${body.proxy ?? "edge"}): ${detail}`,
      dedupKey: EDGE_WITHDRAWAL_ALERT,
    });
  }
  return c.json({ ok: true });
});

app.post("/api/internal/heartbeat", async (c) => {
  const body = z.object({ version: z.string().min(1).max(100) }).parse(await c.req.json());
  await db
    .insert(workerHeartbeats)
    .values({ identity: c.get("worker"), version: body.version, lastSeenAt: new Date() })
    .onConflictDoUpdate({
      target: workerHeartbeats.identity,
      set: { version: body.version, lastSeenAt: new Date() },
    });
  return c.json({ ok: true });
});

app.get("/api/internal/jobs", async (c) => {
  if (c.get("worker") === "agent") {
    const claimed = await claimQueued({ limit: 1, agentOwned: true });
    const authorized = [];
    for (const row of claimed.rows) {
      try {
        await assertExecutionAuthorized(row);
        authorized.push(row);
      } catch (error) {
        await db
          .update(operations)
          .set({
            status: "failed",
            claimToken: null,
            error: String(redactValue(error instanceof Error ? error.message : "Authorization was revoked.")),
            updatedAt: new Date(),
          })
          .where(and(eq(operations.id, row.id), eq(operations.claimToken, claimed.token)));
      }
    }
    return c.json({
      jobs: authorized.map((row) => ({ ...row, claimToken: claimed.token })),
    });
  }
  const requested = (c.req.header("x-ark-worker-kinds") ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const allowed = new Set(workerPrefixes[c.get("worker")] ?? []);
  if (!requested.length || requested.some((item) => !allowed.has(item))) {
    throw new HTTPException(403, { message: "A valid worker job allowlist is required." });
  }
  const preflight = requested.includes(ipv6PreflightKind);
  const claimed = await claimQueued({
    limit: 1,
    kindPrefixes: requested.filter((kind) => kind !== ipv6PreflightKind),
    exactKinds: preflight ? [ipv6PreflightKind] : [],
    excludeKinds: preflight ? [] : [ipv6PreflightKind],
  });
  return c.json({ jobs: claimed.rows.map((row) => ({ ...row, claimToken: claimed.token })) });
});

app.post("/api/internal/jobs/:id/heartbeat", async (c) => {
  const body = z.object({ claimToken: z.string().min(1) }).parse(await c.req.json());
  const [operation] = await db
    .select()
    .from(operations)
    .where(eq(operations.id, c.req.param("id")));
  if (!operation || !workerCanExecute(c.get("worker"), operation.kind)) {
    throw new HTTPException(403, { message: "This worker may not heartbeat that operation kind." });
  }
  if (c.get("worker") === "agent") {
    await assertExecutionAuthorized(operation).catch(() => {
      throw new HTTPException(403, { message: "The operation actor is no longer authorized." });
    });
  }
  if (!(await heartbeatClaim(c.req.param("id"), body.claimToken))) {
    throw new HTTPException(409, { message: "The operation lease is stale or no longer owned." });
  }
  return c.json({ ok: true });
});

app.post("/api/internal/jobs/:id/complete", async (c) => {
  const body = z
    .object({
      status: z.enum(["succeeded", "failed"]),
      error: z.string().optional(),
      evidence: z.record(z.string(), z.unknown()).optional(),
      claimToken: z.string().min(1).optional(),
    })
    .parse(await c.req.json());
  const [operation] = await db
    .select()
    .from(operations)
    .where(eq(operations.id, c.req.param("id")));
  if (!operation) throw new HTTPException(404, { message: "Operation not found." });
  if (!workerCanExecute(c.get("worker"), operation.kind)) {
    throw new HTTPException(403, { message: "This worker may not complete that operation kind." });
  }
  if (operation.status !== "running") {
    throw new HTTPException(409, { message: "Operation is not claimed for completion." });
  }
  if (!body.claimToken || !operation.claimToken || operation.claimToken !== body.claimToken) {
    throw new HTTPException(403, { message: "Claim token does not match this job." });
  }
  if (c.get("worker") === "agent" && body.status === "succeeded") {
    await assertExecutionAuthorized(operation).catch(() => {
      throw new HTTPException(403, { message: "The operation actor is no longer authorized." });
    });
  }
  if (!canTransition(operation.status as OperationState, body.status)) {
    throw new HTTPException(409, {
      message: `Operation cannot move from ${operation.status} to ${body.status}.`,
    });
  }
  try {
    await db.transaction(async (tx) => {
      const updated = await tx
        .update(operations)
        .set({
          status: body.status,
          error: body.error ? String(redactValue(body.error)).slice(0, 1000) : null,
          claimToken: null,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(operations.id, operation.id),
            eq(operations.status, "running"),
            eq(operations.claimToken, body.claimToken!),
          ),
        )
        .returning({ id: operations.id });
      if (updated.length !== 1) {
        throw new HTTPException(409, { message: "The operation lease changed before completion." });
      }
      if (body.evidence) {
        await tx.insert(operationSteps).values({
          id: createId("step"),
          operationId: operation.id,
          name: "worker-complete",
          status: body.status,
          evidence: redactValue(body.evidence) as Record<string, unknown>,
          error: body.error ? String(redactValue(body.error)).slice(0, 1000) : undefined,
        });
      }
      if (c.get("worker") === "agent") {
        await finalizeAgentCompletion(operation, body.status === "succeeded", tx);
      }
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    throw error;
  }
  return c.json({ ok: true });
});

async function readDbIngressCounters() {
  try {
    return JSON.parse(await readFile(dbIngressCountersFile(), "utf8")) as unknown;
  } catch {
    return null;
  }
}

app.get("/api/metrics/prometheus", async (c) => {
  if (!secureEqual(c.req.header("authorization") ?? "", `Bearer ${env.metricsToken}`)) {
    throw new HTTPException(401, { message: "Invalid metrics credential." });
  }
  const hostMetricsDir = process.env.ARK_HOST_METRICS_DIR;
  const [opRows, backupRows, certRows, heartbeatRows, openAlerts, rebootMarker] = await Promise.all([
    db.select().from(operations),
    db.select().from(backups),
    db.select().from(certificates),
    db.select().from(workerHeartbeats),
    db
      .select({ dedupKey: alerts.dedupKey, severity: alerts.severity })
      .from(alerts)
      .where(isNull(alerts.resolvedAt)),
    hostMetricsDir ? readFile(join(hostMetricsDir, "reboot-required"), "utf8").catch(() => null) : null,
  ]);
  const rolloverAlerts = openAlerts.filter((item) => item.dedupKey.startsWith(ROLLOVER_ALERT_PREFIX));
  const lines = [
    "# TYPE ark_operations gauge",
    `ark_operations{status="failed"} ${opRows.filter((item) => item.status === "failed").length}`,
    `ark_operations{status="running"} ${opRows.filter((item) => item.status === "running").length}`,
    `ark_operations{status="waiting_external"} ${opRows.filter((item) => item.status === "waiting_external").length}`,
    `ark_operations{status="needs_recovery"} ${opRows.filter((item) => item.status === "needs_recovery").length}`,
    "# TYPE ark_backups_unverified gauge",
    `ark_backups_unverified ${backupRows.filter((item) => !item.restoreVerified).length}`,
    "# TYPE ark_certificates_expiring gauge",
    `ark_certificates_expiring ${certRows.filter((item) => item.expiresAt && item.expiresAt.getTime() < Date.now() + 14 * 86_400_000).length}`,
    "# TYPE ark_worker_heartbeat_stale gauge",
    ...[
      "agent",
      "database",
      "domains",
      ...(mailEnabled(process.env.ARK_MAIL_ENABLED) ? ["mail"] : []),
      "backup",
    ].map((identity) => {
      const item = heartbeatRows.find((row) => row.identity === identity);
      return `ark_worker_heartbeat_stale{identity="${identity}"} ${!item || Date.now() - item.lastSeenAt.getTime() > 90_000 ? 1 : 0}`;
    }),
    // Database client certificate rollover (front door §3.10.4, FD-28): open rollover-pending
    // alerts by severity (info at T−30, warning at T−14, critical at T−7) and open retirement
    // (drain) failures, which are always critical.
    "# TYPE ark_db_client_rollover_pending gauge",
    ...(["info", "warning", "critical"] as const).map(
      (severity) =>
        `ark_db_client_rollover_pending{severity="${severity}"} ${rolloverAlerts.filter((item) => item.severity === severity).length}`,
    ),
    "# TYPE ark_db_client_retirement_failures gauge",
    `ark_db_client_retirement_failures ${openAlerts.filter((item) => item.dedupKey.startsWith(RETIREMENT_ALERT_PREFIX)).length}`,
    // nft drop counters for the public edge ports (§3.11), written by the
    // host-namespace database-ingress reconciler. A missing or unreadable snapshot reports 0.
    ...ingressCounterMetrics(await readDbIngressCounters()),
    ...rebootRequiredMetrics(rebootMarker),
    // Off-VPS backup targets (front door §3.19, FD-21): last success age, append-only verdict and the
    // age of the newest off-VPS recovery point per source.
    ...(await backupTargetMetrics()),
  ];
  return c.text(`${lines.join("\n")}\n`, 200, { "content-type": "text/plain; version=0.0.4" });
});

// The one-time signed request authorizes this off-host callback without an admin cookie.
app.post(ipv6PreflightResultPath, async (c) => {
  const type = c.req.header("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (type !== "application/json")
    throw new HTTPException(415, { message: "An IPv6 report requires application/json." });
  const { signature, report } = z
    .object({
      signature: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
      report: ipv6ProbeReport,
    })
    .parse(await c.req.json().catch(() => null));
  if (!(await verifyIpv6Submission(report, signature, env.authSecret))) {
    throw new HTTPException(403, { message: "The signed IPv6 request is invalid, expired or already used." });
  }
  const operation = await enqueue({
    kind: ipv6PreflightKind,
    targetIds: [ipv6PreflightTarget],
    payload: { report },
    idempotencyKey: `ipv6.preflight.result:${report.id}`,
  });
  return c.json({ operationId: operation.id }, 202);
});

app.use("/api/*", async (c, next) => {
  if (
    c.req.path.startsWith("/api/internal/") ||
    c.req.path.startsWith("/api/auth/") ||
    c.req.path === "/api/setup/status" ||
    c.req.path === "/api/health"
  ) {
    return next();
  }
  const sessionValue = await auth.api.getSession({ headers: authHeaders(c) });
  if (!sessionValue) throw new HTTPException(401, { message: "Sign in to continue." });
  // Session separation (front door §3.9.1): the admin API accepts only sessions minted on an admin
  // origin, presented on an admin origin. A gate session (login origin) gets 403 on every route.
  const sessionOrigin = (sessionValue.session as { origin?: string }).origin;
  if (sessionOrigin !== "admin" || c.get("requestOrigin").origin !== "admin") {
    throw new HTTPException(403, { message: "This session cannot use the administration API." });
  }
  // Better Auth's two-factor plugin owns `twoFactorEnabled`, while Ark owns the
  // enrollment boundary timestamp. Read both from the authoritative row rather
  // than relying on the plugin's deliberately narrow session serializer.
  const [currentUser] = await db.select().from(user).where(eq(user.id, sessionValue.user.id));
  if (!currentUser) throw new HTTPException(401, { message: "The signed-in account no longer exists." });
  c.set("session", {
    ...sessionValue,
    user: {
      ...sessionValue.user,
      twoFactorEnabled: currentUser.twoFactorEnabled,
      mfaEnrolledAt: currentUser.mfaEnrolledAt,
    },
  } as SessionValue);
  const [access] = await db
    .select()
    .from(platformAccess)
    .where(eq(platformAccess.userId, sessionValue.user.id));
  // No platform_access row (a gate-only user, §3.9.6) means no administration access at all, not viewer.
  if (!access) throw new HTTPException(403, { message: "This account has no administration access." });
  c.set("access", {
    userId: sessionValue.user.id,
    role: access.role as Role,
    projectIds: access?.projectIds ?? [],
    domainIds: access?.domainIds ?? [],
  });
  await next();
});

const browserOrigins = new Set([env.authUrl, ...env.trustedOrigins].map((item) => new URL(item).origin));
app.use("/api/*", async (c, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(c.req.method)) return next();
  const origin = c.req.header("origin");
  if (!origin || !browserOrigins.has(origin)) {
    throw new HTTPException(403, { message: "The request origin is not trusted." });
  }
  const mediaType = (c.req.header("content-type") ?? "").split(";", 1)[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") {
    throw new HTTPException(415, { message: "Custom API mutations require application/json." });
  }
  await next();
});

async function audit(
  actorId: string | undefined,
  action: string,
  resourceType: string,
  resourceId: string | undefined,
  detail: Record<string, unknown> = {},
  operationId?: string,
  role?: string,
) {
  await db.insert(auditEvents).values({
    id: createId("aud"),
    actorId,
    action,
    resourceType,
    resourceId,
    role,
    operationId,
    detail: redactValue(detail) as Record<string, unknown>,
  });
}

async function consumeOneTimeSecret(
  secretId: string,
  input: { actorId: string; role: string; resourceType: string; resourceId: string; kind: string },
) {
  return db.transaction(async (tx) => {
    const [consumed] = await tx
      .update(secrets)
      .set({ revealedAt: new Date() })
      .where(and(eq(secrets.id, secretId), isNull(secrets.revealedAt)))
      .returning();
    if (!consumed) return null;
    await tx.insert(auditEvents).values({
      id: createId("aud"),
      actorId: input.actorId,
      action: "secret.reveal",
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      role: input.role,
      detail: { kind: input.kind },
    });
    return consumed;
  });
}

async function requireTargetScope(access: Access, targetId: string, mode: "view" | "manage" = "manage") {
  const [database] = await db.select().from(managedDatabases).where(eq(managedDatabases.id, targetId));
  if (database) return requireDatabaseAccess(access, targetId, mode);
  const [mailbox] = await db.select().from(mailboxes).where(eq(mailboxes.id, targetId));
  if (mailbox) return requireDomain(access, mailbox.domainId, mode);
  const [domain] = await db.select().from(domainClaims).where(eq(domainClaims.id, targetId));
  if (domain) return requireDomain(access, domain.id, mode);
  const [service] = await db.select().from(services).where(eq(services.id, targetId));
  if (service) return requireProject(access, service.projectId);
  const [project] = await db.select().from(projects).where(eq(projects.id, targetId));
  if (project) return requireProject(access, project.id);
  if (targetId === "platform" && access.role === "owner") return;
  throw new HTTPException(403, { message: "The target is not granted to your account." });
}

async function requireSecretScope(access: Access, secret: typeof secrets.$inferSelect) {
  assertSecretRevealable(secret);
  // Database client keys and passwords are owner-only and leave only through the client's own
  // one-time reveal (FD-17), never through the generic endpoint operators can reach.
  const clientKey =
    secret.kind === CLIENT_KEY_SECRET_KIND
      ? await db
          .select({ id: databaseClients.id })
          .from(clientCertificates)
          .innerJoin(databaseClients, eq(databaseClients.caId, clientCertificates.caId))
          .where(eq(clientCertificates.keySecretId, secret.id))
          .limit(1)
      : [];
  if (
    secret.kind === CLIENT_PASSWORD_SECRET_KIND ||
    secret.kind.startsWith(`${CLIENT_PASSWORD_SECRET_KIND}.`) ||
    clientKey.length > 0
  ) {
    throw new HTTPException(403, {
      message: "Database client credentials are revealed only through the client's one-time reveal.",
    });
  }
  // A gate user's temporary password leaves only through `/api/gate/users/:id/temporary-password`.
  if (secret.kind === GATE_USER_PASSWORD_SECRET_KIND) {
    throw new HTTPException(403, {
      message: "A gate user's temporary password is revealed only through its own one-time reveal.",
    });
  }
  if (!secret.resourceId || !secret.resourceType) {
    throw new HTTPException(403, { message: "This legacy secret has no verified resource owner." });
  }
  await requireTargetScope(access, secret.resourceId, "manage");
}

app.get("/api/state", async (c) => {
  const access = c.get("access");
  const session = c.get("session");
  const [setup] = await db.select().from(platformSetup).where(eq(platformSetup.id, "default"));
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  const [
    domains,
    records,
    ends,
    certs,
    clusterRows,
    dbs,
    roles,
    mailboxRows,
    aliasRows,
    projectRows,
    serviceRows,
    opRows,
    stepRows,
    backupRows,
    alertRows,
    auditRows,
    candidateRows,
  ] = await Promise.all([
    db.select().from(domainClaims),
    db.select().from(dnsRecords),
    db.select().from(endpoints),
    db.select().from(certificates),
    db.select().from(databaseClusters),
    db.select().from(managedDatabases),
    db.select().from(databaseRoles),
    db.select().from(mailboxes),
    db.select().from(aliases),
    db.select().from(projects),
    db.select().from(services),
    db.select().from(operations).orderBy(desc(operations.createdAt)).limit(50),
    db.select().from(operationSteps).orderBy(desc(operationSteps.createdAt)).limit(200),
    db.select().from(backups).orderBy(desc(backups.createdAt)).limit(50),
    db.select().from(alerts).orderBy(desc(alerts.createdAt)).limit(50),
    db.select().from(auditEvents).orderBy(desc(auditEvents.createdAt)).limit(50),
    db.select().from(updateCandidates).orderBy(desc(updateCandidates.detectedAt)).limit(50),
  ]);
  const visibleDomains = domains.filter((item) => canViewDomain(access, item.id));
  const visibleDomainIds = new Set(visibleDomains.map((item) => item.id));
  const visibleProjects = projectRows.filter((item) => canViewProject(access, item.id));
  const visibleProjectIds = new Set(visibleProjects.map((item) => item.id));
  const clusterById = new Map(clusterRows.map((item) => [item.id, item]));
  const endpointById = new Map(ends.map((item) => [item.id, item]));
  const visibleDatabases = dbs.filter((item) => {
    if (item.projectId) return visibleProjectIds.has(item.projectId);
    const cluster = clusterById.get(item.clusterId);
    const endpoint = cluster?.endpointId ? endpointById.get(cluster.endpointId) : undefined;
    if (endpoint?.domainId) return visibleDomainIds.has(endpoint.domainId);
    return access.role === "owner";
  });
  const visibleDatabaseIds = new Set(visibleDatabases.map((item) => item.id));
  const visibleServices = serviceRows.filter((item) => visibleProjectIds.has(item.projectId));
  const visibleServiceIds = new Set(visibleServices.map((item) => item.id));
  const visibleMailboxes = mailboxRows.filter((item) => visibleDomainIds.has(item.domainId));
  const visibleMailboxIds = new Set(visibleMailboxes.map((item) => item.id));
  const visibleIds = new Set<string>([
    ...visibleDomainIds,
    ...visibleProjectIds,
    ...visibleDatabaseIds,
    ...visibleServiceIds,
    ...visibleMailboxIds,
  ]);
  if (access.role === "owner" || access.role === "operator") visibleIds.add("platform");
  const visibleEndpoints = ends.filter((item) => !item.domainId || visibleDomainIds.has(item.domainId));
  const visibleEndpointIds = new Set(visibleEndpoints.map((item) => item.id));
  const visibleMailDomainRows = (await db.select().from(mailDomains)).filter((item) =>
    visibleDomainIds.has(item.domainId),
  );
  const deviceRows = await db.select().from(mailboxDevices);
  return c.json({
    user: { ...session.user, role: access.role },
    setup: {
      completed: Boolean(setup?.completed),
      wizardCompleted: Boolean(setup?.wizardCompleted),
      mfaEnrolled: Boolean(session.user.twoFactorEnabled && session.user.mfaEnrolledAt),
      mfaAssured: Boolean(
        session.user.twoFactorEnabled &&
        session.user.mfaEnrolledAt &&
        new Date(session.session.createdAt).getTime() >= new Date(session.user.mfaEnrolledAt).getTime(),
      ),
    },
    settings,
    region: regionSummary(settings ?? null),
    dbIngress: dbIngressLimitsSummary(settings ?? null),
    // One pooler-wide policy on public 5432 (FD-26, §3.8.3); requests name databases, so only owners
    // and operators see them. Every role sees the boundary and the publication state.
    poolerPolicy: await poolerPolicyView(access),
    domains: visibleDomains.map((domain) => ({
      ...redactDomain(domain, access),
      records: records.filter(
        (record) => record.domainId === domain.id && (desiredDns(record) || pendingWithdrawal(record)),
      ),
    })),
    endpoints: visibleEndpoints,
    certificates: certs
      .filter((item) => visibleEndpointIds.has(item.endpointId))
      .map((item) => ({ ...item, fingerprint: item.fingerprint })),
    clusters: clusterRows.filter((item) => {
      const endpoint = item.endpointId ? endpointById.get(item.endpointId) : undefined;
      return !endpoint?.domainId || visibleDomainIds.has(endpoint.domainId);
    }),
    databases: visibleDatabases.map((item) => ({
      ...item,
      roles: roles
        .filter((role) => role.databaseId === item.id)
        .map((role) => ({ ...role, secretId: role.secretId ? "stored" : null })),
    })),
    mailboxes: visibleMailboxes.map((item) => {
      const domain = domains.find((row) => row.id === item.domainId);
      return { ...item, address: domain ? `${item.localPart}@${domain.name}` : item.localPart };
    }),
    aliases: aliasRows
      .filter((item) => visibleDomainIds.has(item.domainId))
      .map((item) => {
        const domain = domains.find((row) => row.id === item.domainId);
        return { ...item, address: domain ? `${item.localPart}@${domain.name}` : item.localPart };
      }),
    mailDomains: visibleMailDomainRows,
    devices: deviceRows
      .filter((item) => visibleMailboxIds.has(item.mailboxId))
      .map((item) => ({
        ...item,
        secretId: item.secretId ? "stored" : null,
      })),
    projects: visibleProjects,
    services: visibleServices.map((item) => ({
      id: item.id,
      projectId: item.projectId,
      name: item.name,
      imageDigest: item.imageDigest,
      desiredRevision: item.desiredRevision,
      observedRevision: item.observedRevision,
      status: item.status,
      updatePolicy: item.updatePolicy,
      stateful: item.stateful,
      observedAt: item.observedAt,
      createdAt: item.createdAt,
    })),
    operations: opRows
      .filter((item) => access.role === "owner" || item.targetIds.some((id) => visibleIds.has(id)))
      .map((item) => ({
        id: item.id,
        kind: item.kind,
        status: item.status,
        targetIds: item.targetIds,
        error: item.error ? String(redactValue(item.error)).slice(0, 500) : null,
        createdAt: item.createdAt,
        updatedAt: item.updatedAt,
      })),
    steps: stepRows
      .filter((item) =>
        opRows.some(
          (op) =>
            op.id === item.operationId &&
            (access.role === "owner" || op.targetIds.some((id) => visibleIds.has(id))),
        ),
      )
      .map((item) => ({
        id: item.id,
        operationId: item.operationId,
        name: item.name,
        status: item.status,
        createdAt: item.createdAt,
      })),
    backups: backupRows.filter((item) => access.role === "owner" || visibleIds.has(item.targetId)),
    alerts: access.role === "owner" || access.role === "operator" ? alertRows : [],
    audit: (access.role === "owner"
      ? auditRows
      : auditRows.filter((item) => item.actorId === access.userId)
    ).map((item) => ({
      id: item.id,
      actorId: item.actorId,
      action: item.action,
      resourceType: item.resourceType,
      resourceId: item.resourceId,
      role: item.role,
      operationId: item.operationId,
      createdAt: item.createdAt,
    })),
    updateCandidates: candidateRows.filter((item) => visibleServiceIds.has(item.serviceId)),
    providers: {
      cloudflare: Boolean(process.env.DNS_API_TOKEN || process.env.CLOUDFLARE_API_TOKEN),
      ses: Boolean(process.env.AWS_ACCESS_KEY_ID || process.env.AWS_BOOTSTRAP_ACCESS_KEY_ID),
      stalwart: Boolean(process.env.STALWART_URL),
      alertWebhook: Boolean(process.env.ARK_ALERT_WEBHOOK),
    },
  });
});

app.post("/api/wizard", async (c) => {
  const access = c.get("access");
  const session = c.get("session");
  // The wizard writes the same admin exposure settings that `/api/settings` and
  // `/api/settings/mode` guard with owner plus an `exposure.public` step-up. Without these
  // checks an operator could re-run it to reach those settings by the back door.
  if (access.role !== "owner") throw new HTTPException(403, { message: "Owner access is required." });
  requireMfa(session);
  const [wizardSetup] = await db.select().from(platformSetup).where(eq(platformSetup.id, "default"));
  if (wizardSetup?.wizardCompleted) {
    throw new HTTPException(409, {
      message: "First-run setup is already complete. Change these settings from Settings instead.",
    });
  }
  const input = wizardInput.parse(await c.req.json());
  if (input.includeMail) requireMailEnabled();
  const ownershipToken = `ark-own-${createToken(16)}`;
  const plan = buildDomainPlan({
    baseDomain: input.baseDomain,
    publicIpv4: input.publicIpv4,
    adminMode: input.adminMode,
    adminHostname: input.adminHostname,
    databaseHostname: input.databaseHostname,
    mailHostname: input.mailHostname,
    ownershipToken,
    includeDatabase: input.includeDatabase,
    includeMail: input.includeMail,
  });
  const domainId = createId("dom");
  await db.insert(domainClaims).values({
    id: domainId,
    name: plan.zone,
    ownershipToken,
    status: "awaiting_dns",
    dnsProvider: input.dnsProvider,
    mailFrom: `bounce.${plan.zone}`,
  });
  for (const record of plan.records) {
    await db.insert(dnsRecords).values(dnsRecordValues(domainId, record));
  }
  const createdEndpoints: string[] = [];
  const addEndpoint = async (kind: string, hostname: string, exposure: string) => {
    const id = createId("ep");
    await db.insert(endpoints).values({ id, kind, hostname, domainId, exposure, status: "awaiting_dns" });
    createdEndpoints.push(id);
    return id;
  };
  if (input.includeDatabase) {
    const endpointId = await addEndpoint(
      "database",
      normalizeHostname(input.databaseHostname ?? `db.${plan.zone}`),
      "public",
    );
    const clusterId = createId("cl");
    await db
      .insert(databaseClusters)
      .values({ id: clusterId, name: "application", endpointId, status: "provisioning" });
    if (input.firstDatabaseName) {
      const databaseId = createId("db");
      await db.insert(managedDatabases).values({
        id: databaseId,
        clusterId,
        name: input.firstDatabaseName,
        exposure: "public",
        status: "queued",
      });
    }
  }
  if (input.includeMail) {
    await addEndpoint("mail", normalizeHostname(input.mailHostname ?? `mail.${plan.zone}`), "public");
    await db.insert(mailDomains).values({
      id: createId("md"),
      domainId,
      inboundStatus: "pending",
      outboundStatus: "paused",
    });
    if (input.firstMailboxLocalPart) {
      const mailboxId = createId("mbx");
      await db.insert(mailboxes).values({
        id: mailboxId,
        domainId,
        localPart: localPart(input.firstMailboxLocalPart),
        displayName: "First mailbox",
      });
    }
  }
  if (input.adminMode === "public") {
    await addEndpoint("admin", normalizeHostname(input.adminHostname ?? `admin.${plan.zone}`), "public");
  }
  await db
    .update(platformSettings)
    .set({
      adminMode: input.adminMode,
      baseDomain: plan.zone,
      adminHostname:
        input.adminMode === "public" ? normalizeHostname(input.adminHostname ?? `admin.${plan.zone}`) : null,
      publicIpv4: input.publicIpv4,
      publicIpv6: input.publicIpv6 ?? null,
      ipv6Status: "unchecked",
      ipv6CheckedAt: null,
      ipv6Evidence: null,
      dnsProvider: input.dnsProvider,
      authOrigin: env.authUrl,
      updatedAt: new Date(),
    })
    .where(eq(platformSettings.id, "default"));
  await db.update(platformSetup).set({ wizardCompleted: true }).where(eq(platformSetup.id, "default"));
  if (input.publicIpv6) {
    await enqueue({
      kind: ipv6PreflightKind,
      targetIds: [ipv6PreflightTarget],
      idempotencyKey: ipv6PreflightKey,
    });
  }
  await grantAccess(access.userId, { domainId });
  const verify =
    input.dnsProvider === "cloudflare"
      ? null
      : await enqueue({ kind: "domain.verify", actorId: access.userId, targetIds: [domainId] });
  await audit(
    access.userId,
    "wizard.complete",
    "domain",
    domainId,
    { adminMode: input.adminMode },
    verify?.id,
    access.role,
  );
  return c.json({ domainId, records: plan.records, operationId: verify?.id ?? null });
});

app.post("/api/step-up", async (c) => {
  const access = c.get("access");
  const sessionValue = c.get("session");
  requireOperator(access);
  requireMfa(sessionValue);
  const body = z
    .object({
      password: z.string().min(1).max(1024),
      action: z.enum([
        "role.grant",
        "secret.reveal",
        "resource.delete",
        "restore.overwrite",
        "exposure.public",
        "credential.rotate",
        "platform.update",
      ]),
      planHash: z.string().max(200).optional(),
      request: z.record(z.string(), z.unknown()).optional(),
    })
    .parse(await c.req.json());
  const planHash = body.request ? privilegedRequestHash(body.action, body.request) : body.planHash;
  if (!planHash) {
    throw new HTTPException(422, {
      message: "A request binding or plan hash is required for a single-use step-up grant.",
    });
  }
  // `auth.api.verifyPassword` bypasses Better Auth's rate limiter, which only wraps
  // `auth.handler`. Without a throttle here a stolen post-MFA session cookie could brute-force
  // the account password to mint grants for secret reveal and credential rotation.
  assertStepUpAttemptAllowed(access.userId);
  try {
    await auth.api.verifyPassword({ body: { password: body.password }, headers: authHeaders(c) });
  } catch (error) {
    recordStepUpFailure(access.userId);
    await audit(access.userId, "auth.step_up_failed", "session", sessionValue.session.id, {
      action: body.action,
    });
    throw error;
  }
  clearStepUpFailures(access.userId);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
  await db.insert(stepUpGrants).values({
    id: createId("sup"),
    userId: access.userId,
    sessionId: sessionValue.session.id,
    action: body.action,
    planHash,
    expiresAt,
  });
  await audit(access.userId, "auth.step_up", "session", sessionValue.session.id, {
    action: body.action,
    expiresAt: expiresAt.toISOString(),
  });
  c.header("cache-control", "no-store");
  return c.json({ action: body.action, expiresAt });
});

app.post("/api/domains", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = domainInput.parse(await c.req.json());
  if (input.dnsProvider === "cloudflare") requireOwner(access);
  const name = normalizeHostname(input.name);
  const id = createId("dom");
  const ownershipToken = `ark-own-${createToken(16)}`;
  await db.insert(domainClaims).values({
    id,
    name,
    ownershipToken,
    status: "awaiting_dns",
    dnsProvider: input.dnsProvider,
    mailFrom: input.mailFrom ? normalizeHostname(input.mailFrom) : `bounce.${name}`,
    dmarcPolicy: input.dmarcPolicy,
  });
  await db.insert(dnsRecords).values({
    id: createId("dns"),
    domainId: id,
    type: "TXT",
    name: `_ark-stack.${name}`,
    relativeName: "_ark-stack",
    expectedValue: ownershipToken,
    ttl: 60,
    purpose: "Installation-bound domain ownership proof",
    required: true,
  });
  await grantAccess(access.userId, { domainId: id });
  await audit(access.userId, "domain.create", "domain", id, { name }, undefined, access.role);
  return c.json({
    id,
    records: [{ type: "TXT", name: `_ark-stack.${name}`, value: ownershipToken, required: true }],
  });
});

app.post("/api/domains/:id/verify", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  requireDomain(access, c.req.param("id"), "manage");
  await watchManualDns(c.req.param("id"));
  const operation = await enqueue({
    kind: "domain.verify",
    actorId: access.userId,
    targetIds: [c.req.param("id")],
  });
  return c.json({ operationId: operation.id });
});

app.post("/api/domains/:id/dns/watch", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const domainId = c.req.param("id");
  requireDomain(access, domainId, "manage");
  await watchManualDns(domainId);
  return c.body(null, 204);
});

async function dnsWorkerReview<T>(domainId: string, local: () => Promise<T>) {
  const url = process.env.ARK_DOMAIN_WORKER_URL;
  if (!url) {
    if (process.env.NODE_ENV === "production")
      throw new DnsReviewError(503, "The domain worker is unavailable.");
    return local();
  }
  let response: Response;
  try {
    response = await fetch(new URL("/dns/review", url), {
      method: "POST",
      headers: { authorization: "Bearer " + env.workerTokens.domains, "content-type": "application/json" },
      body: JSON.stringify({ domainId }),
      signal: AbortSignal.timeout(55_000),
    });
  } catch {
    throw new DnsReviewError(
      503,
      "The domain worker did not respond. Reload the DNS review before retrying.",
    );
  }
  const result = (await response.json().catch(() => null)) as (T & { error?: string }) | null;
  if (!response.ok) {
    const status = response.status;
    throw new DnsReviewError(
      status === 403 || status === 404 || status === 409 || status === 422 || status === 503 ? status : 502,
      result?.error ?? "The domain worker could not complete the DNS request.",
    );
  }
  if (!result) throw new DnsReviewError(502, "The domain worker returned an invalid DNS response.");
  return result;
}

async function getDnsReview(domainId: string, localOnly: boolean) {
  if (localOnly) return domainDnsReview(domainId, false);
  const [domain] = await db
    .select({ provider: domainClaims.dnsProvider })
    .from(domainClaims)
    .where(eq(domainClaims.id, domainId));
  if (!domain) throw new DnsReviewError(404, "Domain not found.");
  if (domain.provider !== "cloudflare") return domainDnsReview(domainId);
  return dnsWorkerReview(domainId, () => domainDnsReview(domainId));
}

app.get("/api/domains/:id/dns", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireDomain(access, c.req.param("id"));
  c.header("cache-control", "no-store");
  return c.json(await getDnsReview(c.req.param("id"), c.req.query("local") === "1"));
});

app.post("/api/domains/:id/publish", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const domainId = c.req.param("id");
  requireDomain(access, domainId, "manage");
  const input = dnsPublishInput.parse(await c.req.json());
  if (input.authorizeAAAAWithdrawal !== undefined) requireOwner(access);
  const actor = {
    userId: access.userId,
    role: access.role === "owner" ? ("owner" as const) : ("operator" as const),
  };
  const accepted = await queueDnsPublish(domainId, input, actor);
  c.header("location", `/api/domains/${domainId}/publish/${accepted.operationId}`);
  c.header("cache-control", "no-store");
  return c.json(accepted, 202);
});

app.get("/api/domains/:id/publish/:operationId", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  const domainId = c.req.param("id");
  requireDomain(access, domainId, "manage");
  c.header("cache-control", "no-store");
  const result = await dnsPublishStatus(domainId, c.req.param("operationId"));
  return c.json(result, result.status === "failed" && result.errorStatus === 409 ? 409 : 200);
});

app.put("/api/domains/:id/aaaa", async (c) => {
  const access = c.get("access");
  const session = c.get("session");
  requireOwner(access);
  requireMfa(session);
  const domainId = c.req.param("id");
  const input = z
    .object({ enabled: z.boolean() })
    .strict()
    .parse(await c.req.json());
  const ipv6 = await changeAaaaSetting(domainId, input.enabled, (tx) =>
    requirePrivileged(
      access,
      session,
      "exposure.public",
      privilegedRequestHash("exposure.public", { domainId, ...input }),
      tx,
    ),
  );
  const operation = await enqueue({
    kind: "domain.verify",
    targetIds: [domainId],
    payload: { routeEndpointsOnly: true },
  });
  await audit(access.userId, "dns.aaaa", "domain", domainId, input, operation.id, access.role);
  return c.json({ operationId: operation.id, ...ipv6 });
});

app.delete("/api/domains/:id/aaaa/authorization", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  await revokeAaaaWithdrawal(c.req.param("id"), access.userId);
  return c.json({ revoked: true });
});

app.post("/api/projects", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = projectInput.parse(await c.req.json());
  const id = createId("prj");
  await db.insert(projects).values({ id, name: input.name, slug: input.slug });
  await grantAccess(access.userId, { projectId: id });
  await audit(access.userId, "project.create", "project", id, input, undefined, access.role);
  return c.json({ id });
});

app.post("/api/databases", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = databaseInput.parse(await c.req.json());
  let clusterId = input.clusterId;
  if (!clusterId) {
    const [cluster] = await db.select().from(databaseClusters);
    clusterId = cluster?.id;
  }
  if (!clusterId)
    throw new HTTPException(400, { message: "Complete the domain wizard so an application cluster exists." });
  const [cluster] = await db.select().from(databaseClusters).where(eq(databaseClusters.id, clusterId));
  if (cluster?.endpointId) {
    const [endpoint] = await db.select().from(endpoints).where(eq(endpoints.id, cluster.endpointId));
    if (endpoint?.domainId) requireDomain(access, endpoint.domainId, "manage");
  } else if (access.role !== "owner") {
    throw new HTTPException(403, { message: "You do not have access to this database cluster." });
  }
  const id = createId("db");
  await db.insert(managedDatabases).values({
    id,
    clusterId,
    name: input.name,
    exposure: input.exposure,
    withPgvector: input.withPgvector,
    withTestDatabase: input.withTestDatabase,
    sourceCidrs: input.sourceCidrs ?? [],
  });
  const operation = await enqueue({ kind: "database.provision", actorId: access.userId, targetIds: [id] });
  await audit(access.userId, "database.create", "database", id, input, operation.id, access.role);
  return c.json({ id, operationId: operation.id });
});

function requireMailEnabled() {
  if (!mailEnabled(process.env.ARK_MAIL_ENABLED)) {
    throw new HTTPException(503, { message: "Mail is disabled on this installation." });
  }
}

app.post("/api/mailboxes", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  requireMailEnabled();
  const input = mailboxInput.parse(await c.req.json());
  requireDomain(access, input.domainId, "manage");
  const id = createId("mbx");
  await db.insert(mailboxes).values({
    id,
    domainId: input.domainId,
    localPart: localPart(input.localPart),
    displayName: input.displayName,
    quotaGb: input.quotaGb,
  });
  const operation = await enqueue({ kind: "mail.provision", actorId: access.userId, targetIds: [id] });
  await audit(access.userId, "mail.mailbox.create", "mailbox", id, input, operation.id, access.role);
  return c.json({ id, operationId: operation.id });
});

app.post("/api/aliases", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  requireMailEnabled();
  const input = aliasInput.parse(await c.req.json());
  requireDomain(access, input.domainId, "manage");
  const existing = await db.select().from(aliases);
  const domains = await db.select().from(domainClaims);
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  assertExternalForwarding({
    targets: input.targets,
    localDomains: domains.map((item) => item.name),
    allowExternalForwarding: Boolean(settings?.allowExternalForwarding),
    allowExternal: input.allowExternal,
  });
  const graph = existing
    .filter((item) => item.status === "active")
    .map((item) => {
      const domain = domains.find((row) => row.id === item.domainId);
      return { address: `${item.localPart}@${domain?.name}`, targets: item.targets };
    });
  const domain = domains.find((row) => row.id === input.domainId);
  graph.push({ address: `${localPart(input.localPart)}@${domain?.name}`, targets: input.targets });
  assertAliasGraph(graph);
  const mailbox = await requireDomainMailbox(input.domainId);
  const id = createId("als");
  await db.insert(aliases).values({
    id,
    domainId: input.domainId,
    localPart: localPart(input.localPart),
    description: input.description,
    targets: input.targets,
  });
  const operation = await enqueue({
    kind: "mail.reconcile",
    actorId: access.userId,
    targetIds: [mailbox.id],
  });
  await audit(access.userId, "mail.alias.create", "alias", id, input, operation.id, access.role);
  return c.json({ id, operationId: operation.id });
});

app.patch("/api/aliases/:id", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  requireMailEnabled();
  const body = z
    .object({
      description: z.string().max(200).optional(),
      targets: z.array(z.string().email()).min(1).max(20),
      allowExternal: z.boolean().optional(),
    })
    .parse(await c.req.json());
  const [alias] = await db
    .select()
    .from(aliases)
    .where(eq(aliases.id, c.req.param("id")));
  if (!alias || alias.status !== "active") throw new HTTPException(404, { message: "Alias not found." });
  requireDomain(access, alias.domainId, "manage");
  const domains = await db.select().from(domainClaims);
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  assertExternalForwarding({
    targets: body.targets,
    localDomains: domains.map((item) => item.name),
    allowExternalForwarding: Boolean(settings?.allowExternalForwarding),
    allowExternal: body.allowExternal,
  });
  const graph = (await db.select().from(aliases))
    .filter((item) => item.id !== alias.id && item.status === "active")
    .map((item) => ({
      address: `${item.localPart}@${domains.find((domain) => domain.id === item.domainId)?.name}`,
      targets: item.targets,
    }));
  const domain = domains.find((item) => item.id === alias.domainId);
  graph.push({ address: `${alias.localPart}@${domain?.name}`, targets: body.targets });
  assertAliasGraph(graph);
  const mailbox = await requireDomainMailbox(alias.domainId);
  await db
    .update(aliases)
    .set({ targets: body.targets, description: body.description })
    .where(eq(aliases.id, alias.id));
  const operation = await enqueue({
    kind: "mail.reconcile",
    actorId: access.userId,
    targetIds: [mailbox.id],
  });
  await audit(access.userId, "mail.alias.update", "alias", alias.id, {}, operation.id, access.role);
  return c.json({ operationId: operation.id });
});

app.delete("/api/aliases/:id", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMailEnabled();
  const [alias] = await db
    .select()
    .from(aliases)
    .where(eq(aliases.id, c.req.param("id")));
  if (!alias || alias.status !== "active") throw new HTTPException(404, { message: "Alias not found." });
  requireDomain(access, alias.domainId, "manage");
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "resource.delete",
    privilegedRequestHash("resource.delete", { aliasId: c.req.param("id") }),
  );
  if (!alias.nativeId) {
    await db.delete(aliases).where(eq(aliases.id, alias.id));
    await audit(
      access.userId,
      "mail.alias.delete",
      "alias",
      alias.id,
      { native: false },
      undefined,
      access.role,
    );
    return c.json({ operationId: null });
  }
  const [domain] = await db.select().from(domainClaims).where(eq(domainClaims.id, alias.domainId));
  const mailbox = await requireDomainMailbox(alias.domainId);
  if (!domain) throw new HTTPException(409, { message: "The alias domain is no longer available." });
  await db.update(aliases).set({ status: "pending_delete" }).where(eq(aliases.id, alias.id));
  const operation = await enqueue({
    kind: "mail.reconcile",
    actorId: access.userId,
    targetIds: [mailbox.id],
    payload: {
      removedAliasId: alias.id,
      removedAlias: { address: `${alias.localPart}@${domain.name}`, nativeId: alias.nativeId },
    },
  });
  await audit(access.userId, "mail.alias.delete", "alias", alias.id, {}, operation.id, access.role);
  return c.json({ operationId: operation.id });
});

app.post("/api/services", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = serviceInput.parse(await c.req.json());
  requireProject(access, input.projectId);
  const policy = validateComposeSource(input.compose);
  if (!policy.ok)
    throw new HTTPException(422, { message: policy.violations.map((item) => item.message).join(" ") });
  const id = createId("svc");
  // Write the approved compose artefact first: if the filesystem write fails the request must
  // not leave behind a registered service row with no deploy operation behind it.
  const written = await writeApprovedCompose(id, input.compose);
  await db.insert(services).values({
    id,
    projectId: input.projectId,
    name: input.name,
    compose: canonicalizeComposeSource(input.compose),
    desiredRevision: createId("rev"),
    imageDigest: policy.images[0] ?? null,
    status: "registered",
    updatePolicy: input.updatePolicy,
    stateful: input.stateful,
  });
  const [project] = await db.select().from(projects).where(eq(projects.id, input.projectId));
  const operation = await enqueue({
    kind: "service.deploy",
    actorId: access.userId,
    targetIds: [id],
    payload: {
      images: policy.images,
      compose: written.canonical,
      composeHash: written.hash,
      name: input.name,
      project: `ark-${project?.slug ?? "workload"}`,
    },
  });
  await audit(
    access.userId,
    "service.create",
    "service",
    id,
    { name: input.name, projectId: input.projectId },
    operation.id,
    access.role,
  );
  return c.json({ id, operationId: operation.id, preview: policy });
});

app.post("/api/services/discover", async (c) => {
  const access = c.get("access");
  if (access.role !== "owner")
    throw new HTTPException(403, { message: "Only owners can discover host resources." });
  requireMfa(c.get("session"));
  await c.req.json();
  const operation = await enqueue({
    kind: "service.discover",
    actorId: access.userId,
    targetIds: ["platform"],
    payload: { request: "redacted-inventory-v1" },
  });
  await audit(access.userId, "service.discover", "platform", "platform", {}, operation.id, access.role);
  return c.json({ operationId: operation.id, status: operation.status });
});

app.get("/api/services/discovery/:operationId", async (c) => {
  const access = c.get("access");
  if (access.role !== "owner")
    throw new HTTPException(403, { message: "Only owners can view host discovery." });
  const [operation] = await db
    .select()
    .from(operations)
    .where(eq(operations.id, c.req.param("operationId")));
  if (!operation || operation.kind !== "service.discover" || !operation.targetIds.includes("platform")) {
    throw new HTTPException(404, { message: "Discovery result was not found." });
  }
  if (operation.status !== "succeeded") {
    return c.json({ status: operation.status, available: false, error: operation.error });
  }
  const [step] = await db
    .select()
    .from(operationSteps)
    .where(eq(operationSteps.operationId, operation.id))
    .orderBy(desc(operationSteps.createdAt))
    .limit(1);
  const evidence = (step?.evidence ?? {}) as Record<string, unknown>;
  const inventory = Array.isArray(evidence.inventory)
    ? evidence.inventory.slice(0, 100).flatMap((raw) => {
        if (!raw || typeof raw !== "object" || Array.isArray(raw)) return [];
        const item = raw as Record<string, unknown>;
        const names = Array.isArray(item.Names) ? item.Names : [];
        const labels = item.Labels && typeof item.Labels === "object" ? item.Labels : {};
        return [
          {
            id: String(item.Id ?? "").slice(0, 64),
            name: String(names[0] ?? "")
              .replace(/^\//, "")
              .slice(0, 128),
            image: String(item.Image ?? "").slice(0, 512),
            state: String(item.State ?? "unknown").slice(0, 32),
            labels: labels as Record<string, string>,
          },
        ];
      })
    : [];
  const registered = (await db.select().from(services)).map((item) => item.name);
  return c.json({ status: operation.status, available: true, ...classifyDiscovery(inventory, registered) });
});

app.post("/api/services/adopt", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = adoptInput.parse(await c.req.json());
  requireProject(access, input.projectId);
  const preview = adoptionPreview(input.compose);
  if (!preview.ok) throw new HTTPException(422, { message: "Unsupported compose cannot be adopted." });
  const id = createId("svc");
  // Same ordering as registration: a failed artefact write must not leave an orphan row.
  const written = await writeApprovedCompose(id, input.compose);
  await db.insert(services).values({
    id,
    projectId: input.projectId,
    name: input.name,
    compose: input.compose,
    desiredRevision: createId("rev"),
    containerId: input.containerId,
    adoptedFrom: input.containerId,
    status: "adoption_pending",
    updatePolicy: "notify",
  });
  const operation = await enqueue({
    kind: "service.adopt",
    actorId: access.userId,
    targetIds: [id],
    payload: { ...input, compose: written.canonical, composeHash: written.hash },
  });
  await audit(
    access.userId,
    "service.adopt",
    "service",
    id,
    { name: input.name, projectId: input.projectId },
    operation.id,
    access.role,
  );
  return c.json({ id, operationId: operation.id, preview });
});

app.post("/api/services/:id/observe", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = z.object({ kind: z.enum(["logs", "stats"]) }).parse(await c.req.json());
  const [service] = await db
    .select()
    .from(services)
    .where(eq(services.id, c.req.param("id")));
  if (!service) throw new HTTPException(404, { message: "Service not found." });
  requireProject(access, service.projectId);
  const operation = await enqueue({
    kind: input.kind === "logs" ? "service.logs" : "service.stats",
    actorId: access.userId,
    targetIds: [service.id],
    payload: { name: service.name },
  });
  await audit(access.userId, `service.${input.kind}`, "service", service.id, {}, operation.id, access.role);
  return c.json({ operationId: operation.id, status: operation.status });
});

app.get("/api/services/:id/observations/:operationId", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  const [service] = await db
    .select()
    .from(services)
    .where(eq(services.id, c.req.param("id")));
  if (!service) throw new HTTPException(404, { message: "Service not found." });
  requireProject(access, service.projectId);
  const [operation] = await db
    .select()
    .from(operations)
    .where(eq(operations.id, c.req.param("operationId")));
  if (
    !operation ||
    !operation.targetIds.includes(service.id) ||
    (operation.kind !== "service.logs" && operation.kind !== "service.stats")
  ) {
    throw new HTTPException(404, { message: "Service observation was not found." });
  }
  if (operation.status !== "succeeded") {
    return c.json({ status: operation.status, available: false, error: operation.error });
  }
  const [step] = await db
    .select()
    .from(operationSteps)
    .where(eq(operationSteps.operationId, operation.id))
    .orderBy(desc(operationSteps.createdAt))
    .limit(1);
  const evidence = (step?.evidence ?? {}) as Record<string, unknown>;
  if (operation.kind === "service.logs") {
    const lines = Array.isArray(evidence.lines)
      ? evidence.lines.filter((item): item is string => typeof item === "string").slice(-500)
      : [];
    return c.json({ status: operation.status, available: true, lines });
  }
  const stats =
    evidence.stats && typeof evidence.stats === "object" && !Array.isArray(evidence.stats)
      ? evidence.stats
      : {};
  return c.json({ status: operation.status, available: true, stats });
});

app.post("/api/services/:id/:action", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const action = c.req.param("action");
  const kind =
    action === "restart"
      ? "service.restart"
      : action === "start"
        ? "service.start"
        : action === "stop"
          ? "service.stop"
          : null;
  if (!kind) throw new HTTPException(404, { message: "Unknown service action." });
  const [service] = await db
    .select()
    .from(services)
    .where(eq(services.id, c.req.param("id")));
  if (!service) throw new HTTPException(404, { message: "Service not found." });
  requireProject(access, service.projectId);
  const [project] = await db.select().from(projects).where(eq(projects.id, service.projectId));
  const operation = await enqueue({
    kind,
    actorId: access.userId,
    targetIds: [c.req.param("id")],
    payload: { name: service.name, project: `ark-${project?.slug ?? "workload"}` },
  });
  await audit(access.userId, kind, "service", c.req.param("id"), {}, operation.id, access.role);
  return c.json({ operationId: operation.id });
});

app.post("/api/sql/query", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  const input = sqlInput.parse(await c.req.json());
  const classified = classifySql(input.sql, input.readOnly);
  await requireDatabaseAccess(access, input.databaseId, "manage");
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "secret.reveal",
    privilegedRequestHash("secret.reveal", { databaseId: input.databaseId, kind: "sql.query" }),
  );
  const [database] = await db
    .select()
    .from(managedDatabases)
    .where(eq(managedDatabases.id, input.databaseId));
  if (!database) throw new HTTPException(404, { message: "Database not found." });
  const [role] = await db
    .select()
    .from(databaseRoles)
    .where(and(eq(databaseRoles.databaseId, database.id), eq(databaseRoles.kind, input.role)));
  if (!role?.secretId)
    throw new HTTPException(404, { message: "That role is not available for this database." });
  const operation = await enqueue({
    kind: "database.query",
    actorId: access.userId,
    targetIds: [database.id],
    payload: {
      executionId: input.executionId,
      workspaceId: input.workspaceId,
      role: input.role,
      sql: input.sql,
      readOnly: input.readOnly,
      fingerprint: classified.fingerprint,
    },
  });
  await audit(
    access.userId,
    "sql.execute",
    "database",
    input.databaseId,
    { fingerprint: classified.fingerprint, role: input.role, workspaceId: input.workspaceId },
    operation.id,
    access.role,
  );
  return c.json({
    operationId: operation.id,
    status: operation.status,
    databaseId: input.databaseId,
    workspaceId: input.workspaceId,
    role: input.role,
    fingerprint: classified.fingerprint,
  });
});

app.get("/api/sql/results/:operationId", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  const [operation] = await db
    .select()
    .from(operations)
    .where(eq(operations.id, c.req.param("operationId")));
  if (
    !operation ||
    !["database.query", "database.schema"].includes(operation.kind) ||
    operation.targetIds.length !== 1
  ) {
    throw new HTTPException(404, { message: "Database result was not found." });
  }
  await requireDatabaseAccess(access, operation.targetIds[0]!, "manage");
  if (operation.status !== "succeeded") {
    return c.json({ status: operation.status, available: false, error: operation.error });
  }
  const [step] = await db
    .select()
    .from(operationSteps)
    .where(eq(operationSteps.operationId, operation.id))
    .orderBy(desc(operationSteps.createdAt))
    .limit(1);
  const evidence = (step?.evidence ?? {}) as Record<string, unknown>;
  const key = operation.kind === "database.query" ? "query" : "schema";
  const result = evidence[key];
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new HTTPException(409, { message: "Database worker completed without a bounded result." });
  }
  return c.json({ status: operation.status, available: true, [key]: result });
});

app.post("/api/sql/cancel", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = sqlCancelInput.parse(await c.req.json());
  const scope = await requireDatabaseAccess(access, input.databaseId, "manage");
  let cancelled = false;
  if (env.embeddedWorkers) {
    cancelled = await cancelWorkspaceQuery({
      executionId: input.executionId,
      actorId: access.userId,
      database: scope.database.name,
    });
  } else {
    const workerUrl = process.env.ARK_DATABASE_WORKER_URL;
    if (!workerUrl) throw new HTTPException(503, { message: "Database cancellation worker is unavailable." });
    const response = await fetch(`${workerUrl.replace(/\/$/, "")}/cancel`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${env.workerTokens.database}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        executionId: input.executionId,
        actorId: access.userId,
        database: scope.database.name,
      }),
      signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok)
      throw new HTTPException(503, { message: "Database cancellation worker rejected the request." });
    const result = (await response.json()) as { cancelled?: boolean };
    cancelled = result.cancelled === true;
  }
  return c.json({ executionId: input.executionId, cancelled });
});

app.post("/api/databases/:id/schema", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  await requireDatabaseAccess(access, c.req.param("id"));
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "secret.reveal",
    privilegedRequestHash("secret.reveal", { databaseId: c.req.param("id"), kind: "schema" }),
  );
  const [database] = await db
    .select()
    .from(managedDatabases)
    .where(eq(managedDatabases.id, c.req.param("id")));
  if (!database) throw new HTTPException(404, { message: "Database not found." });
  const [role] = await db
    .select()
    .from(databaseRoles)
    .where(and(eq(databaseRoles.databaseId, database.id), eq(databaseRoles.kind, "readonly")));
  if (!role?.secretId) throw new HTTPException(404, { message: "Readonly role is not available." });
  const operation = await enqueue({
    kind: "database.schema",
    actorId: access.userId,
    targetIds: [database.id],
    payload: {},
  });
  await audit(access.userId, "database.schema", "database", database.id, {}, operation.id, access.role);
  return c.json({ operationId: operation.id, status: operation.status });
});

app.post("/api/databases/:id/rotate", async (c) => {
  const access = c.get("access");
  const body = z.object({ kind: z.enum(["runtime", "readonly", "migration"]) }).parse(await c.req.json());
  await requireDatabaseAccess(access, c.req.param("id"), "manage");
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "credential.rotate",
    privilegedRequestHash("credential.rotate", { databaseId: c.req.param("id"), kind: body.kind }),
  );
  const operation = await enqueue({
    kind: "database.rotate",
    actorId: access.userId,
    targetIds: [c.req.param("id")],
    payload: body,
  });
  await audit(
    access.userId,
    "credential.rotate",
    "database",
    c.req.param("id"),
    body,
    operation.id,
    access.role,
  );
  return c.json({ operationId: operation.id });
});

app.put("/api/databases/:id/cidrs", async (c) => {
  const access = c.get("access");
  const input = cidrInput.parse(await c.req.json());
  await requireDatabaseAccess(access, c.req.param("id"), "manage");
  const cidrs = assertCidrs(input.sourceCidrs);
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "exposure.public",
    privilegedRequestHash("exposure.public", { databaseId: c.req.param("id"), cidrs: input.sourceCidrs }),
  );
  await db
    .update(managedDatabases)
    .set({ sourceCidrs: cidrs })
    .where(eq(managedDatabases.id, c.req.param("id")));
  const operation = await enqueue({
    kind: "pgbouncer.reload",
    actorId: access.userId,
    targetIds: [c.req.param("id")],
    payload: { cidrs },
  });
  await audit(
    access.userId,
    "database.cidrs",
    "database",
    c.req.param("id"),
    { cidrs },
    operation.id,
    access.role,
  );
  return c.json({ operationId: operation.id, cidrs });
});

/** The pooler policy for the inventory: full detail for owners and operators, the boundary for all. */
async function poolerPolicyView(access: { role: string }) {
  const evaluation = await loadPoolerPolicy();
  if (access.role === "owner" || access.role === "operator") return evaluation;
  return {
    scope: evaluation.scope,
    status: evaluation.status,
    publishable: evaluation.publishable,
    message: evaluation.message,
    boundary: evaluation.boundary,
    conflict: evaluation.conflict,
  };
}

app.get("/api/databases/:id/admission", async (c) => {
  requireOperator(c.get("access"));
  await requireDatabaseAccess(c.get("access"), c.req.param("id"));
  const [database] = await db
    .select()
    .from(managedDatabases)
    .where(eq(managedDatabases.id, c.req.param("id")));
  if (!database) throw new HTTPException(404, { message: "Database not found." });
  // Classic SSLRequest carries no database name, so admission is the pooler-wide policy for every
  // database. A source admitted for another database is admitted here too: never report this
  // database's own CIDRs as isolating it (§3.8.3).
  const evaluation = await loadPoolerPolicy();
  return c.json({
    databaseId: database.id,
    requestedCidrs: database.sourceCidrs ?? [],
    ...poolerAdmission(evaluation, String(c.req.query("ip") ?? "")),
  });
});

// The pooler-wide source policy for public 5432 (front door §3.8.3, FD-26). Owners and operators read
// the requests, conflicts and publication state. Saving is owner-only with MFA and a single-use
// `exposure.public` grant bound to the body: it is the explicit review that publication needs when
// databases request different sources, so the body echoes the requests fingerprint it reviewed.
app.get("/api/databases/pooler-policy", async (c) => {
  requireOperator(c.get("access"));
  return c.json(await loadPoolerPolicy());
});

app.put("/api/databases/pooler-policy", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const request = await c.req.json();
  const input = poolerPolicyInput.parse(request);
  let checked: ReturnType<typeof checkPoolerPolicy>;
  try {
    checked = checkPoolerPolicy(input);
  } catch (error) {
    throw new HTTPException(422, { message: (error as Error).message });
  }
  const current = await loadPoolerPolicy();
  if (input.reviewedRequests !== current.requestsFingerprint) {
    throw new HTTPException(409, {
      message:
        "The databases' requests changed since they were reviewed. Reload, review them again and save.",
    });
  }
  // Validate before consuming the single-use grant, so a stale review does not burn a step-up.
  await requirePrivileged(
    access,
    c.get("session"),
    "exposure.public",
    privilegedRequestHash("exposure.public", request),
  );
  const previous = await db.transaction(async (tx) => {
    const [saved] = await tx
      .select()
      .from(platformSettings)
      .where(eq(platformSettings.id, "default"))
      .for("update");
    if (input.reviewedRequests !== (await loadPoolerPolicy(tx)).requestsFingerprint) {
      throw new HTTPException(409, {
        message: "The databases' requests changed. Reload and review them again.",
      });
    }
    const now = new Date();
    const keepConfirmation =
      checked.allowInternet && saved?.poolerAllowInternet && saved.poolerInternetConfirmedAt;
    const values = {
      poolerSourceCidrs: checked.allowInternet ? [] : checked.sourceCidrs,
      poolerAllowInternet: checked.allowInternet,
      poolerInternetConfirmedBy: checked.allowInternet
        ? keepConfirmation
          ? saved!.poolerInternetConfirmedBy
          : access.userId
        : null,
      poolerInternetConfirmedAt: checked.allowInternet
        ? keepConfirmation
          ? saved!.poolerInternetConfirmedAt
          : now
        : null,
      poolerPolicyReviewedBy: access.userId,
      poolerPolicyReviewedAt: now,
      poolerPolicyReviewedRequests: current.requestsFingerprint,
      updatedAt: now,
    };
    await tx
      .insert(platformSettings)
      .values({ id: "default", ...values })
      .onConflictDoUpdate({ target: platformSettings.id, set: values });
    return saved;
  });
  const loosened = poolerPolicyLoosens(
    {
      sourceCidrs: Array.isArray(previous?.poolerSourceCidrs) ? previous.poolerSourceCidrs : [],
      allowInternet: Boolean(previous?.poolerAllowInternet),
    },
    checked,
  );
  // The edge re-renders be_pgbouncer at once (tightening must not wait for PgBouncer); the reload
  // then updates each public database's status against the new policy.
  await queuePoolerEdgeApply();
  const operation = await enqueue({
    kind: "pgbouncer.reload",
    actorId: access.userId,
    targetIds: ["platform"],
    payload: { poolerPolicy: { ...checked, reviewedRequests: current.requestsFingerprint } },
  });
  await audit(
    access.userId,
    "pooler_policy.update",
    "platform",
    "platform",
    {
      ...checked,
      loosened,
      reviewedRequests: current.requestsFingerprint,
      distinctRequests: current.distinctRequests,
      conflicts: current.conflicts.map((conflict) => conflict.reason),
      previous: previous
        ? { sourceCidrs: previous.poolerSourceCidrs, allowInternet: previous.poolerAllowInternet }
        : null,
    },
    operation.id,
    access.role,
  );
  return c.json({ ...(await loadPoolerPolicy()), operationId: operation.id });
});

// ---- Database clients (front door §3.10.3, §3.12, FD-17) ----------------------------------------
// Owner-only (R12-style exposure decision). Issue and revoke need MFA plus a single-use
// `credential.rotate` grant bound to the request; the one-time reveal needs `secret.reveal`.

app.get("/api/databases/:id/clients", async (c) => {
  requireOwner(c.get("access"));
  await databaseClientContext(c.req.param("id"));
  return c.json({ clients: await listDatabaseClients(c.req.param("id")) });
});

app.post("/api/databases/:id/clients", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  if (!(await consumeClientIssueAttempt(access.userId)))
    throw new HTTPException(429, {
      message: "Too many database client requests. Wait a few minutes before submitting another.",
    });
  const databaseId = c.req.param("id");
  const request = (await c.req.json()) as Record<string, unknown>;
  const input = databaseClientInput.parse(request);
  // Parse the CSR here as well as in the worker, so a refused request never reaches the queue.
  if (input.csrPem !== undefined) validateCsr(input.csrPem);
  const roleKind = input.roleKind ?? defaultClientRoleKind(input.environment);
  // Validate before consuming the single-use grant; bind it to the database and the exact body.
  await requirePrivileged(
    access,
    c.get("session"),
    "credential.rotate",
    privilegedRequestHash("credential.rotate", { databaseId, ...request }),
  );
  const { clientId, role, operation } = await queueClientIssue({
    databaseId,
    ...input,
    roleKind,
    actorId: access.userId,
  });
  await audit(
    access.userId,
    "database.client_issue",
    "database",
    databaseId,
    {
      clientId,
      name: input.name,
      environment: input.environment,
      roleKind,
      loginRole: role,
      keySource: input.csrPem === undefined ? "generated" : "csr",
    },
    operation.id,
    access.role,
  );
  return c.json(
    { clientId, operationId: operation.id, role, roleKind, readOnly: roleKind === "readonly" },
    202,
  );
});

app.post("/api/databases/:id/clients/:clientId/reveal", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const databaseId = c.req.param("id");
  const clientId = c.req.param("clientId");
  const client = await getDatabaseClient(databaseId, clientId);
  if (!client)
    throw new HTTPException(404, {
      message: "Database client not found. If it was just requested, wait for issuance to finish.",
    });
  if (!client.issuedAt)
    throw new HTTPException(409, { message: "Client issuance has not completed; retry issuance first." });
  if (client.status !== "active" || client.revokedAt)
    throw new HTTPException(409, { message: "This client was revoked; its credentials cannot be revealed." });
  if (client.revealedAt)
    throw new HTTPException(409, {
      message:
        "This client's credentials were already revealed. Revoke it and issue a new client to obtain new ones.",
    });
  await requirePrivileged(
    access,
    c.get("session"),
    "secret.reveal",
    privilegedRequestHash("secret.reveal", { databaseId, clientId }),
  );
  const bundle = await revealDatabaseClient({
    databaseId,
    clientId,
    actorId: access.userId,
    actorRole: access.role,
  });
  c.header("cache-control", "no-store");
  return c.json(bundle);
});

app.post("/api/databases/:id/clients/:clientId/revoke", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const databaseId = c.req.param("id");
  const clientId = c.req.param("clientId");
  const client = await getDatabaseClient(databaseId, clientId);
  if (!client) throw new HTTPException(404, { message: "Database client not found." });
  if (client.revocationCompletedAt)
    throw new HTTPException(409, { message: "This client is already revoked." });
  await requirePrivileged(
    access,
    c.get("session"),
    "credential.rotate",
    privilegedRequestHash("credential.rotate", { databaseId, clientId }),
  );
  const operation = await queueClientRevocation({ databaseId, clientId, actorId: access.userId });
  await audit(
    access.userId,
    "database.client_revoke",
    "database",
    databaseId,
    { clientId, name: client.name, environment: client.environment },
    operation.id,
    access.role,
  );
  return c.json({ clientId, operationId: operation.id }, 202);
});

app.get("/api/databases/:id/clients/:clientId/vercel", async (c) => {
  requireOwner(c.get("access"));
  return c.json(await databaseClientVercelGuide(c.req.param("id"), c.req.param("clientId")));
});

// ---- Database client certificate rollover (front door §3.10.4, FD-28) ---------------------------
// Owner-only. The early rollover needs MFA plus a single-use `credential.rotate` grant bound to
// the request; revealing the successor needs `secret.reveal`; confirming delivery needs MFA.

app.get("/api/databases/:id/clients/:clientId/rollover", async (c) => {
  requireOwner(c.get("access"));
  return c.json(
    await rolloverStatus({
      databaseId: c.req.param("id"),
      clientId: c.req.param("clientId"),
      now: new Date(),
    }),
  );
});

app.post("/api/databases/:id/clients/:clientId/rollover", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const databaseId = c.req.param("id");
  const clientId = c.req.param("clientId");
  const request = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const input = earlyRolloverInput.parse(request);
  if (input.csrPem !== undefined) validateCsr(input.csrPem);
  const client = await getDatabaseClient(databaseId, clientId);
  if (!client) throw new HTTPException(404, { message: "Database client not found." });
  await requirePrivileged(
    access,
    c.get("session"),
    "credential.rotate",
    privilegedRequestHash("credential.rotate", { databaseId, clientId, rollover: true, ...request }),
  );
  const { operation, predecessor } = await queueEarlyRollover({
    databaseId,
    clientId,
    actorId: access.userId,
    csrPem: input.csrPem,
  });
  await audit(
    access.userId,
    "database.client_rollover",
    "database",
    databaseId,
    {
      clientId,
      early: true,
      predecessorId: predecessor.id,
      predecessorNotAfter: predecessor.notAfter.toISOString(),
      keySource: input.csrPem === undefined ? "generated" : "csr",
    },
    operation.id,
    access.role,
  );
  return c.json({ clientId, operationId: operation.id, predecessorId: predecessor.id }, 202);
});

app.post("/api/databases/:id/clients/:clientId/rollover/reveal", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const databaseId = c.req.param("id");
  const clientId = c.req.param("clientId");
  const client = await getDatabaseClient(databaseId, clientId);
  if (!client) throw new HTTPException(404, { message: "Database client not found." });
  await requirePrivileged(
    access,
    c.get("session"),
    "secret.reveal",
    privilegedRequestHash("secret.reveal", { databaseId, clientId, rollover: true }),
  );
  const bundle = await revealRolloverSuccessor({
    databaseId,
    clientId,
    actorId: access.userId,
    actorRole: access.role,
  });
  c.header("cache-control", "no-store");
  return c.json(bundle);
});

app.post("/api/databases/:id/clients/:clientId/rollover/confirm", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const input = rolloverConfirmInput.parse(await c.req.json());
  return c.json(
    await confirmRolloverDelivery({
      databaseId: c.req.param("id"),
      clientId: c.req.param("clientId"),
      certificateId: input.certificateId,
      actorId: access.userId,
      actorRole: access.role,
      source: "manual",
      now: new Date(),
    }),
  );
});

const vercelIntegrationPath = "/api/databases/:id/clients/:clientId/vercel-integration";

app.get(vercelIntegrationPath, async (c) => {
  requireOwner(c.get("access"));
  c.header("cache-control", "no-store");
  return c.json(
    await vercelIntegrationStatus({
      databaseId: c.req.param("id"),
      clientId: c.req.param("clientId"),
    }),
  );
});

app.put(vercelIntegrationPath, async (c) => {
  const access = c.get("access");
  const session = c.get("session");
  requireOwner(access);
  requireMfa(session);
  const databaseId = c.req.param("id");
  const clientId = c.req.param("clientId");
  const request = vercelConnectInput.safeParse(await c.req.json().catch(() => null));
  if (!request.success) throw new HTTPException(422, { message: "Invalid Vercel connection settings." });
  await requirePrivileged(
    access,
    session,
    "credential.rotate",
    privilegedRequestHash("credential.rotate", {
      databaseId,
      clientId,
      vercelIntegration: "connect",
      ...vercelConnectBinding(request.data),
    }),
  );
  c.header("cache-control", "no-store");
  return c.json(
    await connectVercel(
      { databaseId, clientId, actorId: access.userId, actorRole: access.role },
      request.data,
    ),
  );
});

app.post(`${vercelIntegrationPath}/test`, async (c) => {
  const access = c.get("access");
  const session = c.get("session");
  requireOwner(access);
  requireMfa(session);
  const databaseId = c.req.param("id");
  const clientId = c.req.param("clientId");
  await requirePrivileged(
    access,
    session,
    "credential.rotate",
    privilegedRequestHash("credential.rotate", {
      databaseId,
      clientId,
      vercelIntegration: "test",
    }),
  );
  c.header("cache-control", "no-store");
  return c.json(
    await testVercelConnection({ databaseId, clientId, actorId: access.userId, actorRole: access.role }),
  );
});

app.delete(vercelIntegrationPath, async (c) => {
  const access = c.get("access");
  const session = c.get("session");
  requireOwner(access);
  requireMfa(session);
  const databaseId = c.req.param("id");
  const clientId = c.req.param("clientId");
  await requirePrivileged(
    access,
    session,
    "credential.rotate",
    privilegedRequestHash("credential.rotate", {
      databaseId,
      clientId,
      vercelIntegration: "disconnect",
    }),
  );
  c.header("cache-control", "no-store");
  return c.json(
    await disconnectVercel({ databaseId, clientId, actorId: access.userId, actorRole: access.role }),
  );
});

app.get("/api/mail/queue", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMailEnabled();
  // Queue entries carry sender and recipient addresses for every tenant. Scope reads to the
  // domains the caller may view, matching the domain scoping the mutation route already does.
  const domainRows = await db.select().from(domainClaims);
  const visible = new Set(
    domainRows.filter((item) => canViewDomain(access, item.id)).map((item) => item.name.toLowerCase()),
  );
  const items = (await listMailQueue())
    .filter((item) => {
      const recipient = item.recipient.split("@")[1]?.toLowerCase() ?? "";
      const sender = item.sender.split("@")[1]?.toLowerCase() ?? "";
      return visible.has(recipient) || visible.has(sender);
    })
    .map(redactQueueItem);
  return c.json({ items });
});

app.post("/api/mail/queue", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  requireMailEnabled();
  const input = queueActionInput.parse(await c.req.json());
  const native = (await listMailQueue()).find((item) => item.id === input.item.id);
  if (!native) throw new HTTPException(404, { message: "Queue item not found." });
  const domainRows = await db.select().from(domainClaims);
  const domains = domainRows.map((item) => item.name);
  const allowed = canMutateQueue({ action: input.action, item: native, localDomains: domains });
  if (!allowed.ok) throw new HTTPException(422, { message: allowed.reason });
  const recipientDomain = native.recipient.split("@")[1]?.toLowerCase();
  const domain = domainRows.find((item) => item.name === recipientDomain);
  if (!domain) throw new HTTPException(403, { message: "Queue item is outside managed mail domains." });
  requireDomain(access, domain.id, "manage");
  const operation = await enqueue({
    kind: input.action === "delete" ? "mail.queue_delete" : "mail.queue_retry",
    actorId: access.userId,
    targetIds: [input.item.id],
    payload: native,
  });
  await audit(
    access.userId,
    `mail.queue.${input.action}`,
    "mail-queue",
    input.item.id,
    { action: input.action, recipient: native.recipient },
    operation.id,
    access.role,
  );
  return c.json({ operationId: operation.id });
});

app.post("/api/mailboxes/:id/devices", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  requireMailEnabled();
  const input = deviceInput.parse(await c.req.json());
  const [mailbox] = await db
    .select()
    .from(mailboxes)
    .where(eq(mailboxes.id, c.req.param("id")));
  if (!mailbox) throw new HTTPException(404, { message: "Mailbox not found." });
  requireDomain(access, mailbox.domainId, "manage");
  const id = createId("dev");
  await db.insert(mailboxDevices).values({ id, mailboxId: mailbox.id, label: input.label });
  const operation = await enqueue({
    kind: "mailbox.device",
    actorId: access.userId,
    targetIds: [mailbox.id],
    payload: { action: "create", deviceId: id, label: input.label },
  });
  await audit(
    access.userId,
    "mailbox.device.create",
    "mailbox",
    mailbox.id,
    { deviceId: id, label: input.label },
    operation.id,
    access.role,
  );
  return c.json({ id, operationId: operation.id });
});

app.post("/api/devices/:id/credential", async (c) => {
  const access = c.get("access");
  const [device] = await db
    .select()
    .from(mailboxDevices)
    .where(eq(mailboxDevices.id, c.req.param("id")));
  if (!device) throw new HTTPException(404, { message: "Device not found." });
  const [mailbox] = await db.select().from(mailboxes).where(eq(mailboxes.id, device.mailboxId));
  if (!mailbox) throw new HTTPException(404, { message: "Mailbox not found." });
  requireDomain(access, mailbox.domainId, "manage");
  if (!device.secretId) throw new HTTPException(409, { message: "The native credential is not ready." });
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "secret.reveal",
    privilegedRequestHash("secret.reveal", { deviceId: c.req.param("id") }),
  );
  const consumed = await consumeOneTimeSecret(device.secretId, {
    actorId: access.userId,
    role: access.role,
    resourceType: "mailbox-device",
    resourceId: device.id,
    kind: `mailbox-device.${device.id}`,
  });
  if (!consumed) throw new HTTPException(409, { message: "This device password was already shown." });
  c.header("cache-control", "no-store");
  return c.json({ password: revealSecret(consumed) });
});

app.post("/api/devices/:id/revoke", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  requireMailEnabled();
  const [device] = await db
    .select()
    .from(mailboxDevices)
    .where(eq(mailboxDevices.id, c.req.param("id")));
  if (!device) throw new HTTPException(404, { message: "Device not found." });
  const [mailbox] = await db.select().from(mailboxes).where(eq(mailboxes.id, device.mailboxId));
  if (!mailbox) throw new HTTPException(404, { message: "Mailbox not found." });
  requireDomain(access, mailbox.domainId, "manage");
  const operation = await enqueue({
    kind: "mailbox.device",
    actorId: access.userId,
    targetIds: [mailbox.id],
    payload: { action: "revoke", deviceId: device.id },
  });
  await audit(access.userId, "mailbox.device.revoke", "mailbox", mailbox.id, {}, operation.id, access.role);
  return c.json({ operationId: operation.id });
});

app.post("/api/platform/maintain", async (c) => {
  const access = c.get("access");
  if (access.role !== "owner") throw new HTTPException(403, { message: "Owner access is required." });
  const input = maintainInput.parse(await c.req.json());
  // Falling back to a placeholder would turn the second factor into a public constant, so an
  // unconfigured maintenance token has to fail closed.
  if (!env.maintenanceToken) {
    throw new HTTPException(503, {
      message: "ARK_MAINTENANCE_TOKEN is not configured; platform maintenance is unavailable.",
    });
  }
  if (!secureEqual(c.req.header("x-maintenance-token") ?? "", env.maintenanceToken)) {
    throw new HTTPException(403, { message: "Maintenance token is invalid." });
  }
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "platform.update",
    privilegedRequestHash("platform.update", { maintain: input }),
  );
  const operation = await enqueue({
    kind: "platform.maintain",
    actorId: access.userId,
    targetIds: ["platform"],
    payload: input,
  });
  await audit(
    access.userId,
    "platform.maintain",
    "platform",
    "platform",
    input as Record<string, unknown>,
    operation.id,
    access.role,
  );
  return c.json({ operationId: operation.id });
});

app.post("/api/secrets/:id/reveal", async (c) => {
  const access = c.get("access");
  const [secret] = await db
    .select()
    .from(secrets)
    .where(eq(secrets.id, c.req.param("id")));
  if (!secret) throw new HTTPException(404, { message: "Secret not found." });
  await requireSecretScope(access, secret);
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "secret.reveal",
    privilegedRequestHash("secret.reveal", { secretId: c.req.param("id") }),
  );
  let consumed = secret;
  if (secret.once) {
    const winner = await consumeOneTimeSecret(secret.id, {
      actorId: access.userId,
      role: access.role,
      resourceType: secret.resourceType!,
      resourceId: secret.resourceId!,
      kind: secret.kind,
    });
    if (!winner)
      throw new HTTPException(409, {
        message: "This credential was already revealed. Rotate it to obtain a new value.",
      });
    consumed = winner;
  } else {
    await audit(
      access.userId,
      "secret.reveal",
      secret.resourceType!,
      secret.resourceId!,
      { kind: secret.kind },
      undefined,
      access.role,
    );
  }
  const value = revealSecret(consumed);
  c.header("cache-control", "no-store");
  return c.json({ value, kind: secret.kind });
});

app.post("/api/databases/:id/credential", async (c) => {
  const access = c.get("access");
  await requireDatabaseAccess(access, c.req.param("id"), "manage");
  const [role] = await db
    .select()
    .from(databaseRoles)
    .where(and(eq(databaseRoles.databaseId, c.req.param("id")), eq(databaseRoles.kind, "runtime")));
  if (!role?.secretId) throw new HTTPException(404, { message: "Runtime credential is not available." });
  const [secret] = await db.select().from(secrets).where(eq(secrets.id, role.secretId));
  if (!secret) throw new HTTPException(404, { message: "Runtime credential is not available." });
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "secret.reveal",
    privilegedRequestHash("secret.reveal", { databaseId: c.req.param("id"), kind: "runtime" }),
  );
  const consumed = await consumeOneTimeSecret(secret.id, {
    actorId: access.userId,
    role: access.role,
    resourceType: "database",
    resourceId: c.req.param("id"),
    kind: secret.kind,
  });
  if (!consumed)
    throw new HTTPException(409, {
      message: "This password was already shown. Rotate the role to generate a new one.",
    });
  const password = revealSecret(consumed);
  const [database] = await db
    .select()
    .from(managedDatabases)
    .where(eq(managedDatabases.id, c.req.param("id")));
  const [cluster] = await db
    .select()
    .from(databaseClusters)
    .where(eq(databaseClusters.id, database?.clusterId ?? ""));
  const [endpoint] = cluster?.endpointId
    ? await db.select().from(endpoints).where(eq(endpoints.id, cluster.endpointId))
    : [];
  const hostname = endpoint?.hostname ?? "db.local";
  c.header("cache-control", "no-store");
  return c.json({
    username: role.name,
    password,
    connectionString: `postgresql://${role.name}:${encodeURIComponent(password)}@${hostname}:5432/${database?.name}?sslmode=verify-full`,
  });
});

app.post("/api/mailboxes/:id/credential", async (c) => {
  const access = c.get("access");
  const [mailbox] = await db
    .select()
    .from(mailboxes)
    .where(eq(mailboxes.id, c.req.param("id")));
  if (!mailbox) throw new HTTPException(404, { message: "Mailbox not found." });
  // Scope first: answering 409-vs-403 before the grant check would tell a caller without access
  // whether a foreign mailbox still holds an unrevealed credential.
  requireDomain(access, mailbox.domainId, "manage");
  if (!mailbox.credentialAvailable)
    throw new HTTPException(409, { message: "No one-time mailbox credential remains." });
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "secret.reveal",
    privilegedRequestHash("secret.reveal", { mailboxId: c.req.param("id") }),
  );
  const [secret] = await db
    .select()
    .from(secrets)
    .where(eq(secrets.kind, `mailbox.${mailbox.id}`))
    .orderBy(desc(secrets.createdAt))
    .limit(1);
  if (!secret) throw new HTTPException(409, { message: "No one-time mailbox credential remains." });
  const consumed = await consumeOneTimeSecret(secret.id, {
    actorId: access.userId,
    role: access.role,
    resourceType: "mailbox",
    resourceId: mailbox.id,
    kind: secret.kind,
  });
  if (!consumed) throw new HTTPException(409, { message: "No one-time mailbox credential remains." });
  const password = revealSecret(consumed);
  await db.update(mailboxes).set({ credentialAvailable: false }).where(eq(mailboxes.id, mailbox.id));
  c.header("cache-control", "no-store");
  return c.json({ password });
});

app.post("/api/backups", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const body = z
    .object({ kind: z.enum(["platform-postgres", "app-postgres", "mail", "volume"]), targetId: z.string() })
    .parse(await c.req.json());
  await requireTargetScope(access, body.targetId);
  const operation = await enqueue({
    kind: "backup.create",
    actorId: access.userId,
    targetIds: [body.targetId],
    payload: body,
  });
  return c.json({ operationId: operation.id });
});

app.post("/api/backups/restore-test", async (c) => {
  const access = c.get("access");
  const body = z
    .object({
      kind: z.enum(["platform-postgres", "app-postgres", "mail", "volume"]),
      targetId: z.string(),
      backupId: z.string().min(1),
    })
    .parse(await c.req.json());
  await requireTargetScope(access, body.targetId);
  const [selected] = await db.select().from(backups).where(eq(backups.id, body.backupId));
  if (!selected || selected.targetId !== body.targetId || selected.kind !== body.kind) {
    throw new HTTPException(404, { message: "The selected backup does not belong to this target." });
  }
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "restore.overwrite",
    privilegedRequestHash("restore.overwrite", {
      kind: body.kind,
      targetId: body.targetId,
      backupId: body.backupId,
    }),
  );
  const operation = await enqueue({
    kind: "backup.restore_test",
    actorId: access.userId,
    targetIds: [body.targetId],
    payload: body,
  });
  await audit(
    access.userId,
    "backup.restore_test",
    "backup",
    body.backupId,
    { kind: body.kind, targetId: body.targetId },
    operation.id,
    access.role,
  );
  return c.json({ operationId: operation.id });
});

/**
 * A completed restore test only proves the bytes came back. Restore proof — the state stateful
 * updates gate on — requires a human to confirm the restored copy actually booted and served
 * its data, which is what this route records.
 */
app.post("/api/backups/:id/verify-restore", async (c) => {
  const access = c.get("access");
  const [selected] = await db
    .select()
    .from(backups)
    .where(eq(backups.id, c.req.param("id")));
  if (!selected) throw new HTTPException(404, { message: "Backup not found." });
  await requireTargetScope(access, selected.targetId);
  const body = z
    .object({ confirmation: z.literal("restored copy booted and served its data") })
    .parse(await c.req.json());
  await requirePrivileged(
    access,
    c.get("session"),
    "restore.overwrite",
    privilegedRequestHash("restore.overwrite", { backupId: selected.id, verify: true }),
  );
  let status: string;
  try {
    status = nextBackupStatus(selected.status as BackupStatus, "restore");
  } catch (error) {
    throw new HTTPException(409, {
      message: error instanceof Error ? error.message : "Backup cannot be marked restore verified.",
    });
  }
  await db.update(backups).set({ status, restoreVerified: true }).where(eq(backups.id, selected.id));
  await audit(
    access.userId,
    "backup.restore_verified",
    "backup",
    selected.id,
    { confirmation: body.confirmation },
    undefined,
    access.role,
  );
  return c.json({ id: selected.id, status, restoreVerified: true });
});

// Off-VPS backup targets (front door §3.3, §3.18, FD-21). Owner-only. Saving needs MFA and a
// single-use `credential.rotate` grant bound to the request; credentials are write-only and never
// returned. Saving (and the weekly schedule) runs the append-only canary.
app.get("/api/backups/targets", async (c) => {
  requireOwner(c.get("access"));
  const targets = await db.select().from(backupTargets);
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  return c.json({
    targets: targets.map(publicTarget),
    health: await backupHealth(),
    recipes: PROVIDER_RECIPES,
    tailnetRecipe: TAILNET_REST_RECIPE,
    regionHint: regionSummary(settings ?? null).backupRegionHint,
    bucketProtectionPolicy: Object.fromEntries(
      targets
        .filter((item) => item.bucket)
        .map((item) => [item.id, repositoryProtectionPolicy(item.bucket!, item.prefix)]),
    ),
    writerPolicy: Object.fromEntries(
      targets.filter((item) => item.bucket).map((item) => [item.id, writerPolicy(item.bucket!, item.prefix)]),
    ),
  });
});

app.put("/api/backups/targets/:kind", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  if (c.req.param("kind") === "tailnet_rest")
    return c.json(await saveTailnetTarget(await c.req.json(), access, c.get("session")));
  if (c.req.param("kind") !== "s3") {
    throw new HTTPException(400, { message: "Backup target kind must be s3 or tailnet_rest." });
  }
  const request = await c.req.json();
  const input = s3TargetInput.parse(request);
  await requirePrivileged(
    access,
    c.get("session"),
    "credential.rotate",
    privilegedRequestHash("credential.rotate", { backupTarget: "s3", ...request }),
  );
  let target: Awaited<ReturnType<typeof saveS3Target>>;
  try {
    target = await saveS3Target(input);
  } catch (error) {
    throw new HTTPException(422, {
      message: error instanceof Error ? error.message : "Backup target rejected.",
    });
  }
  const operation = await enqueue({
    kind: "backup.verify_target",
    actorId: access.userId,
    targetIds: [target.id],
    payload: { revision: target.configRevision },
  });
  await audit(
    access.userId,
    "backup.target_saved",
    "backup_target",
    target.id,
    {
      provider: input.provider,
      endpoint: input.endpoint,
      bucket: input.bucket,
      prefix: input.prefix,
      pathStyle: input.pathStyle,
      region: input.region,
      recoveryWindowDays: input.recoveryWindowDays,
      credentialsReplaced: Boolean(input.accessKeyId),
      verifierReplaced: input.verifierToken !== undefined,
    },
    operation.id,
    access.role,
  );
  return c.json({ target: publicTarget(target), verifyOperationId: operation.id });
});

/**
 * The home target (FD-30, front door §3.18.3): pinned from backup-ts's own observation when saved, so
 * the request fails unless backup-ts currently sees exactly one matching, untagged home machine.
 */
async function saveTailnetTarget(request: Record<string, unknown>, access: Access, session: SessionValue) {
  const input = tailnetRestTargetInput.parse(request);
  await requirePrivileged(
    access,
    session,
    "credential.rotate",
    privilegedRequestHash("credential.rotate", { backupTarget: "tailnet_rest", ...request }),
  );
  let target: Awaited<ReturnType<typeof saveTailnetRestTarget>>;
  try {
    target = await saveTailnetRestTarget(input);
  } catch (error) {
    throw new HTTPException(422, {
      message: error instanceof Error ? error.message : "Backup target rejected.",
    });
  }
  const operation = await enqueue({
    kind: "backup.verify_target",
    actorId: access.userId,
    targetIds: [target.id],
    payload: { revision: target.configRevision },
  });
  await audit(
    access.userId,
    "backup.target_saved",
    "backup_target",
    target.id,
    {
      kind: "tailnet_rest",
      restUrl: input.restUrl,
      pinned: { stableId: target.targetNodeStableId, ip: target.targetIp },
      recoveryWindowDays: input.recoveryWindowDays,
      credentialsReplaced: Boolean(input.password),
    },
    operation.id,
    access.role,
  );
  return { target: publicTarget(target), verifyOperationId: operation.id };
}

// backup-ts's view of the tailnet (FD-30): its own generation, lease and each home target's identity.
app.get("/api/backups/tailnet", async (c) => {
  requireOwner(c.get("access"));
  return c.json(await backupTailnetOverview());
});

app.post("/api/backups/tailnet/observe", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  // Read-only, no exposure effect; a queued or running observation is reused.
  const operation = await enqueue({ kind: "backup.observe", targetIds: [BACKUP_OBSERVE_TARGET] });
  await audit(access.userId, "backup.tailnet.observe", "tailnet", "backup", {}, operation?.id, access.role);
  return c.json({ operation }, 202);
});

app.post("/api/backups/targets/:id/verify", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  const [target] = await db
    .select()
    .from(backupTargets)
    .where(eq(backupTargets.id, c.req.param("id")));
  if (!target) throw new HTTPException(404, { message: "Backup target not found." });
  const operation = await enqueue({
    kind: "backup.verify_target",
    actorId: access.userId,
    targetIds: [target.id],
    payload: { revision: target.configRevision },
  });
  await audit(
    access.userId,
    "backup.target_verify",
    "backup_target",
    target.id,
    {},
    operation.id,
    access.role,
  );
  return c.json({ operationId: operation.id });
});

const metricLabel = (value: string) => value.replace(/["\\\n]/g, "_");

async function backupTargetMetrics() {
  const health = await backupHealth();
  const targets = await db.select().from(backupTargets);
  const label = metricLabel;
  return [
    "# TYPE ark_backup_target_last_success_age_seconds gauge",
    ...targets.map(
      (item) =>
        `ark_backup_target_last_success_age_seconds{target="${label(item.name)}"} ${item.lastSuccessAt ? Math.round((Date.now() - item.lastSuccessAt.getTime()) / 1000) : -1}`,
    ),
    "# TYPE ark_backup_target_append_only_verified gauge",
    ...health.targets.map(
      (item) =>
        `ark_backup_target_append_only_verified{target="${label(item.name)}"} ${item.appendOnly.current ? 1 : 0}`,
    ),
    "# TYPE ark_backup_recovery_point_age_seconds gauge",
    ...health.targets.flatMap((item) =>
      item.sources.map(
        (source) =>
          `ark_backup_recovery_point_age_seconds{target="${label(item.name)}",source="${label(source.source)}"} ${source.lastRecoverableAt ? Math.round((Date.now() - new Date(source.lastRecoverableAt).getTime()) / 1000) : -1}`,
      ),
    ),
    "# TYPE ark_backups_healthy gauge",
    `ark_backups_healthy ${health.healthy ? 1 : 0}`,
  ];
}

app.post("/api/mail/reconcile", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  requireMailEnabled();
  const body = z.object({ mailboxId: z.string() }).parse(await c.req.json());
  const [mailbox] = await db.select().from(mailboxes).where(eq(mailboxes.id, body.mailboxId));
  if (!mailbox) throw new HTTPException(404, { message: "Mailbox not found." });
  requireDomain(access, mailbox.domainId, "manage");
  const operation = await enqueue({
    kind: "mail.reconcile",
    actorId: access.userId,
    targetIds: [body.mailboxId],
  });
  return c.json({ operationId: operation.id });
});

app.post("/api/ses/reconcile", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  requireMailEnabled();
  const body = z.object({ domainId: z.string() }).parse(await c.req.json());
  requireDomain(access, body.domainId, "manage");
  const operation = await enqueue({
    kind: "ses.reconcile",
    actorId: access.userId,
    targetIds: [body.domainId],
  });
  return c.json({ operationId: operation.id });
});

app.post("/api/mailboxes/:id/lifecycle", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  requireMailEnabled();
  const body = z
    .object({ lifecycle: z.enum(["active", "suspended", "retained", "purged"]) })
    .parse(await c.req.json());
  const [mailbox] = await db
    .select()
    .from(mailboxes)
    .where(eq(mailboxes.id, c.req.param("id")));
  if (!mailbox) throw new HTTPException(404, { message: "Mailbox not found." });
  requireDomain(access, mailbox.domainId, "manage");
  if (mailbox.lifecycle === "purged")
    throw new HTTPException(409, { message: "A purged mailbox address stays reserved." });
  if (body.lifecycle === "purged") {
    await requirePrivileged(
      access,
      c.get("session"),
      "resource.delete",
      privilegedRequestHash("resource.delete", { mailboxId: c.req.param("id"), lifecycle: "purged" }),
    );
    const [domain] = await db.select().from(domainClaims).where(eq(domainClaims.id, mailbox.domainId));
    const address = `${mailbox.localPart}@${domain?.name}`.toLowerCase();
    const dependencies = (await db.select().from(aliases)).filter(
      (alias) =>
        alias.status === "active" && alias.targets.some((target) => target.toLowerCase() === address),
    );
    if (dependencies.length) {
      throw new HTTPException(409, {
        message: `Remove ${dependencies.length} alias dependency before permanently purging this mailbox.`,
      });
    }
  }
  await db.update(mailboxes).set({ lifecycle: body.lifecycle }).where(eq(mailboxes.id, mailbox.id));
  const operation = await enqueue({
    kind: "mail.reconcile",
    actorId: access.userId,
    targetIds: [mailbox.id],
    payload: { lifecycle: body.lifecycle },
  });
  await audit(access.userId, "mailbox.lifecycle", "mailbox", mailbox.id, body, operation.id, access.role);
  return c.json({ operationId: operation.id });
});

app.post("/api/updates/detect", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  if (access.role !== "owner") throw new HTTPException(403, { message: "Owner access is required." });
  const operation = await enqueue({
    kind: "update.detect",
    actorId: access.userId,
    targetIds: ["platform"],
  });
  return c.json({ operationId: operation.id });
});

app.post("/api/import/scan", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  if (access.role !== "owner") throw new HTTPException(403, { message: "Owner access is required." });
  const body = z
    .object({
      source: z.enum(["orkmail", "pgstack", "compose"]),
      domains: z.array(z.string()).optional(),
      databases: z.array(z.string()).optional(),
      services: z.array(z.string()).optional(),
    })
    .parse(await c.req.json());
  const operation = await enqueue({
    kind: "import.scan",
    actorId: access.userId,
    targetIds: ["platform"],
    payload: body,
  });
  await audit(
    access.userId,
    "import.scan",
    "platform",
    "platform",
    { source: body.source },
    operation.id,
    access.role,
  );
  return c.json({ operationId: operation.id, ownersImported: false });
});

app.post("/api/alerts/:id/ack", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  await db
    .update(alerts)
    .set({ acknowledged: true })
    .where(eq(alerts.id, c.req.param("id")));
  return c.json({ ok: true });
});

app.post("/api/alerts/:id/silence", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const body = z.object({ minutes: z.number().int().min(5).max(10_080) }).parse(await c.req.json());
  const [alert] = await db
    .select()
    .from(alerts)
    .where(eq(alerts.id, c.req.param("id")));
  if (!alert) throw new HTTPException(404, { message: "Alert not found." });
  const silencedUntil = new Date(Date.now() + body.minutes * 60_000);
  await db.update(alerts).set({ silencedUntil }).where(eq(alerts.id, alert.id));
  await audit(
    access.userId,
    "alert.silence",
    "alert",
    alert.id,
    { silencedUntil: silencedUntil.toISOString() },
    undefined,
    access.role,
  );
  return c.json({ silencedUntil });
});

app.post("/api/updates/apply", async (c) => {
  const access = c.get("access");
  const body = z.object({ serviceId: z.string(), digest: z.string() }).parse(await c.req.json());
  const [service] = await db.select().from(services).where(eq(services.id, body.serviceId));
  if (!service) throw new HTTPException(404, { message: "Service not found." });
  requireProject(access, service.projectId);
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "platform.update",
    privilegedRequestHash("platform.update", { serviceId: body.serviceId, digest: body.digest }),
  );
  const operation = await enqueue({
    kind: "update.apply",
    actorId: access.userId,
    targetIds: [body.serviceId],
    payload: body,
  });
  await audit(access.userId, "update.apply", "service", body.serviceId, body, operation.id, access.role);
  return c.json({ operationId: operation.id });
});

app.post("/api/settings/mode", async (c) => {
  const access = c.get("access");
  if (access.role !== "owner") throw new HTTPException(403, { message: "Owner access is required." });
  const body = z.object({ adminMode: z.enum(["public", "tailnet"]) }).parse(await c.req.json());
  await requirePrivileged(
    access,
    c.get("session"),
    "exposure.public",
    privilegedRequestHash("exposure.public", { adminMode: body.adminMode }),
  );
  const operation = await enqueue({
    kind: "admin.mode_change",
    actorId: access.userId,
    targetIds: ["platform"],
    payload: body,
  });
  await audit(access.userId, "settings.mode", "platform", "platform", body, operation.id, access.role);
  return c.json({ operationId: operation.id });
});

app.put("/api/settings", async (c) => {
  const access = c.get("access");
  if (access.role !== "owner") throw new HTTPException(403, { message: "Owner access is required." });
  requireMfa(c.get("session"));
  const input = settingsInput.parse(await c.req.json());
  await db
    .update(platformSettings)
    .set({
      timezone: input.timezone,
      defaultQuotaGb: input.defaultQuotaGb,
      allowExternalForwarding: input.allowExternalForwarding,
      updatedAt: new Date(),
    })
    .where(eq(platformSettings.id, "default"));
  await audit(access.userId, "settings.update", "platform", "platform", input, undefined, access.role);
  return c.json({ ok: true });
});

// Region preset (front door §3.15, FD-03). Every signed-in role can read the suggestions; the
// Vercel guide and backup wizard render them. The setting never touches AWS_REGION or SES.
app.get("/api/settings/region", async (c) => {
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  return c.json(regionSummary(settings ?? null));
});

app.put("/api/settings/region", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const request = await c.req.json();
  const input = regionSettingsInput.parse(request);
  // Validate before consuming the single-use grant, so a typo does not burn a password+MFA round.
  // Bind to the original JSON, just as /api/step-up does; normalize only the stored values.
  await requirePrivileged(
    access,
    c.get("session"),
    "platform.update",
    privilegedRequestHash("platform.update", request),
  );
  const [previous] = await db
    .select({ region: platformSettings.region, vpsRegionLabel: platformSettings.vpsRegionLabel })
    .from(platformSettings)
    .where(eq(platformSettings.id, "default"));
  const values = { region: input.region, vpsRegionLabel: input.vpsRegionLabel, updatedAt: new Date() };
  const [settings] = await db
    .insert(platformSettings)
    .values({ id: "default", ...values })
    .onConflictDoUpdate({ target: platformSettings.id, set: values })
    .returning();
  await audit(
    access.userId,
    "settings.region",
    "platform",
    "platform",
    { ...input, previous: previous ?? null },
    undefined,
    access.role,
  );
  return c.json(regionSummary(settings ?? null));
});

// Per-source limits on the public database port (front door §3.11, FD-18). Every signed-in role
// can read them; changing them re-renders `inet ark_db_ingress` through a pgbouncer.reload.
app.get("/api/settings/db-ingress", async (c) => {
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  return c.json(dbIngressLimitsSummary(settings ?? null));
});

app.put("/api/settings/db-ingress", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const request = await c.req.json();
  const input = dbIngressLimitsInput.parse(request);
  // Validate before consuming the single-use grant, so a typo does not burn a password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "platform.update",
    privilegedRequestHash("platform.update", request),
  );
  const [previous] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  const values = {
    dbIngressMaxConnections: input.maxConnectionsPerSource,
    dbIngressRatePerSecond: input.newConnectionsPerSecond,
    dbIngressRateBurst: input.newConnectionBurst,
    updatedAt: new Date(),
  };
  const [settings] = await db
    .insert(platformSettings)
    .values({ id: "default", ...values })
    .onConflictDoUpdate({ target: platformSettings.id, set: values })
    .returning();
  const operation = await enqueue({
    kind: "pgbouncer.reload",
    actorId: access.userId,
    targetIds: ["platform"],
    payload: { dbIngressLimits: input },
  });
  await audit(
    access.userId,
    "settings.db_ingress",
    "platform",
    "platform",
    { ...input, previous: previous ? platformDbIngressLimits(previous) : null },
    operation.id,
    access.role,
  );
  return c.json({ ...dbIngressLimitsSummary(settings ?? null), operationId: operation.id });
});

// Gate login origin (front door §3.3, §3.9.1, FD-10). R1: public or disabled only. Enabling or moving
// it needs an `exposure.public` step-up bound to the exact body; disabling tightens and needs none.
app.get("/api/settings/gate", async (c) => {
  requireOwner(c.get("access"));
  return c.json(await gateSettingsSummary());
});

app.put("/api/settings/gate", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const request = (await c.req.json()) as Record<string, unknown>;
  // Validate before consuming the single-use grant, so a typo does not burn a password+MFA round.
  const plan = await prepareGateSettings(gateSettingsInput.parse(request));
  const authorize =
    plan.mode === "public"
      ? (tx: import("./db.ts").DbTransaction) =>
          requirePrivileged(
            access,
            c.get("session"),
            "exposure.public",
            privilegedRequestHash("exposure.public", request),
            tx,
          )
      : undefined;
  const result = await commitGateSettings(
    plan,
    { userId: access.userId, role: access.role },
    enqueueGateOperation,
    authorize,
  );
  return c.json({ ...(await gateSettingsSummary()), ...result, records: plan.records });
});

app.get("/api/settings/ipv6/preflight", async (c) => {
  requireOwner(c.get("access"));
  requireMfa(c.get("session"));
  const settings = await ipv6Settings();
  const id = c.req.query("operationId") ?? settings?.ipv6Evidence?.operationId;
  c.header("cache-control", "no-store");
  return c.json({
    ...ipv6Summary(settings),
    manual: typeof id === "string" ? await ipv6PreflightChallenge(id, env.authSecret) : null,
  });
});

app.post("/api/settings/ipv6/preflight", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const operation = await enqueue({
    kind: ipv6PreflightKind,
    targetIds: [ipv6PreflightTarget],
    actorId: access.userId,
    idempotencyKey: ipv6PreflightKey,
  });
  await audit(
    access.userId,
    "settings.ipv6_preflight",
    "platform",
    "platform",
    {},
    operation.id,
    access.role,
  );
  return c.json({ operationId: operation.id }, 202);
});

// Tailscale policy snippets (front door §3.7, FD-07). Owner-only, like route management (R12):
// the snippet maps the tailnet machines behind every public route. Ark never writes the policy.
app.get("/api/front/acl", async (c) => {
  requireOwner(c.get("access"));
  return c.json(await frontAclSnippet({ kind: "global" }));
});

// Edge node's view of the tailnet (front door §3.3, FD-06): latest complete generation, lease and
// every route's identity state. Owner-only, like the rest of route management.
app.get("/api/front/tailnet", async (c) => {
  requireOwner(c.get("access"));
  return c.json(await tailnetOverview());
});

app.post("/api/front/tailnet/observe", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  // Read-only, with no exposure effect; a queued or running observation is reused.
  const operation = await enqueue({ kind: "edge.observe", targetIds: [EDGE_OBSERVE_TARGET] });
  await audit(access.userId, "front.tailnet.observe", "tailnet", "edge", {}, operation?.id, access.role);
  return c.json({ operation }, 202);
});

app.get("/api/front/routes/:id/acl", async (c) => {
  requireOwner(c.get("access"));
  const snippet = await frontAclSnippet({ kind: "route", routeId: c.req.param("id") });
  if (!snippet) throw new HTTPException(404, { message: "Route not found." });
  return c.json(snippet);
});

// HTTP route lifecycle (front door §3.3, §3.13, §3.14, FD-08). Every role may list routes; every
// change is owner-only (R12) with MFA. Creating, enabling and loosening need a single-use
// `exposure.public` grant bound to the exact request, deleting a `resource.delete` grant, and
// disabling (a tightening) none. Final validation, grant consumption and mutation commit together.
app.get("/api/front/routes", async (c) => {
  return c.json({ routes: await listFrontRoutes() });
});

// Listeners and protocol guidance for route creation (front door §3.8.2, FD-14): which shared SNI
// ports this host enabled at install time, the dedicated raw-TCP range, the ports that can never be
// a dedicated port, and which protocols can be routed by name.
app.get("/api/front/listeners", async (c) => {
  return c.json({
    sniRouterPort: 443,
    sharedSniPorts: { available: SHARED_SNI_PORTS, enabled: enabledSniPorts() },
    tcpPorts: TCP_ROUTE_PORTS,
    reservedPorts: RESERVED_ROUTE_PORTS,
    tlsModes: ["passthrough", "terminate", "terminate_mtls"],
    guidance: PROTOCOL_GUIDANCE,
    // Postgres routes on the 5432 router (FD-26, §3.8.3): target hardening and driver guidance.
    postgres: {
      port: POSTGRES_ROUTER_PORT,
      compatPorts: TCP_ROUTE_PORTS,
      checklist: POSTGRES_TARGET_CHECKLIST,
      drivers: POSTGRES_DRIVER_GUIDANCE,
      notes: POSTGRES_ROUTE_NOTES,
      poolerBoundary: POOLER_POLICY_BOUNDARY,
    },
  });
});

app.get("/api/front/routes/:id", async (c) => {
  const [route] = await listFrontRoutes(c.req.param("id"));
  if (!route) throw new HTTPException(404, { message: "Route not found." });
  return c.json({ route });
});

app.get("/api/front/routes/:id/dns", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  const [row] = await db
    .select({ domainId: endpoints.domainId })
    .from(frontRoutes)
    .innerJoin(endpoints, eq(endpoints.id, frontRoutes.endpointId))
    .where(eq(frontRoutes.id, c.req.param("id")));
  if (!row?.domainId) throw new DnsReviewError(404, "No DNS claim for this route.");
  requireDomain(access, row.domainId);
  c.header("cache-control", "no-store");
  return c.json(await getDnsReview(row.domainId, c.req.query("local") === "1"));
});

app.post("/api/front/routes", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const request = (await c.req.json()) as Record<string, unknown>;
  const plan = await prepareRouteCreate(frontRouteCreateInput.parse(request));
  const authorize = (tx: import("./db.ts").DbTransaction) =>
    requirePrivileged(
      access,
      c.get("session"),
      "exposure.public",
      privilegedRequestHash("exposure.public", request),
      tx,
    );
  const actor = { userId: access.userId, role: access.role };
  const { routeId, records, observeOperationId } = await commitRouteCreate(plan, actor, enqueue, authorize);
  const [route] = await listFrontRoutes(routeId);
  return c.json(
    {
      route,
      records: records.map((record) => ({
        type: record.type,
        name: record.name,
        relativeName: record.relativeName,
        value: record.value,
        ttl: record.ttl,
        required: record.required,
      })),
      acl: await frontAclSnippet({ kind: "route", routeId }),
      operationId: observeOperationId,
    },
    201,
  );
});

app.patch("/api/front/routes/:id", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const routeId = c.req.param("id");
  const request = (await c.req.json()) as Record<string, unknown>;
  const plan = await prepareRouteUpdate(routeId, frontRouteUpdateInput.parse(request));
  const authorize = plan.loosening.length
    ? (tx: import("./db.ts").DbTransaction) =>
        requirePrivileged(
          access,
          c.get("session"),
          "exposure.public",
          privilegedRequestHash("exposure.public", { routeId, ...request }),
          tx,
        )
    : undefined;
  try {
    const { status } = await commitRouteUpdate(
      plan,
      { userId: access.userId, role: access.role },
      enqueue,
      authorize,
    );
    const [route] = await listFrontRoutes(routeId);
    return c.json({ route, status, loosening: plan.loosening });
  } catch (error) {
    if (error instanceof HTTPException && error.status === 403)
      return c.json({ error: error.message, code: "exposure_step_up_required" }, 403);
    throw error;
  }
});

app.post("/api/front/routes/:id/enable", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const routeId = c.req.param("id");
  const plan = await prepareRouteEnable(routeId);
  const authorize = (tx: import("./db.ts").DbTransaction) =>
    requirePrivileged(
      access,
      c.get("session"),
      "exposure.public",
      privilegedRequestHash("exposure.public", { routeId }),
      tx,
    );
  await commitRouteEnable(plan, { userId: access.userId, role: access.role }, enqueue, authorize);
  const [route] = await listFrontRoutes(routeId);
  return c.json({ route });
});

app.post("/api/front/routes/:id/disable", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const routeId = c.req.param("id");
  await disableRoute(routeId, { userId: access.userId, role: access.role }, enqueue);
  const [route] = await listFrontRoutes(routeId);
  return c.json({ route });
});

// Client certificates of a terminate_mtls route (front door §3.8.4, FD-14) or an HTTP mTLS route
// (FD-23). Owner-only. Issuing grants access, so it needs a `credential.rotate` grant bound to the
// route and exact body; revoking tightens (the CRL is regenerated and the route's sessions drained)
// and needs none.
const routeClientCertificateInput = z
  .object({
    name: z
      .string()
      .trim()
      .min(1)
      .max(64)
      .regex(/^[A-Za-z0-9][A-Za-z0-9._@-]*$/, "Use letters, digits, '.', '_', '@' or '-'."),
    csrPem: z
      .string()
      .max(16 * 1024)
      .optional(),
  })
  .strict();

app.get("/api/front/routes/:id/client-certificates", async (c) => {
  requireOwner(c.get("access"));
  return c.json(await listRouteClientCertificates(c.req.param("id")));
});

app.post("/api/front/routes/:id/client-certificates", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const routeId = c.req.param("id");
  const request = (await c.req.json()) as Record<string, unknown>;
  const input = routeClientCertificateInput.parse(request);
  if (input.csrPem !== undefined) validateCsr(input.csrPem);
  const issued = await issueRouteClientCertificate(
    routeId,
    input,
    { userId: access.userId, role: access.role },
    enqueue,
    (tx) =>
      requirePrivileged(
        access,
        c.get("session"),
        "credential.rotate",
        privilegedRequestHash("credential.rotate", { routeId, ...request }),
        tx,
      ),
  );
  c.header("cache-control", "no-store");
  return c.json(issued, 201);
});

app.post("/api/front/routes/:id/client-certificates/:certificateId/revoke", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const result = await revokeRouteClientCertificate(c.req.param("id"), c.req.param("certificateId"), {
    userId: access.userId,
    role: access.role,
  });
  return c.json(result);
});

app.delete("/api/front/routes/:id", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const routeId = c.req.param("id");
  const plan = await prepareRouteDelete(routeId);
  const authorize = (tx: import("./db.ts").DbTransaction) =>
    requirePrivileged(
      access,
      c.get("session"),
      "resource.delete",
      privilegedRequestHash("resource.delete", { routeId }),
      tx,
    );
  const result = await commitRouteDelete(
    plan,
    { userId: access.userId, role: access.role },
    enqueue,
    authorize,
  );
  return c.json({ id: routeId, ...result });
});

// Route access lists (front door §3.3, §3.9.6, FD-11): individual users only (R11). Reading is
// owner-only like the rest of route management; replacing needs MFA and a `role.grant` step-up bound
// to the route and the exact list. Removals revoke and drain atomically (§3.9.3).
app.get("/api/front/routes/:id/access", async (c) => {
  requireOwner(c.get("access"));
  const routeId = c.req.param("id");
  const [route] = await listFrontRoutes(routeId);
  if (!route) throw new HTTPException(404, { message: "Route not found." });
  return c.json({ routeId, users: await listRouteAccess(routeId) });
});

app.put("/api/front/routes/:id/access", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const routeId = c.req.param("id");
  const request = (await c.req.json()) as Record<string, unknown>;
  const input = routeAccessInput.parse(request);
  const result = await replaceRouteAccess(
    routeId,
    input.userIds,
    { userId: access.userId, role: access.role },
    (tx) =>
      requirePrivileged(
        access,
        c.get("session"),
        "role.grant",
        privilegedRequestHash("role.grant", { routeId, ...request }),
        tx,
      ),
  );
  return c.json({ routeId, ...result, users: await listRouteAccess(routeId) });
});

// Gate users (front door §3.9.6, FD-12): login-origin-only accounts for SSO routes, with no
// `platform_access` row. Owner only. Creating and deleting need MFA and a `role.grant` step-up bound
// to the exact request; the one-time temporary password leaves only through its own reveal, with a
// `secret.reveal` step-up, exactly once. Deletion cascades sessions, gate sessions and route access,
// and journals the forced-reload drain for every affected route in the same transaction (§3.9.3).
app.get("/api/gate/users", async (c) => {
  requireOwner(c.get("access"));
  c.header("cache-control", "no-store");
  return c.json({ users: await listGateUsers() });
});

app.post("/api/gate/users", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const request = (await c.req.json()) as Record<string, unknown>;
  const input = gateUserInput.parse(request);
  const created = await createGateUser(
    input,
    { userId: access.userId, role: access.role },
    () =>
      requirePrivileged(
        access,
        c.get("session"),
        "role.grant",
        privilegedRequestHash("role.grant", gateUserCreateBinding(request)),
      ),
    c.get("requestOrigin").host,
  );
  c.header("cache-control", "no-store");
  return c.json({ user: created }, 201);
});

app.post("/api/gate/users/:id/temporary-password", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const userId = c.req.param("id");
  const password = await revealGateUserPassword(userId, { userId: access.userId, role: access.role }, (tx) =>
    requirePrivileged(
      access,
      c.get("session"),
      "secret.reveal",
      privilegedRequestHash("secret.reveal", gateUserRevealBinding(userId)),
      tx,
    ),
  );
  c.header("cache-control", "no-store");
  return c.json({ id: userId, password });
});

app.delete("/api/gate/users/:id", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const userId = c.req.param("id");
  const result = await deleteGateUser(userId, { userId: access.userId, role: access.role }, (tx) =>
    requirePrivileged(
      access,
      c.get("session"),
      "role.grant",
      privilegedRequestHash("role.grant", gateUserDeleteBinding(userId)),
      tx,
    ),
  );
  return c.json(result);
});

app.get("/api/metrics", async (c) => {
  const [ops, backupRows, certs] = await Promise.all([
    db.select().from(operations),
    db.select().from(backups),
    db.select().from(certificates),
  ]);
  return c.json({
    operationsFailed: ops.filter((item) => item.status === "failed").length,
    operationsRunning: ops.filter((item) => item.status === "running").length,
    backupsWithoutRestoreProof: backupRows.filter((item) => !item.restoreVerified).length,
    certificatesExpiringSoon: certs.filter(
      (item) => item.expiresAt && item.expiresAt.getTime() < Date.now() + 14 * 24 * 60 * 60 * 1000,
    ).length,
  });
});

app.get("/api/me", async (c) => {
  const [row] = await db
    .select()
    .from(user)
    .where(eq(user.id, c.get("session").user.id));
  return c.json({ user: row, access: c.get("access") });
});

// ---- Login gate pages (front door §3.9.2, FD-11) --------------------------------------------------
// Served on the login origin only; on every other host the namespace is 404 and never falls through
// to the admin SPA.

/** The login-origin session of this request, when it was minted on the login origin. */
async function gateLoginSession(c: Context<AppEnv>) {
  const value = await auth.api.getSession({ headers: authHeaders(c) });
  if (!value || (value.session as { origin?: string }).origin !== "gate") return null;
  const [row] = await db.select().from(user).where(eq(user.id, value.user.id));
  if (!row) return null;
  return { value, user: row };
}

function gateHtml(c: Context<AppEnv>, status: number, html: (nonce: string) => string) {
  const nonce = gateNonce();
  return c.body(html(nonce), status as 200, gatePageHeaders(nonce));
}

app.get("/gate/login", async (c) => {
  if (c.get("requestOrigin")?.origin !== "gate") return c.json({ error: "Not found." }, 404);
  const next = checkLoginNext(c.req.query("next"));
  const current = await gateLoginSession(c);
  if (current && !current.user.twoFactorEnabled) return c.redirect(gateEnrollPath(next), 303);
  if (current && next) return c.redirect(next, 303);
  return gateHtml(c, 200, (nonce) => loginPage({ nonce, next, signedInAs: current?.user.email ?? null }));
});

/** The forced-enrollment page, carrying a validated relative authorize `next` through. */
function gateEnrollPath(next: string | null) {
  return next ? `/gate/enroll?next=${encodeURIComponent(next)}` : "/gate/enroll";
}

// Forced first TOTP enrollment (§3.9.6, FD-12). A login-origin session whose user has not enrolled
// TOTP can reach nothing else: authorize and the gate check require MFA assurance, so it is sent here.
app.get("/gate/enroll", async (c) => {
  if (c.get("requestOrigin")?.origin !== "gate") return c.json({ error: "Not found." }, 404);
  const next = checkLoginNext(c.req.query("next"));
  const current = await gateLoginSession(c);
  if (!current) return c.redirect(next ? `/gate/login?next=${encodeURIComponent(next)}` : "/gate/login", 303);
  if (current.user.twoFactorEnabled) return c.redirect(next ?? "/gate/login", 303);
  return gateHtml(c, 200, (nonce) => enrollPage({ nonce, next, email: current.user.email }));
});

app.get("/gate/authorize", async (c) => {
  if (c.get("requestOrigin")?.origin !== "gate") return c.json({ error: "Not found." }, 404);
  const url = new URL(c.req.url);
  const current = await gateLoginSession(c);
  if (!current) {
    // Relative only: the login page follows `next` back here after sign-in.
    const next = `/gate/authorize${url.search}`;
    return c.redirect(`/gate/login?next=${encodeURIComponent(next)}`, 303);
  }
  // No TOTP yet (a new gate user's first login): enroll first, then come back here.
  if (!current.user.twoFactorEnabled) return c.redirect(gateEnrollPath(`/gate/authorize${url.search}`), 303);
  const outcome = await gateAuthorize({
    routeId: url.searchParams.get("route"),
    state: url.searchParams.get("state"),
    rd: url.searchParams.get("rd"),
    session: {
      id: current.value.session.id,
      userId: current.user.id,
      createdAt: new Date(current.value.session.createdAt),
    },
    user: { twoFactorEnabled: current.user.twoFactorEnabled, mfaEnrolledAt: current.user.mfaEnrolledAt },
  });
  if (outcome.kind === "redirect") {
    return new Response(null, {
      status: 303,
      headers: { Location: outcome.location, "Referrer-Policy": "no-referrer", "Cache-Control": "no-store" },
    });
  }
  return gateHtml(c, outcome.status, (nonce) =>
    gateMessagePage({ nonce, title: "Access denied", message: outcome.message, signOut: true }),
  );
});

// Global logout on the login origin: ends the login session, and with it (ON DELETE CASCADE) every
// route session; the revocation triggers queue the forced reload for each affected route (§3.9.3).
app.post("/gate/logout", async (c) => {
  const requestOrigin = c.get("requestOrigin");
  if (requestOrigin?.origin !== "gate") return c.json({ error: "Not found." }, 404);
  if (c.req.header("origin") !== `https://${requestOrigin.host}`)
    return c.json({ error: "The request origin is not trusted." }, 403);
  const headers = new Headers({ Location: "/gate/login", "Cache-Control": "no-store" });
  if (await gateLoginSession(c)) {
    const signedOut = await auth.api.signOut({ headers: authHeaders(c), asResponse: true });
    for (const cookie of signedOut.headers.getSetCookie()) headers.append("Set-Cookie", cookie);
  }
  return new Response(null, { status: 303, headers });
});

// The gate pages' icon (favicon and page mark): fixed, cacheable paths on the login origin only, so
// the pages' CSP needs just `img-src 'self'`.
app.get("/gate/brand/:file", (c) => {
  if (c.get("requestOrigin")?.origin !== "gate") return c.json({ error: "Not found." }, 404);
  const asset = gateBrandAsset(new URL(c.req.url).pathname);
  if (!asset) return c.json({ error: "Not found." }, 404);
  return c.body(asset.body, 200, asset.headers);
});

app.all("/gate/*", (c) => c.json({ error: "Not found." }, 404));

const webDist = new URL("../../web/dist", import.meta.url).pathname;
if (existsSync(webDist)) {
  app.use("/*", serveStatic({ root: webDist }));
  app.get("*", serveStatic({ path: `${webDist}/index.html` }));
}
