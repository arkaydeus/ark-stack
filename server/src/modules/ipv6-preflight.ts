import { createHmac } from "node:crypto";
import { join } from "node:path";

import {
  IPV6_HOST_SAMPLE_MS,
  IPV6_PREFLIGHT_TICKET_MS,
  IPV6_PREFLIGHT_WEEK_MS,
  createId,
  currentGeneration,
  dockerIpv6Ready,
  evaluateIpv6Report,
  ipv6ProbeReport,
  ipv6ProbeRequest,
  planHash,
  publicIpv6,
  secureEqual,
  signIpv6Report,
  type EdgeL4Manifest,
  type Ipv6DockerState,
  type Ipv6EdgeLog,
  type Ipv6ExpectedCheck,
  type Ipv6ProbeReport,
  type Ipv6ProbeRequest,
} from "@ark-stack/shared";
import { and, desc, eq, ne } from "drizzle-orm";

import { db, type DbTransaction } from "../db.ts";
import { domainClaims, frontRoutes, operations, operationSteps, platformSettings } from "../schema.ts";
import { reconcileDomainDns } from "./domain-dns.ts";
import { edgeL4Settings } from "./edge-l4.ts";
import { poolerEdgeInput } from "./pooler-policy.ts";

type Settings = typeof platformSettings.$inferSelect;
type Operation = typeof operations.$inferSelect;
type Snapshot = { docker?: Ipv6DockerState; logs?: Ipv6EdgeLog[] };
type Host = { at: number; addresses: string[] };
const settingsId = eq(platformSettings.id, "default");
const challengeStep = "ipv6-preflight-challenge";
const resultStep = "ipv6-preflight-result";
export const ipv6PreflightKind = "domain.ipv6_preflight" as const;
export const ipv6PreflightKey = "ipv6.preflight";
export const ipv6PreflightResultPath = "/api/settings/ipv6/preflight/result";

async function sample<T>(name: string): Promise<T | undefined> {
  const path = process.env[name];
  return path
    ? Bun.file(path)
        .json()
        .catch(() => undefined)
    : undefined;
}

export async function ipv6Settings() {
  const [settings] = await db.select().from(platformSettings).where(settingsId);
  return settings;
}

export function ipv6Summary(settings: Settings | undefined) {
  return {
    address: settings?.publicIpv6 ?? null,
    status: settings?.ipv6Status ?? "unchecked",
    checkedAt: settings?.ipv6CheckedAt ?? null,
    evidence: settings?.ipv6Evidence ?? null,
  };
}

async function installedGeneration() {
  const root = edgeL4Settings().root;
  if (!root) return null;
  const generation = await currentGeneration(root);
  if (!generation) return null;
  const manifest: EdgeL4Manifest | undefined = await Bun.file(
    join(root, "generations", generation, "manifest.json"),
  )
    .json()
    .catch(() => undefined);
  return manifest?.version === 2 ? { generation, ...manifest } : null;
}

async function preflightPlan(settings: Settings) {
  const [host, snapshot, edge, routes, pooler] = await Promise.all([
    sample<Host>("ARK_IPV6_HOST_SNAPSHOT"),
    sample<Snapshot>("ARK_IPV6_DOCKER_SNAPSHOT"),
    installedGeneration(),
    db
      .select()
      .from(frontRoutes)
      .where(and(eq(frontRoutes.enabled, true), ne(frontRoutes.kind, "http")))
      .orderBy(frontRoutes.id),
    poolerEdgeInput(),
  ]);
  const address = publicIpv6(settings.publicIpv6);
  const addresses =
    host &&
    Array.isArray(host.addresses) &&
    Date.now() - host.at >= 0 &&
    Date.now() - host.at <= IPV6_HOST_SAMPLE_MS
      ? [...new Set(host.addresses.map(publicIpv6).filter((ip) => ip !== null))].toSorted()
      : null;
  const docker = snapshot?.docker;
  const ready = dockerIpv6Ready(docker);
  const fingerprint = planHash([
    settings.publicIpv4,
    settings.publicIpv6,
    addresses === null ? null : addresses.length > 0,
    Boolean(address && addresses?.includes(address)),
    ready,
    docker?.daemon,
    docker?.edge,
    docker?.edgeAddress,
    edge?.generation,
    routes.map((route) => [route.id, route.listenPort, route.compatPort, route.updatedAt]),
    pooler.pooler,
  ]);
  const fail = (status: "failed" | "not_present", reason: string) => ({
    status,
    reason,
    fingerprint,
    addresses,
    docker,
  });
  if (!addresses) return fail("failed", "Host IPv6 observation is missing or stale.");
  if (!addresses.length) return fail("not_present", "The host has no public IPv6 address.");
  if (!address || !addresses.includes(address)) {
    return fail("failed", "The configured public IPv6 address is not a global address on the host.");
  }
  if (!ready)
    return fail(
      "failed",
      "Docker has not confirmed native IPv6, ip6tables, live-restore, proxy disabled and a dual-stack edge.",
    );
  if (!edge) return fail("failed", "The active HAProxy generation could not be read.");

  const checks: Ipv6ExpectedCheck[] = [];
  const tls443 = edge.routes.find((route) => route.kind === "tls" && route.listenPort === 443);
  const hostname = edge.httpHostnames[0] ?? tls443?.hostname;
  if (!hostname) return fail("failed", "Port 443 has no configured TLS hostname to probe.");
  checks.push({ id: "http", port: 80, protocol: "http", hostname });
  if (edge.httpHostnames.length) {
    checks.push({ id: "https", port: 443, protocol: "tls", hostname, frontend: "fe_tls443" });
  }
  if (pooler.pooler || edge.pooler) {
    const poolerName = pooler.pooler?.hostname;
    if (!poolerName || edge.pooler?.hostname !== poolerName) {
      return fail("failed", "Port 5432 has no active PgBouncer hostname matching its policy.");
    }
    checks.push({
      id: "pgbouncer",
      port: 5432,
      protocol: "postgres-classic",
      hostname: poolerName,
      clientCertificate: true,
      frontend: "fe_pg5432",
      backend: "be_pgbouncer",
      server: "pgbouncer",
    });
  }
  for (const stored of routes) {
    const route = edge.routes.find((candidate) => candidate.id === stored.id);
    if (
      !route ||
      route.listenPort !== stored.listenPort ||
      (route.compat?.listenPort ?? null) !== stored.compatPort
    ) {
      return fail(
        "failed",
        `Port ${stored.listenPort} route ${stored.id} is missing from active HAProxy configuration.`,
      );
    }
    const base = {
      id: route.id,
      port: route.listenPort,
      hostname: route.hostname,
      backend: route.loop?.backend ?? route.backend,
      server: route.loop?.server ?? route.server,
    };
    if (route.kind === "postgres") {
      checks.push({
        ...base,
        protocol: "postgres-direct",
        frontend: "fe_pg5432",
        clientCertificate: route.mode === "terminate_mtls",
      });
      if (route.compat)
        checks.push({
          ...base,
          id: route.id + "-compat",
          port: route.compat.listenPort,
          protocol: "tcp",
          frontend: `fe_${route.id}_compat`,
          backend: route.compat.backend,
          server: route.compat.server,
        });
    } else if (route.kind === "tcp") {
      checks.push({ ...base, protocol: "tcp", frontend: `fe_${route.id}` });
    } else {
      checks.push({
        ...base,
        protocol: "tls",
        frontend: `fe_tls${route.listenPort}`,
        clientCertificate: route.mode === "terminate_mtls",
      });
    }
  }
  if (checks.length < 2 || checks.length > 512)
    return fail("failed", "The external IPv6 probe needs a bounded, complete listener inventory.");
  return { status: "ready" as const, checks, address, fingerprint, addresses, docker };
}

export async function ipv6PreflightDue() {
  if (!process.env.ARK_IPV6_HOST_SNAPSHOT) return false;
  const settings = await ipv6Settings();
  if (!settings?.publicIpv4 && !settings?.publicIpv6) return false;
  const plan = await preflightPlan(settings);
  return (
    settings.ipv6Evidence?.fingerprint !== plan.fingerprint ||
    !settings.ipv6CheckedAt ||
    Date.now() - settings.ipv6CheckedAt.getTime() >= IPV6_PREFLIGHT_WEEK_MS
  );
}

async function step(
  tx: DbTransaction,
  operationId: string,
  name: string,
  evidence: Record<string, unknown>,
  error?: string,
) {
  await tx.insert(operationSteps).values({
    id: createId("step"),
    operationId,
    name,
    evidence,
    error,
    status: error ? "failed" : "succeeded",
  });
}

async function readStep(operationId: string, name: string, query: Pick<typeof db, "select"> = db) {
  const [row] = await query
    .select()
    .from(operationSteps)
    .where(and(eq(operationSteps.operationId, operationId), eq(operationSteps.name, name)))
    .orderBy(desc(operationSteps.createdAt))
    .limit(1);
  return row;
}

async function recordResult(
  tx: DbTransaction,
  settings: Settings,
  operationId: string,
  status: Settings["ipv6Status"],
  evidence: Record<string, unknown>,
  reason?: string,
) {
  const current = await tx
    .update(platformSettings)
    .set({
      ipv6Status: status,
      ipv6CheckedAt: new Date(),
      ipv6Evidence: { ...evidence, operationId, reason },
    })
    .where(settingsId)
    .returning();
  await step(tx, operationId, resultStep, { ...evidence, status }, status === "failed" ? reason : undefined);
  await reconcileIpv6Dns(tx, settings, current[0]!, operationId);
}

type Plan = Awaited<ReturnType<typeof preflightPlan>>;

async function latestSettings(tx: DbTransaction, before: Settings, plan: Plan) {
  const [settings] = await tx.select().from(platformSettings).where(settingsId).for("update");
  if (
    !settings ||
    settings.publicIpv4 !== before.publicIpv4 ||
    settings.publicIpv6 !== before.publicIpv6 ||
    settings.ipv6Evidence?.operationId !== before.ipv6Evidence?.operationId ||
    settings.ipv6CheckedAt?.getTime() !== before.ipv6CheckedAt?.getTime()
  ) {
    throw new Error("The platform address or IPv6 result changed. Start a new preflight.");
  }
  if ((await preflightPlan(settings)).fingerprint !== plan.fingerprint) {
    throw new Error("The host or edge configuration changed. Start a new IPv6 preflight.");
  }
  return settings;
}

function signedChallenge(request: Ipv6ProbeRequest, secret: string) {
  return createHmac("sha256", secret)
    .update("ark.ipv6.preflight\0")
    .update(JSON.stringify(ipv6ProbeRequest.parse(request)))
    .digest("base64url");
}

export async function ipv6PreflightChallenge(operationId: string, secret: string) {
  const row = await readStep(operationId, challengeStep);
  const validated = ipv6ProbeRequest.safeParse(row?.evidence.request);
  if (!validated.success || validated.data.expiresAt <= Date.now()) return null;
  if (await readStep(operationId, resultStep)) return null;
  const request = validated.data;
  return { request, token: signedChallenge(request, secret) };
}

export async function verifyIpv6Submission(report: Ipv6ProbeReport, signature: string, secret: string) {
  const challenge = await ipv6PreflightChallenge(report.id, secret);
  return Boolean(challenge && secureEqual(signIpv6Report(report, challenge.token), signature));
}

async function offhostReport(request: Ipv6ProbeRequest) {
  const url = new URL("/preflight", process.env.ARK_OFFHOST_HEARTBEAT_URL);
  const token = process.env.ARK_OFFHOST_HEARTBEAT_TOKEN;
  if (url.protocol !== "https:" || !token)
    throw new Error("Off-host IPv6 preflight needs HTTPS and a token.");
  const response = await fetch(url, {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(110_000),
    headers: { authorization: "Bearer " + token, "content-type": "application/json" },
    body: JSON.stringify(request),
  });
  if (!response.ok) throw new Error("The off-host runner refused the IPv6 probe.");
  return ipv6ProbeReport.parse(await response.json());
}

async function completeProbe(
  operation: Operation,
  settings: Settings,
  plan: Extract<Plan, { status: "ready" }>,
  request: Ipv6ProbeRequest,
  report: Ipv6ProbeReport,
  challengeId?: string,
) {
  let evidence = evaluateIpv6Report(request, plan.checks, report, []);
  // An ingress log is flushed when the connection closes and then picked up by the host timer.
  for (let attempt = 0; attempt < 9; attempt++) {
    const snapshot = await sample<Snapshot>("ARK_IPV6_DOCKER_SNAPSHOT");
    if (
      snapshot &&
      dockerIpv6Ready(snapshot.docker) &&
      snapshot.docker?.edge === plan.docker?.edge &&
      snapshot.docker?.daemon === plan.docker?.daemon
    ) {
      evidence = evaluateIpv6Report(
        request,
        plan.checks,
        report,
        Array.isArray(snapshot.logs) ? snapshot.logs : [],
      );
    }
    if (
      !evidence.some(
        (outcome) => outcome.outcome === "failed" && outcome.reason.startsWith("edge did not log"),
      ) ||
      attempt === 8
    )
      break;
    await Bun.sleep(1_000);
  }
  const unverified = evidence.filter((outcome) => outcome.outcome !== "passed");
  const reason = unverified.length
    ? "IPv6 preflight did not pass on " +
      unverified.map(({ port, protocol, hostname }) => `${port}/${protocol} (${hostname})`).join(", ")
    : undefined;

  await db.transaction(async (tx) => {
    const current = await latestSettings(tx, settings, plan);
    if (challengeId && (request.expiresAt <= Date.now() || (await readStep(challengeId, resultStep, tx)))) {
      throw new Error("The signed IPv6 preflight request expired or was already used.");
    }
    const metadata = {
      fingerprint: plan.fingerprint,
      addresses: plan.addresses,
      docker: plan.docker,
      checks: evidence,
    };
    await recordResult(tx, current, operation.id, reason ? "failed" : "passed", metadata, reason);
    if (challengeId)
      await step(tx, challengeId, resultStep, { submittedAs: operation.id, ...metadata }, reason);
  });
  if (reason) throw new Error(reason);
}

export async function runIpv6Preflight(operation: Operation) {
  const previous = await readStep(operation.id, resultStep);
  if (previous?.error) throw new Error(previous.error);
  if (previous || (await readStep(operation.id, challengeStep))) return;
  const settings = await ipv6Settings();
  if (!settings) throw new Error("Configure the platform addresses before running IPv6 preflight.");
  const plan = await preflightPlan(settings);
  const submitted = operation.payload.report ? ipv6ProbeReport.parse(operation.payload.report) : null;
  if (submitted) {
    const challenge = await readStep(submitted.id, challengeStep);
    const request = ipv6ProbeRequest.parse(challenge?.evidence.request);
    if (
      plan.status !== "ready" ||
      plan.fingerprint !== challenge?.evidence.fingerprint ||
      request.expiresAt <= Date.now() ||
      (await readStep(submitted.id, resultStep)) ||
      (settings.ipv6CheckedAt?.getTime() ?? 0) > request.issuedAt
    ) {
      throw new Error(
        "The signed IPv6 preflight request expired, was used, or names an older configuration.",
      );
    }
    return completeProbe(operation, settings, plan, request, submitted, submitted.id);
  }
  const metadata = { fingerprint: plan.fingerprint, addresses: plan.addresses, docker: plan.docker };
  if (plan.status !== "ready") {
    await db.transaction(async (tx) =>
      recordResult(
        tx,
        await latestSettings(tx, settings, plan),
        operation.id,
        plan.status,
        metadata,
        plan.reason,
      ),
    );
    if (plan.status === "failed") throw new Error(plan.reason);
    return;
  }

  const issuedAt = Date.now();
  const request = ipv6ProbeRequest.parse({
    id: operation.id,
    address: plan.address,
    issuedAt,
    expiresAt: issuedAt + IPV6_PREFLIGHT_TICKET_MS,
    checks: plan.checks,
  });
  if (process.env.ARK_OFFHOST_HEARTBEAT_URL) {
    let report: Ipv6ProbeReport | undefined;
    try {
      report = await offhostReport(request);
    } catch {
      // Transport failure is unverified for every port and is recorded through the same DNS flow.
    }
    return completeProbe(operation, settings, plan, request, report ?? { id: request.id, checks: [] });
  }

  await db.transaction(async (tx) => {
    const current = await latestSettings(tx, settings, plan);
    const fresh =
      current.ipv6Status === "passed" &&
      current.ipv6Evidence?.fingerprint === plan.fingerprint &&
      current.ipv6CheckedAt &&
      issuedAt - current.ipv6CheckedAt.getTime() < IPV6_PREFLIGHT_WEEK_MS;
    if (!fresh) {
      const reason = "Awaiting the signed off-host IPv6 preflight report.";
      // The challenge stays open after the initial unverified status is committed.
      const rows = await tx
        .update(platformSettings)
        .set({
          ipv6Status: "failed",
          ipv6CheckedAt: new Date(issuedAt),
          ipv6Evidence: {
            ...metadata,
            operationId: operation.id,
            reason,
            checks: request.checks.map(({ id, port, protocol, hostname }) => ({
              id,
              port,
              protocol,
              hostname,
              outcome: "unverified",
            })),
          },
        })
        .where(settingsId)
        .returning();
      await reconcileIpv6Dns(tx, current, rows[0]!, operation.id);
    }
    await step(tx, operation.id, challengeStep, { ...metadata, request });
  });
}

async function reconcileIpv6Dns(
  tx: DbTransaction,
  previous: Settings,
  current: Settings,
  operationId: string,
) {
  const domains = await tx.select().from(domainClaims).orderBy(domainClaims.id).for("update");
  for (const domain of domains) {
    const { stored, records } = await reconcileDomainDns(tx, domain, current);
    if (previous.ipv6Status === current.ipv6Status && records.every((record) => stored.includes(record)))
      continue;
    // The existing worker owns exact provider deletion, TTL confirmation and certificate handoff.
    const payload = { scheduledDns: true };
    await tx
      .insert(operations)
      .values({
        id: createId("op"),
        kind: "domain.verify",
        targetIds: [domain.id],
        payload,
        idempotencyKey: `dns.ipv6:${operationId}:${domain.id}`,
        planHash: planHash(payload),
      })
      .onConflictDoNothing({ target: operations.idempotencyKey });
  }
}
