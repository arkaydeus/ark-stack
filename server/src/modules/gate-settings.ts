// `PUT /api/settings/gate` (docs/design/front-door.md §3.3, §3.9.1, FD-10).
//
// R1: the login origin is public or disabled; a tailnet-only login mode is not offered. Enabling it
// (or moving it to another hostname) is an exposure decision: owner, MFA and an `exposure.public`
// step-up bound to the exact request. It writes `gate_login_mode`/`gate_login_hostname`, the `gate`
// endpoint and its address records in one transaction, then queues `domain.verify` (DNS, then the
// certificate through the normal endpoint flow) and `edge.apply`. The edge renders the login site only
// once its certificate is issued. Disabling tightens and needs no step-up: it removes the endpoint and
// its records, revokes every `gate` session (they belong to an origin that no longer exists) and
// re-applies the edge.

import {
  createId,
  normalizeRouteHostname,
  routeAddressRecords,
  routeDomainFor,
  type GateSettingsInput,
  type OperationKind,
} from "@ark-stack/shared";
import { and, eq } from "drizzle-orm";

import { db, type DbTransaction } from "../db.ts";
import { loadEnv } from "../env.ts";
import { isAdminHost, refreshLoginHost } from "../origin-hosts.ts";
import { auditEvents, dnsRecords, domainClaims, endpoints, platformSettings, session } from "../schema.ts";

const env = loadEnv();

export const GATE_ENDPOINT_KIND = "gate";
export const GATE_RECORD_PURPOSE = "Gate login hostname";

export class GateSettingsError extends Error {
  constructor(
    readonly status: 409 | 422,
    message: string,
  ) {
    super(message);
    this.name = "GateSettingsError";
  }
}

type Enqueue = (input: { kind: OperationKind; actorId?: string; targetIds: string[] }) => Promise<{
  id: string;
}>;

export async function gateSettingsSummary() {
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  const [endpoint] = await db.select().from(endpoints).where(eq(endpoints.kind, GATE_ENDPOINT_KIND));
  return {
    mode: settings?.gateLoginMode ?? "disabled",
    hostname: settings?.gateLoginHostname ?? null,
    endpointStatus: endpoint?.status ?? null,
    edgeTokenConfigured: Boolean(env.edgeGateToken),
  };
}

/** Every check for `PUT /api/settings/gate`, with no writes. */
export async function prepareGateSettings(input: GateSettingsInput) {
  if (input.mode === "disabled")
    return { mode: "disabled" as const, hostname: null, domain: null, records: [] };
  if (!env.edgeGateToken) {
    throw new GateSettingsError(
      422,
      "ARK_EDGE_GATE_TOKEN is not configured for the API. Without it the API cannot trust the edge's client address, and every login attempt would share one rate-limit bucket.",
    );
  }
  if (!env.authUrl.startsWith("https://")) {
    throw new GateSettingsError(
      422,
      "The login origin needs an HTTPS admin origin (BETTER_AUTH_URL), so its cookies are __Host- cookies.",
    );
  }
  const hostname = normalizeRouteHostname(input.hostname ?? "");
  const domain = routeDomainFor(hostname, await db.select().from(domainClaims));
  if (!domain) {
    throw new GateSettingsError(
      422,
      `No domain claim covers ${hostname}. Add the domain and verify its ownership record first.`,
    );
  }
  if (domain.status !== "verified") {
    throw new GateSettingsError(
      422,
      `The domain ${domain.name} is not verified yet (status ${domain.status}). Verify it first.`,
    );
  }
  const [platform] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  if (!platform?.publicIpv4) {
    throw new GateSettingsError(
      422,
      "Set the server's public IPv4 address before enabling the login origin.",
    );
  }
  if (isAdminHost(hostname) || hostname === platform.adminHostname) {
    throw new GateSettingsError(409, `${hostname} is the administration origin; choose another hostname.`);
  }
  const [endpoint] = await db.select().from(endpoints).where(eq(endpoints.hostname, hostname));
  if (endpoint && endpoint.kind !== GATE_ENDPOINT_KIND) {
    throw new GateSettingsError(409, `${hostname} is already used by the ${endpoint.kind} endpoint.`);
  }
  const records = routeAddressRecords({
    hostname,
    zone: domain.name,
    publicIpv4: platform.publicIpv4,
    publicIpv6: platform.publicIpv6,
    ipv6Status: platform.ipv6Status,
    aaaaEnabled: domain.aaaaEnabled,
    purpose: GATE_RECORD_PURPOSE,
  });
  return { mode: "public" as const, hostname, domain, records };
}

export type GateSettingsPlan = Awaited<ReturnType<typeof prepareGateSettings>>;

async function removeGateEndpoints(tx: DbTransaction, keepHostname: string | null) {
  for (const endpoint of await tx.select().from(endpoints).where(eq(endpoints.kind, GATE_ENDPOINT_KIND))) {
    if (endpoint.hostname === keepHostname) continue;
    if (endpoint.domainId) {
      await tx
        .delete(dnsRecords)
        .where(
          and(
            eq(dnsRecords.domainId, endpoint.domainId),
            eq(dnsRecords.name, endpoint.hostname),
            eq(dnsRecords.purpose, GATE_RECORD_PURPOSE),
          ),
        );
    }
    // Certificates cascade with the endpoint.
    await tx.delete(endpoints).where(eq(endpoints.id, endpoint.id));
  }
}

/**
 * Writes the plan atomically; `authorize` (the step-up grant) is consumed in the same transaction.
 * Returns the queued operation IDs.
 */
export async function commitGateSettings(
  plan: GateSettingsPlan,
  actor: { userId: string; role: string },
  enqueue: Enqueue,
  authorize?: (tx: DbTransaction) => Promise<unknown>,
) {
  const result = await db.transaction(async (tx) => {
    await authorize?.(tx);
    const [previous] = await tx
      .select({ mode: platformSettings.gateLoginMode, hostname: platformSettings.gateLoginHostname })
      .from(platformSettings)
      .where(eq(platformSettings.id, "default"))
      .for("update");
    await removeGateEndpoints(tx, plan.hostname);
    let revokedSessions = 0;
    if (plan.mode === "disabled" || previous?.hostname !== plan.hostname) {
      // Sessions minted on a login origin that no longer exists (or moved) are revoked.
      revokedSessions = (
        await tx.delete(session).where(eq(session.origin, "gate")).returning({ id: session.id })
      ).length;
    }
    if (plan.mode === "public" && plan.domain) {
      const [endpoint] = await tx
        .select()
        .from(endpoints)
        .where(eq(endpoints.hostname, plan.hostname))
        .for("update");
      if (endpoint && (endpoint.kind !== GATE_ENDPOINT_KIND || endpoint.domainId !== plan.domain.id)) {
        throw new GateSettingsError(409, `${plan.hostname} is already owned by another endpoint.`);
      }
      if (!endpoint) {
        const inserted = await tx
          .insert(endpoints)
          .values({
            id: createId("ep"),
            kind: GATE_ENDPOINT_KIND,
            hostname: plan.hostname,
            domainId: plan.domain.id,
            exposure: "public",
            status: "awaiting_dns",
          })
          .onConflictDoNothing({ target: endpoints.hostname })
          .returning({ id: endpoints.id });
        // A route can reserve the hostname after our SELECT. The unique constraint arbitrates;
        // abort the entire transaction (including authorization and session revocation) on loss.
        if (inserted.length === 0) {
          throw new GateSettingsError(409, `${plan.hostname} was reserved by another endpoint.`);
        }
      }
      const existing = await tx
        .select()
        .from(dnsRecords)
        .where(and(eq(dnsRecords.domainId, plan.domain.id), eq(dnsRecords.name, plan.hostname)));
      for (const current of existing) {
        if (
          current.purpose === GATE_RECORD_PURPOSE &&
          !plan.records.some((record) => record.type === current.type)
        ) {
          await tx.delete(dnsRecords).where(eq(dnsRecords.id, current.id));
        }
      }
      for (const record of plan.records) {
        const current = existing.find((item) => item.type === record.type);
        if (current && current.purpose === GATE_RECORD_PURPOSE && current.expectedValue === record.value)
          continue;
        if (current) await tx.delete(dnsRecords).where(eq(dnsRecords.id, current.id));
        await tx.insert(dnsRecords).values({
          id: createId("dns"),
          domainId: plan.domain.id,
          type: record.type,
          name: record.name,
          relativeName: record.relativeName,
          expectedValue: record.value,
          purpose: record.purpose,
          required: record.required,
        });
      }
    }
    await tx
      .insert(platformSettings)
      .values({ id: "default", gateLoginMode: plan.mode, gateLoginHostname: plan.hostname })
      .onConflictDoUpdate({
        target: platformSettings.id,
        set: { gateLoginMode: plan.mode, gateLoginHostname: plan.hostname, updatedAt: new Date() },
      });
    await tx.insert(auditEvents).values({
      id: createId("aud"),
      actorId: actor.userId,
      action: "settings.gate",
      resourceType: "platform",
      resourceId: "platform",
      role: actor.role,
      detail: {
        mode: plan.mode,
        hostname: plan.hostname,
        records: plan.records,
        previous: previous ?? null,
        revokedSessions,
      },
    });
    return { revokedSessions };
  });
  await refreshLoginHost(true);
  const operations: string[] = [];
  if (plan.mode === "public" && plan.domain) {
    operations.push(
      (await enqueue({ kind: "domain.verify", actorId: actor.userId, targetIds: [plan.domain.id] })).id,
    );
  }
  // Platform-wide consequence (like certificate issuance): no actor, so the owner check never trips.
  operations.push((await enqueue({ kind: "edge.apply", targetIds: ["platform"] })).id);
  return { ...result, operationIds: operations };
}
