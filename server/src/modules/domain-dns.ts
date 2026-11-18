import {
  aaaaAllowed,
  canViewDomain,
  createId,
  dnsRecordVerified,
  manualDnsGuides,
  planHash,
  relativeDnsName,
  type DnsRecordPlan,
  type DnsReviewRecord,
  type DnsReviewAction,
  type DomainDnsReview,
} from "@ark-stack/shared";
import { and, eq, inArray } from "drizzle-orm";

import { db, type DbTransaction } from "../db.ts";
import {
  auditEvents,
  dnsRecords,
  domainClaims,
  endpoints,
  operations,
  platformAccess,
  platformSettings,
} from "../schema.ts";
import {
  CloudflareDns,
  DnsReviewError,
  drift,
  ownershipMarker,
  planCloudflare,
  sameRecord,
} from "./cloudflare-dns.ts";

type Domain = typeof domainClaims.$inferSelect;
type Settings = typeof platformSettings.$inferSelect;
export type StoredDnsRecord = typeof dnsRecords.$inferSelect;
type DnsEndpoint = typeof endpoints.$inferSelect;

export const desiredDns = (record: StoredDnsRecord) => record.withdrawalReason === null;
export const pendingWithdrawal = (record: StoredDnsRecord) =>
  record.withdrawalReason !== null && record.withdrawalConfirmedAt === null;

export async function lockedDnsDomain(tx: DbTransaction, domainId: string) {
  const [settings] = await tx
    .select()
    .from(platformSettings)
    .where(eq(platformSettings.id, "default"))
    .for("share");
  const [domain] = await tx.select().from(domainClaims).where(eq(domainClaims.id, domainId)).for("update");
  if (!domain) throw new DnsReviewError(404, "Domain not found.");
  return { domain, settings };
}

export function dnsRecordValues(domainId: string, record: DnsRecordPlan) {
  return {
    id: createId("dns"),
    domainId,
    type: record.type,
    name: record.name,
    relativeName: record.relativeName,
    expectedValue: record.value,
    ttl: record.ttl,
    purpose: record.purpose,
    required: record.required,
  };
}

export function retireDnsRecord(record: StoredDnsRecord, reason: "ipv6" | "endpoint_deleted", now: Date) {
  return {
    ...record,
    status: "withdrawal_pending",
    withdrawalReason: reason,
    withdrawalStartedAt: now,
    // Route removal always requires its own review even if IPv6 withdrawal was authorized.
    automaticWithdrawal: reason === "ipv6" && record.automaticWithdrawal,
  };
}

function effectiveAaaa(domain: Domain, settings?: Settings) {
  return aaaaAllowed({
    aaaaEnabled: domain.aaaaEnabled,
    ipv6Status: settings?.ipv6Status ?? "unchecked",
    publicIpv6: settings?.publicIpv6,
  })
    ? (settings?.publicIpv6 ?? null)
    : null;
}

function projectDns(
  domain: Domain,
  settings: Settings | undefined,
  records: StoredDnsRecord[],
  endpointRows: DnsEndpoint[],
  now: Date,
) {
  const ipv6 = effectiveAaaa(domain, settings);
  const next = records.map((record) => {
    if (
      desiredDns(record) &&
      record.type === "AAAA" &&
      (!ipv6 || !dnsRecordVerified("AAAA", ipv6, record.expectedValue))
    ) {
      return retireDnsRecord(record, "ipv6", now);
    }
    if (
      desiredDns(record) &&
      record.type === "A" &&
      settings?.publicIpv4 &&
      endpointRows.some(
        (endpoint) => ["route", "gate"].includes(endpoint.kind) && endpoint.hostname === record.name,
      ) &&
      record.expectedValue !== settings.publicIpv4
    ) {
      return {
        ...record,
        expectedValue: settings.publicIpv4,
        publishedAt: null,
        observedValue: null,
        status: "pending",
      };
    }
    return record;
  });

  if (ipv6) {
    const publicNames = new Set(
      endpointRows.filter((endpoint) => endpoint.exposure === "public").map((endpoint) => endpoint.hostname),
    );
    for (const address of next.filter(
      (record) => desiredDns(record) && record.type === "A" && publicNames.has(record.name),
    )) {
      const history = next.filter((record) => record.type === "AAAA" && record.name === address.name);
      if (history.some(desiredDns)) continue;
      const restore = history.find(
        (record) =>
          pendingWithdrawal(record) &&
          record.withdrawalReason === "ipv6" &&
          record.required &&
          !record.providerRemovedAt &&
          dnsRecordVerified("AAAA", ipv6, record.expectedValue),
      );
      if (restore) {
        next[next.indexOf(restore)] = {
          ...restore,
          status: "pending",
          withdrawalReason: null,
          withdrawalStartedAt: null,
        };
        continue;
      }
      // A projected row must have the same ID in a dry run and its later publish transaction.
      const id = `dns_${planHash([address.id, ipv6, history.map((record) => record.id).toSorted()]).slice(0, 24)}`;
      next.push({
        ...address,
        id,
        type: "AAAA",
        expectedValue: ipv6,
        purpose: `${address.purpose} (IPv6)`,
        observedValue: null,
        providerOwnership: null,
        automaticWithdrawal: false,
        publishedAt: null,
        status: "pending",
      });
    }
  }
  return next.toSorted(
    (a, b) => a.name.localeCompare(b.name) || a.type.localeCompare(b.type) || a.id.localeCompare(b.id),
  );
}

async function dnsSnapshot(tx: DbTransaction, domain: Domain, settings?: Settings) {
  const [stored, endpointRows] = await Promise.all([
    tx.select().from(dnsRecords).where(eq(dnsRecords.domainId, domain.id)),
    tx.select().from(endpoints).where(eq(endpoints.domainId, domain.id)),
  ]);
  return { stored, endpointRows, records: projectDns(domain, settings, stored, endpointRows, new Date()) };
}

async function saveProjection(tx: DbTransaction, stored: StoredDnsRecord[], records: StoredDnsRecord[]) {
  const byId = new Map(stored.map((record) => [record.id, record]));
  for (const record of records) {
    const previous = byId.get(record.id);
    if (!previous) await tx.insert(dnsRecords).values(record);
    else if (previous !== record) await tx.update(dnsRecords).set(record).where(eq(dnsRecords.id, record.id));
  }
}

export async function reconcileDomainDns(tx: DbTransaction, domain: Domain, settings?: Settings) {
  const snapshot = await dnsSnapshot(tx, domain, settings);
  await saveProjection(tx, snapshot.stored, snapshot.records);
  return snapshot;
}

function reviewRecord(record: StoredDnsRecord) {
  const scope = record.providerOwnership;
  return {
    id: record.id,
    type: record.type,
    name: record.name,
    relativeName: record.relativeName,
    value: record.withdrawalReason && scope ? scope.record.content : record.expectedValue,
    observed: record.observedValue,
    ttl: record.withdrawalReason && scope ? cacheTtl(scope.record.ttl) : record.ttl,
    priority: record.type === "MX" ? 10 : undefined,
    purpose: record.purpose,
    status: record.status,
    providerRemoval: !pendingWithdrawal(record)
      ? null
      : record.providerRemovedAt
        ? ("propagating" as const)
        : !scope
          ? ("manual" as const)
          : record.automaticWithdrawal
            ? ("automatic" as const)
            : ("review" as const),
  };
}

function cacheTtl(ttl: number) {
  return ttl === 1 ? 300 : ttl;
}

function untrackedAaaa(records: StoredDnsRecord[], name: string, ip: string) {
  const matching = records.filter((record) => record.type === "AAAA" && record.name === name);
  return !matching.some(
    (record) =>
      desiredDns(record) ||
      (pendingWithdrawal(record) &&
        dnsRecordVerified("AAAA", record.providerOwnership?.record.content ?? record.expectedValue, ip)),
  );
}

export async function rememberUnexpectedAaaa(
  tx: DbTransaction,
  domain: Domain,
  records: StoredDnsRecord[],
  name: string,
  addresses: string[],
) {
  const additions = [];
  for (const value of new Set(addresses)) {
    if (!untrackedAaaa(records, name, value)) continue;
    const record = {
      ...dnsRecordValues(domain.id, {
        type: "AAAA",
        name,
        relativeName: relativeDnsName(name, domain.name),
        value,
        ttl: 300,
        purpose: "Unexpected public IPv6 address",
        required: false,
      }),
      status: "withdrawal_pending",
      withdrawalReason: "ipv6" as const,
      withdrawalStartedAt: new Date(),
    };
    const [saved] = await tx.insert(dnsRecords).values(record).returning();
    additions.push(saved);
  }
  return additions;
}

async function cloudflareReview(client: CloudflareDns, domain: Domain, records: StoredDnsRecord[]) {
  for (const current of records.filter(desiredDns)) {
    if (
      records.some(
        (record) =>
          pendingWithdrawal(record) &&
          record.providerRemovedAt &&
          record.providerOwnership &&
          record.name === current.name &&
          record.type === current.type &&
          dnsRecordVerified(current.type, current.expectedValue, record.providerOwnership.record.content),
      )
    ) {
      throw new DnsReviewError(
        409,
        `Wait for public DNS to confirm removal of the prior ${current.type} at ${current.name} before publishing that value again.`,
      );
    }
  }
  const planned = await planCloudflare(
    client,
    domain.name,
    records
      .filter((record) => desiredDns(record) && !record.expectedValue.includes("review existing"))
      .map((record) => ({
        recordId: record.id,
        type: record.type,
        name: record.name,
        content: record.expectedValue,
        ttl: record.ttl,
        priority: record.type === "MX" ? 10 : undefined,
        ownership: record.providerOwnership,
      })),
    records.flatMap((record) =>
      pendingWithdrawal(record) && record.providerOwnership && !record.providerRemovedAt
        ? [{ recordId: record.id, ownership: record.providerOwnership }]
        : [],
    ),
  );
  return { ...planned, planHash: planHash([domain.id, planned]) };
}

export function domainDnsReview(domainId: string, includeCloudflare = true): Promise<DomainDnsReview> {
  return db.transaction(async (tx) => {
    const { domain, settings } = await lockedDnsDomain(tx, domainId);
    const { records } = await dnsSnapshot(tx, domain, settings);
    const cloudflare =
      includeCloudflare && domain.dnsProvider === "cloudflare"
        ? await cloudflareReview(new CloudflareDns(), domain, records)
        : null;
    const visible = records.filter((record) => desiredDns(record) || pendingWithdrawal(record));
    const names = [
      ...new Set(
        visible.filter((record) => ["A", "AAAA"].includes(record.type)).map((record) => record.name),
      ),
    ];
    const providerOnly: DnsReviewRecord[] =
      cloudflare?.snapshots.flatMap(([name, snapshot]) =>
        names.includes(name)
          ? snapshot.flatMap((record) =>
              record.type === "AAAA" && untrackedAaaa(records, name, record.content)
                ? [
                    {
                      id: "provider:" + record.id,
                      type: record.type,
                      name,
                      relativeName: relativeDnsName(name, domain.name),
                      value: record.content,
                      observed: null,
                      ttl: cacheTtl(record.ttl),
                      purpose: "Unexpected Cloudflare IPv6 address",
                      status: "withdrawal_pending",
                      providerRemoval: "manual" as const,
                    },
                  ]
                : [],
            )
          : [],
      ) ?? [];
    return {
      domainId,
      zone: domain.name,
      provider: domain.dnsProvider,
      aaaaEnabled: domain.aaaaEnabled,
      automaticWithdrawalAuthorized: visible.some((record) => record.automaticWithdrawal),
      ipv6Status:
        providerOnly.length ||
        visible.some((record) => record.type === "AAAA" && pendingWithdrawal(record)) ||
        domain.lastError?.startsWith("Unexpected AAAA")
          ? "withdrawal_pending"
          : effectiveAaaa(domain, settings)
            ? "eligible"
            : "a_only",
      lastError: domain.lastError,
      records: [...visible.map(reviewRecord), ...providerOnly],
      guides: cloudflare
        ? []
        : manualDnsGuides(
            domain.name,
            names,
            visible.some((record) => record.type === "AAAA"),
          ),
      cloudflare: cloudflare ? { planHash: cloudflare.planHash, actions: cloudflare.actions } : null,
    };
  });
}

export type DnsPublishRequest = {
  planHash: string;
  authorizeAAAAWithdrawal?: true;
};

export type DnsPublisher = { userId: string; role: "owner" | "operator" };

async function applyDnsAction(
  tx: DbTransaction,
  client: CloudflareDns,
  zoneId: string,
  record: StoredDnsRecord,
  action: DnsReviewAction,
  authorize?: true,
) {
  if (action.action === "delete") {
    await client.delete(action.deletionScope!, action.before);
    await tx.update(dnsRecords).set({ providerRemovedAt: new Date() }).where(eq(dnsRecords.id, record.id));
    return;
  }

  const current = action.action === "keep" ? action.before! : await client.write(zoneId, action);
  const previous = record.providerOwnership;
  const previouslyOwned = Boolean(
    previous && action.before && previous.zoneId === zoneId && sameRecord(previous.record, action.before),
  );
  // A unique marker on Ark's POST also lets a retry recover a successful create whose response
  // or database commit was interrupted. Matching third-party records are never adopted.
  const created =
    action.action === "create" ||
    (!previous && action.action === "keep" && current.comment === ownershipMarker(record.id));
  const owned = previouslyOwned || created;
  await tx
    .update(dnsRecords)
    .set({
      publishedAt: new Date(),
      providerOwnership: owned ? { zoneId, record: current } : previous,
      automaticWithdrawal:
        owned &&
        record.type === "AAAA" &&
        (authorize === true || (previouslyOwned && record.automaticWithdrawal && action.action === "keep")),
    })
    .where(eq(dnsRecords.id, record.id));
}

export async function publishReviewedDns(domainId: string, input: DnsPublishRequest, actor: DnsPublisher) {
  const result = await db.transaction(async (tx) => {
    const { domain, settings } = await lockedDnsDomain(tx, domainId);
    if (domain.dnsProvider !== "cloudflare") throw new DnsReviewError(422, "This domain uses manual DNS.");
    const [access] = await tx
      .select()
      .from(platformAccess)
      .where(eq(platformAccess.userId, actor.userId))
      .for("share");
    if (
      !access ||
      access.role !== actor.role ||
      !canViewDomain({ ...access, role: actor.role }, domainId) ||
      (input.authorizeAAAAWithdrawal && actor.role !== "owner")
    ) {
      throw new DnsReviewError(
        403,
        "The actor is no longer authorized to publish or approve withdrawal for this domain.",
      );
    }
    const { stored, records } = await dnsSnapshot(tx, domain, settings);
    const client = new CloudflareDns();
    const reviewed = await cloudflareReview(client, domain, records);
    if (input.planHash !== reviewed.planHash) {
      throw new DnsReviewError(
        409,
        "The Cloudflare DNS plan changed. Review the latest diff before publishing.",
      );
    }
    await saveProjection(tx, stored, records);
    const byId = new Map(records.map((record) => [record.id, record]));
    const applied: DnsReviewAction[] = [];
    let failure: unknown;
    try {
      for (const action of reviewed.actions) {
        await applyDnsAction(
          tx,
          client,
          reviewed.zoneId,
          byId.get(action.recordId)!,
          action,
          input.authorizeAAAAWithdrawal,
        );
        applied.push(action);
      }
    } catch (error) {
      // Persist evidence for successful mutations if a later provider request fails.
      failure = error;
    }
    const operationId = failure ? null : createId("op");
    if (operationId) {
      // Publish and queue verification in the same commit. A worker cannot verify partial writes.
      await tx.insert(operations).values({
        id: operationId,
        kind: "domain.verify",
        actorId: actor.userId,
        targetIds: [domainId],
        idempotencyKey: "dns.publish:" + operationId,
        planHash: planHash({}),
      });
    }
    await tx.insert(auditEvents).values({
      id: createId("audit"),
      actorId: actor.userId,
      role: actor.role,
      action: "dns.publish",
      resourceType: "domain",
      resourceId: domainId,
      operationId,
      detail: {
        planHash: reviewed.planHash,
        actions: reviewed.actions,
        applied,
        authorizeAAAAWithdrawal: input.authorizeAAAAWithdrawal,
        incomplete: Boolean(failure),
      },
    });
    return { applied, failure, operationId };
  });
  if (result.failure) throw result.failure;
  return { actions: result.applied, operationId: result.operationId! };
}

export async function withdrawAuthorizedAaaa(tx: DbTransaction, domain: Domain, records: StoredDnsRecord[]) {
  const candidates = records.filter(
    (record) =>
      pendingWithdrawal(record) &&
      record.type === "AAAA" &&
      record.withdrawalReason === "ipv6" &&
      !record.providerRemovedAt &&
      record.automaticWithdrawal &&
      record.providerOwnership,
  );
  if (domain.dnsProvider !== "cloudflare" || !candidates.length) return [];
  const client = new CloudflareDns();
  const failures: string[] = [];
  for (const record of candidates) {
    const ownership = record.providerOwnership!;
    try {
      const zoneId = await client.zoneId(domain.name);
      if (zoneId !== ownership.zoneId) throw drift(ownership.record.type, ownership.record.name);
      const current = await client.record(zoneId, ownership.record.id);
      const action: DnsReviewAction = {
        recordId: record.id,
        action: "delete",
        before: current,
        after: null,
        deletionScope: ownership,
      };
      await applyDnsAction(tx, client, zoneId, record, action);
      // The verification in this transaction must wait the full TTL of the freshly removed record.
      record.providerRemovedAt = new Date();
      await tx.insert(auditEvents).values({
        id: createId("audit"),
        role: "system",
        action: "dns.withdraw_aaaa",
        resourceType: "domain",
        resourceId: domain.id,
        detail: { planHash: planHash([domain.id, action]), action, authorization: "preauthorized" },
      });
    } catch (error) {
      if (!(error instanceof DnsReviewError)) throw error;
      failures.push(error.message);
    }
  }
  return failures;
}

export async function confirmWithdrawals(
  tx: DbTransaction,
  records: StoredDnsRecord[],
  addresses: (type: string, name: string) => Promise<string[]>,
  now = new Date(),
) {
  const confirmed: string[] = [];
  for (const record of records.filter(pendingWithdrawal)) {
    const owned = record.providerOwnership;
    if (
      owned &&
      (!record.providerRemovedAt ||
        now.getTime() < record.providerRemovedAt.getTime() + cacheTtl(owned.record.ttl) * 1000)
    )
      continue;
    let observed: string[];
    try {
      observed = await addresses(record.type, record.name);
    } catch {
      continue;
    }
    const prior = owned?.record.content ?? record.expectedValue;
    const current = records.find(
      (item) => desiredDns(item) && item.name === record.name && item.type === record.type,
    );
    const absent = !observed.some((value) => dnsRecordVerified(record.type, prior, value));
    if (absent && (record.type !== "AAAA" || current || observed.length === 0)) confirmed.push(record.id);
  }
  if (confirmed.length) {
    await tx
      .update(dnsRecords)
      .set({ status: "withdrawn", withdrawalConfirmedAt: now })
      .where(inArray(dnsRecords.id, confirmed));
  }
  return records.filter((record) => pendingWithdrawal(record) && !confirmed.includes(record.id));
}

export async function changeAaaaSetting(
  domainId: string,
  enabled: boolean,
  authorize: (tx: DbTransaction) => Promise<unknown>,
) {
  await db.transaction(async (tx) => {
    const { domain, settings } = await lockedDnsDomain(tx, domainId);
    if (enabled && !domain.aaaaEnabled) await authorize(tx);
    await tx
      .update(domainClaims)
      .set({ aaaaEnabled: enabled, updatedAt: new Date() })
      .where(eq(domainClaims.id, domainId));
    await reconcileDomainDns(tx, { ...domain, aaaaEnabled: enabled }, settings);
  });
}

export async function revokeAaaaWithdrawal(domainId: string, userId: string) {
  await db.transaction(async (tx) => {
    await lockedDnsDomain(tx, domainId);
    await tx.update(dnsRecords).set({ automaticWithdrawal: false }).where(eq(dnsRecords.domainId, domainId));
    await tx.insert(auditEvents).values({
      id: createId("audit"),
      actorId: userId,
      role: "owner",
      action: "dns.revoke_aaaa_withdrawal",
      resourceType: "domain",
      resourceId: domainId,
    });
  });
}

/** FD-27 supplies the IPv6 status. The domain worker reacts to persisted changes and retries withdrawals. */
export async function domainsDueForDns() {
  const [domains, records, endpointRows, [settings]] = await Promise.all([
    db.select().from(domainClaims),
    db.select().from(dnsRecords),
    db.select().from(endpoints),
    db.select().from(platformSettings).where(eq(platformSettings.id, "default")),
  ]);
  const now = new Date();
  return domains.flatMap((domain) => {
    const stored = records.filter((record) => record.domainId === domain.id);
    const domainEndpoints = endpointRows.filter((row) => row.domainId === domain.id);
    const projected = projectDns(domain, settings, stored, domainEndpoints, now);
    const recent = (at: Date) => now.getTime() - at.getTime() < 30 * 60_000;
    const waiting = domainEndpoints.filter(
      (endpoint) =>
        endpoint.exposure === "public" &&
        endpoint.status === "awaiting_dns" &&
        projected.some(
          (record) =>
            desiredDns(record) &&
            record.name === endpoint.hostname &&
            (domain.dnsProvider === "cloudflare"
              ? record.publishedAt && recent(record.publishedAt)
              : recent(endpoint.createdAt)),
        ),
    );
    const awaitingOwnership =
      domain.dnsProvider !== "cloudflare" && domain.status !== "verified" && recent(domain.createdAt);
    const needsReconcile = projected.some((record) => !stored.includes(record) || pendingWithdrawal(record));
    return needsReconcile || awaitingOwnership || waiting.length
      ? [
          {
            domainId: domain.id,
            routeEndpointsOnly: !awaitingOwnership && waiting.every((endpoint) => endpoint.kind === "route"),
          },
        ]
      : [];
  });
}

export async function ensureEndpointDnsRecords(
  tx: DbTransaction,
  domainId: string,
  hostname: string,
  records: DnsRecordPlan[],
) {
  const existing = await tx.select().from(dnsRecords).where(endpointDnsScope(domainId, hostname));
  for (const record of records) {
    if (existing.some((item) => desiredDns(item) && item.type === record.type)) continue;
    const restore = existing.find(
      (item) =>
        pendingWithdrawal(item) &&
        item.type === record.type &&
        item.expectedValue === record.value &&
        !item.providerRemovedAt,
    );
    if (restore) {
      await tx
        .update(dnsRecords)
        .set({
          status: "pending",
          withdrawalReason: null,
          withdrawalStartedAt: null,
        })
        .where(eq(dnsRecords.id, restore.id));
    } else {
      await tx.insert(dnsRecords).values(dnsRecordValues(domainId, record));
    }
  }
}

export function endpointDnsScope(domainId: string, name: string) {
  return and(eq(dnsRecords.domainId, domainId), eq(dnsRecords.name, name));
}
