import {
  aaaaAllowed,
  canViewDomain,
  createId,
  dnsRecordVerified,
  manualDnsGuides,
  planHash,
  relativeDnsName,
  type CloudflareRecordEvidence,
  type DnsPublishStatus,
  type DnsRecordPlan,
  type DnsReviewRecord,
  type DnsReviewAction,
  type DomainDnsReview,
} from "@ark-stack/shared";
import { and, eq, inArray, isNull, ne } from "drizzle-orm";

import { db, sql, type DbTransaction } from "../db.ts";
import {
  auditEvents,
  certificates,
  dnsRecords,
  domainClaims,
  endpoints,
  frontRoutes,
  operations,
  operationSteps,
  platformAccess,
  platformSettings,
} from "../schema.ts";
import {
  CloudflareDns,
  DnsReviewError,
  drift,
  matchesWrite,
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

export function retireDnsRecord(
  record: StoredDnsRecord,
  reason: NonNullable<StoredDnsRecord["withdrawalReason"]>,
  now: Date,
) {
  return {
    ...record,
    status: "withdrawal_pending",
    withdrawalReason: reason,
    withdrawalStartedAt: record.withdrawalStartedAt ?? now,
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
  const manualAddressHistory: StoredDnsRecord[] = [];
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
      if (domain.dnsProvider !== "cloudflare") {
        manualAddressHistory.push(retireDnsRecord(record, "address_changed", now));
        return {
          ...record,
          id: `dns_${planHash([record.id, settings.publicIpv4]).slice(0, 24)}`,
          expectedValue: settings.publicIpv4,
          publishedAt: null,
          observedValue: null,
          status: "pending",
          withdrawalReason: null,
          withdrawalStartedAt: null,
          withdrawalConfirmedAt: null,
        };
      }
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

  next.push(...manualAddressHistory);
  for (const item of next.filter(
    (record) => pendingWithdrawal(record) && record.withdrawalReason === "address_changed",
  )) {
    if (
      next.some(
        (record) =>
          desiredDns(record) &&
          record.type === "A" &&
          record.name === item.name &&
          record.expectedValue === item.expectedValue,
      )
    ) {
      next[next.indexOf(item)] = { ...item, status: "superseded", withdrawalConfirmedAt: now };
    }
  }

  if (ipv6) {
    const publicNames = new Set(
      endpointRows.filter((endpoint) => endpoint.exposure === "public").map((endpoint) => endpoint.hostname),
    );
    for (const record of next.filter(
      (item) => desiredDns(item) && item.type === "AAAA" && publicNames.has(item.name) && !item.required,
    )) {
      next[next.indexOf(record)] = { ...record, required: true };
    }
    for (const address of next.filter(
      (record) => desiredDns(record) && record.type === "A" && publicNames.has(record.name),
    )) {
      const history = next.filter((record) => record.type === "AAAA" && record.name === address.name);
      if (history.some(desiredDns)) {
        for (const record of history) {
          if (
            pendingWithdrawal(record) &&
            record.withdrawalReason === "ipv6" &&
            !record.providerOwnership &&
            !record.providerUpdateIntent &&
            dnsRecordVerified("AAAA", ipv6, record.expectedValue)
          ) {
            next[next.indexOf(record)] = { ...record, status: "superseded", withdrawalConfirmedAt: now };
          }
        }
        continue;
      }
      const restore = history.find(
        (record) =>
          pendingWithdrawal(record) &&
          record.withdrawalReason === "ipv6" &&
          !record.providerRemovedAt &&
          dnsRecordVerified("AAAA", ipv6, record.expectedValue),
      );
      if (restore) {
        next[next.indexOf(restore)] = {
          ...restore,
          required: true,
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
        providerUpdateIntent: null,
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

// Use a consistent MVCC snapshot without holding row locks during network work.
export function readDnsSnapshot(domainId: string) {
  return db.transaction(
    async (tx) => {
      const [domain] = await tx.select().from(domainClaims).where(eq(domainClaims.id, domainId));
      if (!domain) throw new DnsReviewError(404, "Domain not found.");
      const [settings] = await tx.select().from(platformSettings).where(eq(platformSettings.id, "default"));
      return { domain, settings, ...(await dnsSnapshot(tx, domain, settings)) };
    },
    { isolationLevel: "repeatable read", accessMode: "read only" },
  );
}

type DnsSnapshot = Awaited<ReturnType<typeof readDnsSnapshot>>;

function snapshotKey({ domain, settings, stored, endpointRows }: DnsSnapshot) {
  return planHash(
    JSON.parse(
      JSON.stringify([
        [domain.id, domain.name, domain.dnsProvider, domain.aaaaEnabled, domain.ownershipToken],
        [settings?.publicIpv4, settings?.publicIpv6, settings?.ipv6Status],
        stored
          .map(({ status: _status, observedValue: _observed, ...record }) => record)
          .toSorted((a, b) => a.id.localeCompare(b.id)),
        endpointRows
          .map(({ id, kind, hostname, exposure }) => ({ id, kind, hostname, exposure }))
          .toSorted((a, b) => a.id.localeCompare(b.id)),
      ]),
    ),
  );
}

async function lockSnapshot(tx: DbTransaction, expected: DnsSnapshot) {
  const { domain, settings } = await lockedDnsDomain(tx, expected.domain.id);
  const current = { domain, settings, ...(await dnsSnapshot(tx, domain, settings)) };
  if (snapshotKey(current) !== snapshotKey(expected)) {
    throw new DnsReviewError(409, "The local DNS state changed. Reload the DNS review or recheck DNS.");
  }
  return current;
}

export async function commitDnsSnapshot<T>(
  expected: DnsSnapshot,
  commit: (tx: DbTransaction, snapshot: DnsSnapshot) => Promise<T>,
) {
  return db.transaction(async (tx) => commit(tx, await lockSnapshot(tx, expected)));
}

export async function saveProjection(
  tx: DbTransaction,
  stored: StoredDnsRecord[],
  records: StoredDnsRecord[],
) {
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

async function recoverOwnership(client: CloudflareDns, zoneId: string, record: StoredDnsRecord) {
  const intent = record.providerUpdateIntent;
  const previous = record.providerOwnership;
  if (!intent && previous && previous.zoneId !== zoneId && !record.providerRemovedAt) {
    // Only Cloudflare's record-not-found response in the original zone can release old ownership.
    // Missing zone access is inconclusive and is surfaced as a blocked action in the review.
    const original = await client.record(previous.zoneId, previous.record.id).catch(() => undefined);
    if (original === null) {
      return pendingWithdrawal(record)
        ? { ...record, providerRemovedAt: new Date(), automaticWithdrawal: false }
        : { ...record, providerOwnership: null, publishedAt: null, automaticWithdrawal: false };
    }
  }
  if (!intent || intent.zoneId !== zoneId) return record;
  const candidates = intent.providerId
    ? [await client.record(zoneId, intent.providerId)]
    : await client.records(zoneId, intent.after.name);
  const matches = candidates.filter(
    (item) => item && item.comment === intent.marker && matchesWrite(item, intent.after),
  );
  if (matches.length !== 1 || !matches[0]) return record;
  return {
    ...record,
    providerOwnership: { zoneId, record: matches[0] },
    providerUpdateIntent: null,
    automaticWithdrawal: false,
  };
}

async function cloudflareReview(client: CloudflareDns, domain: Domain, records: StoredDnsRecord[]) {
  const zoneId = await client.zoneId(domain.name);
  const recovered = [];
  for (const record of records) {
    recovered.push(
      desiredDns(record) || pendingWithdrawal(record)
        ? await recoverOwnership(client, zoneId, record)
        : record,
    );
  }
  records = recovered;
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
    zoneId,
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
      pendingWithdrawal(record) &&
      record.providerOwnership &&
      !record.providerRemovedAt &&
      !record.providerUpdateIntent
        ? [{ recordId: record.id, ownership: record.providerOwnership }]
        : [],
    ),
  );
  for (const record of records.filter((item) => item.providerUpdateIntent && pendingWithdrawal(item))) {
    const intent = record.providerUpdateIntent!;
    planned.actions.push({
      recordId: record.id,
      action: "blocked",
      before: record.providerOwnership?.record ?? null,
      after: { ...intent.after, proxied: false },
      reason: "The prior Cloudflare write is unconfirmed. Check the original zone and reload the review.",
    });
  }
  return { ...planned, records, planHash: planHash([domain.id, planned]) };
}

let activeReviews = 0;

async function limitedCloudflareReview(client: CloudflareDns, domain: Domain, records: StoredDnsRecord[]) {
  if (activeReviews >= 4) throw new DnsReviewError(503, "Cloudflare DNS is busy. Reload the review shortly.");
  activeReviews++;
  try {
    return await cloudflareReview(client, domain, records);
  } finally {
    activeReviews--;
  }
}

export async function domainDnsReview(domainId: string, includeCloudflare = true): Promise<DomainDnsReview> {
  const { domain, settings, records } = await readDnsSnapshot(domainId);
  const cloudflare =
    includeCloudflare && domain.dnsProvider === "cloudflare"
      ? await limitedCloudflareReview(new CloudflareDns(), domain, records)
      : null;
  const visible = (cloudflare?.records ?? records).filter(
    (record) => desiredDns(record) || pendingWithdrawal(record),
  );
  const names = [
    ...new Set(visible.filter((record) => ["A", "AAAA"].includes(record.type)).map((record) => record.name)),
  ];
  const activeNames = new Set(visible.filter(desiredDns).map((record) => record.name));
  const providerOnly: DnsReviewRecord[] =
    cloudflare?.snapshots.flatMap(([name, snapshot]) =>
      activeNames.has(name)
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
      domain.proxyAaaaHosts.length ||
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
}

export type DnsPublishRequest = {
  planHash: string;
  authorizeAAAAWithdrawal?: true;
  requestId?: string;
};

export type DnsPublisher = { userId: string; role: "owner" | "operator" };

async function requireDnsPublisher(
  tx: DbTransaction,
  domainId: string,
  actor: DnsPublisher,
  input: DnsPublishRequest,
) {
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
}

type PublishOperation = typeof operations.$inferSelect;
type WriteIntent = StoredDnsRecord["providerUpdateIntent"];
type Publication = {
  zoneId: string;
  actions: DnsReviewAction[];
  rrsets: Array<[string, CloudflareRecordEvidence[]]>;
  snapshot: string;
  index: number;
  pending: { intent: WriteIntent } | null;
  verificationOperationId?: string;
};

export async function queueDnsPublish(domainId: string, input: DnsPublishRequest, actor: DnsPublisher) {
  const key = "dns.reviewed:" + planHash([domainId, actor.userId, input]);
  return db.transaction(async (tx) => {
    const { domain } = await lockedDnsDomain(tx, domainId);
    if (domain.dnsProvider !== "cloudflare") throw new DnsReviewError(422, "This domain uses manual DNS.");
    await requireDnsPublisher(tx, domainId, actor, input);
    const [created] = await tx
      .insert(operations)
      .values({
        id: createId("op"),
        kind: "dns.publish",
        actorId: actor.userId,
        targetIds: [domainId],
        idempotencyKey: key,
        planHash: input.planHash,
        payload: { reviewed: input, role: actor.role },
      })
      .onConflictDoNothing({ target: operations.idempotencyKey })
      .returning({ id: operations.id });
    const [operation] = created
      ? [created]
      : await tx.select({ id: operations.id }).from(operations).where(eq(operations.idempotencyKey, key));
    return { operationId: operation!.id };
  });
}

export async function dnsPublishStatus(domainId: string, operationId: string): Promise<DnsPublishStatus> {
  const [operation] = await db
    .select()
    .from(operations)
    .where(and(eq(operations.id, operationId), eq(operations.kind, "dns.publish")));
  if (!operation || operation.targetIds[0] !== domainId)
    throw new DnsReviewError(404, "DNS publish operation not found.");
  const publication = operation.payload.publication as Publication | undefined;
  const verificationOperationId = publication?.verificationOperationId ?? null;
  // The final transaction saves the verification handoff before the worker acknowledges completion.
  return {
    operationId,
    status: verificationOperationId ? "succeeded" : operation.status,
    error: verificationOperationId ? null : operation.error,
    errorStatus: verificationOperationId
      ? null
      : ((operation.payload.errorStatus as number | undefined) ?? null),
    applied: publication?.index ?? 0,
    total: publication?.actions.length ?? null,
    verificationOperationId,
  };
}

function activeClaim(operation: PublishOperation) {
  return and(
    eq(operations.id, operation.id),
    eq(operations.status, "running"),
    operation.claimToken ? eq(operations.claimToken, operation.claimToken) : isNull(operations.claimToken),
  );
}

async function saveDnsAction(
  tx: DbTransaction,
  zoneId: string,
  record: StoredDnsRecord,
  action: DnsReviewAction,
  written: CloudflareRecordEvidence | null,
  authorize?: true,
) {
  if (action.action === "blocked") {
    if (desiredDns(record) && record.publishedAt)
      await tx.update(dnsRecords).set({ publishedAt: null }).where(eq(dnsRecords.id, record.id));
    return;
  }
  if (action.action === "delete") {
    await tx
      .update(dnsRecords)
      .set({ providerRemovedAt: new Date(), automaticWithdrawal: false, providerUpdateIntent: null })
      .where(eq(dnsRecords.id, record.id));
    return;
  }

  const previous = record.providerOwnership;
  const previouslyOwned = Boolean(
    previous && action.before && previous.zoneId === zoneId && sameRecord(previous.record, action.before),
  );
  const owned =
    previouslyOwned ||
    action.action === "create" ||
    (!previous && action.action === "keep" && written!.comment === ownershipMarker(record.id));
  await tx
    .update(dnsRecords)
    .set({
      publishedAt: new Date(),
      providerOwnership: owned ? { zoneId, record: written! } : previous,
      providerUpdateIntent: owned ? null : record.providerUpdateIntent,
      automaticWithdrawal:
        owned &&
        record.type === "AAAA" &&
        (authorize === true || (previouslyOwned && record.automaticWithdrawal && action.action === "keep")),
    })
    .where(eq(dnsRecords.id, record.id));
}

const publishingDomains = new Set<string>();

// Provider writers are serialized across workers, while observations and local row locks can proceed.
// This is a session lock on a reserved connection, with no database transaction open during I/O.
async function withDnsWriter<T>(domainId: string, work: () => Promise<T>) {
  if (publishingDomains.size >= 3 || publishingDomains.has(domainId))
    throw new DnsReviewError(409, "A DNS change is already in progress. Retry shortly.");
  publishingDomains.add(domainId);
  try {
    const connection = await sql.reserve();
    const key = "ark:dns:provider:" + domainId;
    try {
      const [row] = await connection`SELECT pg_advisory_lock(hashtextextended(${key}, 0))`;
      if (!row) throw new Error("Could not lock the DNS provider.");
      try {
        return await work();
      } finally {
        await connection`SELECT pg_advisory_unlock(hashtextextended(${key}, 0))`;
      }
    } finally {
      connection.release();
    }
  } finally {
    publishingDomains.delete(domainId);
  }
}

export async function publishReviewedDns(
  operation: PublishOperation,
  input: DnsPublishRequest,
  actor: DnsPublisher,
) {
  const domainId = operation.targetIds[0];
  try {
    await withDnsWriter(domainId, () => publishDnsPlan(operation, input, actor));
  } catch (error) {
    if (error instanceof DnsReviewError) {
      const [current] = await db
        .select({ payload: operations.payload })
        .from(operations)
        .where(activeClaim(operation));
      if (current)
        await db
          .update(operations)
          .set({ payload: { ...current.payload, errorStatus: error.status } })
          .where(activeClaim(operation));
    }
    throw error;
  }
}

function changedRrset(
  rrset: CloudflareRecordEvidence[],
  action: DnsReviewAction,
  result: CloudflareRecordEvidence | null,
) {
  const updated = rrset.filter((item) => item.id !== action.before?.id);
  if (result) updated.push(result);
  return updated.toSorted((a, b) => a.id.localeCompare(b.id));
}

async function applyReviewedProviderAction(
  client: CloudflareDns,
  zoneId: string,
  action: DnsReviewAction,
  rrset: CloudflareRecordEvidence[],
  intent: WriteIntent,
  retrying: boolean,
  beforeMutation: () => void,
) {
  if (action.action === "blocked") return null;
  const { name, type } = action.deletionScope?.record ?? action.after!;
  if (retrying) {
    const current = await client.records(zoneId, name);
    if (
      action.action === "delete" &&
      action.before &&
      planHash(current) === planHash(changedRrset(rrset, action, null))
    ) {
      await client.checkDeletion(action.deletionScope!, null);
      return null;
    }
    if (action.action === "create" || action.action === "update") {
      const matching = current.filter(
        (item) =>
          (action.action === "create" || item.id === action.before!.id) &&
          item.comment === (intent?.marker ?? action.before?.comment) &&
          matchesWrite(item, action.after!),
      );
      if (matching.length === 1 && planHash(current) === planHash(changedRrset(rrset, action, matching[0]))) {
        return matching[0];
      }
    }
  }
  await client.checkRrset(zoneId, name, rrset, type);
  if (action.action === "keep") return action.before;
  if (action.action === "delete") {
    await client.checkDeletion(action.deletionScope!, action.before);
    beforeMutation();
    await client.delete(action.deletionScope!, action.before);
    return null;
  }
  if (action.action === "update")
    await client.checkRecord(zoneId, action.before, action.before!.id, type, name);
  beforeMutation();
  return client.write(zoneId, action, intent?.marker);
}

async function publishDnsPlan(operation: PublishOperation, input: DnsPublishRequest, actor: DnsPublisher) {
  const domainId = operation.targetIds[0];
  let snapshot = await readDnsSnapshot(domainId);
  if (snapshot.domain.dnsProvider !== "cloudflare")
    throw new DnsReviewError(422, "This domain uses manual DNS.");
  const client = new CloudflareDns();
  let publication = operation.payload.publication as Publication | undefined;
  const audit = (tx: DbTransaction, action: string, detail: Record<string, unknown>) =>
    tx.insert(auditEvents).values({
      id: createId("audit"),
      actorId: actor.userId,
      role: actor.role,
      action,
      resourceType: "domain",
      resourceId: domainId,
      operationId: operation.id,
      detail: { planHash: input.planHash, ...detail },
    });

  // Lock the local state and confirm the worker claim before reading provider evidence. The
  // network phase follows this commit so lock waits cannot make the provider evidence stale.
  async function commit(step: (tx: DbTransaction, live: DnsSnapshot) => Promise<Publication>) {
    const [committed, refreshed] = await commitDnsSnapshot(snapshot, async (tx, current) => {
      await requireDnsPublisher(tx, domainId, actor, input);
      const [claim] = await tx
        .select({ id: operations.id })
        .from(operations)
        .where(activeClaim(operation))
        .for("update");
      if (!claim) throw new DnsReviewError(409, "The DNS publish worker claim changed.");
      const next = await step(tx, current);
      const live = { ...current, ...(await dnsSnapshot(tx, current.domain, current.settings)) };
      next.snapshot = snapshotKey(live);
      await tx
        .update(operations)
        .set({ payload: { ...operation.payload, publication: next } })
        .where(eq(operations.id, operation.id));
      return [next, live] as const;
    });
    snapshot = refreshed;
    return committed;
  }

  if (publication) {
    if (publication.verificationOperationId) return;
    if (
      publication.snapshot !== snapshotKey(snapshot) ||
      publication.zoneId !== (await client.zoneId(snapshot.domain.name))
    ) {
      throw new DnsReviewError(409, "The DNS state changed while publishing. Review the latest diff.");
    }
  } else {
    await db.transaction((tx) => requireDnsPublisher(tx, domainId, actor, input));
    const reviewed = await limitedCloudflareReview(client, snapshot.domain, snapshot.records);
    if (input.planHash !== reviewed.planHash)
      throw new DnsReviewError(
        409,
        "The Cloudflare DNS plan changed. Review the latest diff before publishing.",
      );
    publication = await commit(async (tx, live) => {
      // Merge recovered evidence into the locked projection without replacing live observations.
      const prior = new Map(snapshot.records.map((record) => [record.id, record]));
      const recovered = new Map(
        reviewed.records
          .filter((record) => prior.get(record.id) !== record)
          .map((record) => [record.id, record]),
      );
      const records = live.records.map((record) => {
        const evidence = recovered.get(record.id);
        if (!evidence) return record;
        const {
          providerOwnership,
          providerUpdateIntent,
          automaticWithdrawal,
          providerRemovedAt,
          publishedAt,
        } = evidence;
        return {
          ...record,
          providerOwnership,
          providerUpdateIntent,
          automaticWithdrawal,
          providerRemovedAt,
          publishedAt,
        };
      });
      await saveProjection(tx, live.stored, records);
      await audit(tx, "dns.publish", {
        actions: reviewed.actions,
        authorizeAAAAWithdrawal: input.authorizeAAAAWithdrawal === true,
      });
      return {
        zoneId: reviewed.zoneId,
        actions: [
          ...reviewed.actions.filter((action) => action.action !== "keep"),
          ...reviewed.actions.filter((action) => action.action === "keep"),
        ],
        rrsets: reviewed.snapshots,
        snapshot: "",
        index: 0,
        pending: null,
      };
    });
  }

  while (publication.index < publication.actions.length) {
    const state: Publication = publication;
    const action = state.actions[state.index];
    const writesProvider =
      action.action === "create" || action.action === "update" || action.action === "delete";
    const retrying = state.pending !== null;
    const previousIntent = snapshot.stored.find((item) => item.id === action.recordId)!.providerUpdateIntent;
    publication = await commit(async (tx, live) => {
      if (retrying || !writesProvider) return state;
      const record = live.stored.find((item) => item.id === action.recordId)!;
      const ownedUpdate =
        action.action === "update" &&
        action.before &&
        record.providerOwnership?.zoneId === state.zoneId &&
        sameRecord(record.providerOwnership.record, action.before);
      const intent =
        action.action === "create" || ownedUpdate
          ? {
              zoneId: state.zoneId,
              providerId: action.before?.id ?? null,
              marker: ownershipMarker(createId("write")),
              after: action.after!,
            }
          : null;
      if (intent)
        await tx.update(dnsRecords).set({ providerUpdateIntent: intent }).where(eq(dnsRecords.id, record.id));
      return { ...state, pending: { intent } };
    });
    const prepared: Publication = publication;
    const name = (action.deletionScope?.record ?? action.after ?? action.before)?.name;
    const rrsets = new Map(prepared.rrsets);
    const rrset = (name && rrsets.get(name)) || [];
    const record = snapshot.stored.find((item) => item.id === action.recordId)!;
    let attemptedMutation = false;
    let written;
    try {
      if (action.action === "create" && record.providerOwnership)
        await client.checkRecord(
          prepared.zoneId,
          null,
          record.providerOwnership.record.id,
          action.after!.type,
          action.after!.name,
        );
      written = await applyReviewedProviderAction(
        client,
        prepared.zoneId,
        action,
        rrset,
        prepared.pending?.intent ?? null,
        retrying,
        () => {
          attemptedMutation = true;
        },
      );
    } catch (error) {
      if (!retrying && !attemptedMutation && prepared.pending?.intent) {
        await commit(async (tx) => {
          await tx
            .update(dnsRecords)
            .set({ providerUpdateIntent: previousIntent })
            .where(eq(dnsRecords.id, record.id));
          return { ...prepared, pending: null };
        }).catch(() => {
          /* Keep the intent if the snapshot or claim no longer matches. */
        });
      }
      throw error;
    }
    if (name && writesProvider) rrsets.set(name, changedRrset(rrset, action, written));
    publication = await commit(async (tx, live) => {
      await saveDnsAction(
        tx,
        prepared.zoneId,
        live.stored.find((item) => item.id === action.recordId)!,
        action,
        written,
        input.authorizeAAAAWithdrawal,
      );
      await tx.insert(operationSteps).values({
        id: createId("step"),
        operationId: operation.id,
        name: "dns-publish-action",
        status: "succeeded",
        evidence: { planHash: input.planHash, action, written },
      });
      return { ...prepared, index: prepared.index + 1, pending: null, rrsets: [...rrsets] };
    });
  }

  const completed = publication;
  await commit(async (tx) => {
    const verificationOperationId = createId("op");
    await tx.insert(operations).values({
      id: verificationOperationId,
      kind: "domain.verify",
      actorId: actor.userId,
      targetIds: [domainId],
      idempotencyKey: "dns.publish.verify:" + operation.id,
      planHash: planHash({}),
    });
    return { ...completed, verificationOperationId };
  });
}

export async function withdrawAuthorizedAaaa(domainId: string) {
  const initial = await readDnsSnapshot(domainId);
  const candidates = (snapshot: DnsSnapshot) =>
    snapshot.records.filter(
      (record) =>
        pendingWithdrawal(record) &&
        record.type === "AAAA" &&
        record.withdrawalReason === "ipv6" &&
        snapshot.endpointRows.some(
          (endpoint) => endpoint.exposure === "public" && endpoint.hostname === record.name,
        ) &&
        !record.providerRemovedAt &&
        !record.providerUpdateIntent &&
        record.automaticWithdrawal &&
        record.providerOwnership,
    );
  if (
    initial.domain.dnsProvider !== "cloudflare" ||
    !candidates(initial).length ||
    publishingDomains.has(domainId)
  )
    return [];
  const failures: string[] = [];
  try {
    await withDnsWriter(domainId, async () => {
      let snapshot = await readDnsSnapshot(domainId);
      if (snapshot.domain.dnsProvider !== "cloudflare") return;
      const client = new CloudflareDns();
      const zoneId = await client.zoneId(snapshot.domain.name);
      for (const candidate of candidates(snapshot)) {
        const ownership = candidate.providerOwnership!;
        try {
          if (zoneId !== ownership.zoneId) throw drift(candidate.type, candidate.name);
          snapshot = await commitDnsSnapshot(snapshot, async (tx, live) => {
            await saveProjection(tx, live.stored, live.records);
            return { ...live, ...(await dnsSnapshot(tx, live.domain, live.settings)) };
          });
          const current = await client.record(zoneId, ownership.record.id);
          if (current && !sameRecord(current, ownership.record)) throw drift(candidate.type, candidate.name);
          const action: DnsReviewAction = {
            recordId: candidate.id,
            action: "delete",
            before: current,
            after: null,
            deletionScope: ownership,
          };
          await client.delete(ownership, current);
          snapshot = await commitDnsSnapshot(snapshot, async (tx, live) => {
            await saveDnsAction(tx, zoneId, candidate, action, null);
            await tx.insert(auditEvents).values({
              id: createId("audit"),
              role: "system",
              action: "dns.withdraw_aaaa",
              resourceType: "domain",
              resourceId: domainId,
              detail: { planHash: planHash([domainId, action]), action, authorization: "preauthorized" },
            });
            return { ...live, ...(await dnsSnapshot(tx, live.domain, live.settings)) };
          });
        } catch (error) {
          if (!(error instanceof DnsReviewError)) throw error;
          failures.push(error.message);
        }
      }
    });
  } catch (error) {
    if (!(error instanceof DnsReviewError)) throw error;
    failures.push(error.message);
  }
  return failures;
}

export async function observedWithdrawals(
  records: StoredDnsRecord[],
  addresses: (type: string, name: string) => Promise<string[]>,
  now = new Date(),
) {
  const confirmed: string[] = [];
  for (const record of records.filter(pendingWithdrawal)) {
    if (record.providerUpdateIntent) continue;
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
    const absent = !observed.some((value) => dnsRecordVerified(record.type, prior, value));
    if (absent) confirmed.push(record.id);
  }
  return confirmed;
}

export async function confirmWithdrawals(tx: DbTransaction, confirmed: string[], now: Date) {
  if (!confirmed.length) return;
  await tx
    .update(dnsRecords)
    .set({ status: "withdrawn", withdrawalConfirmedAt: now })
    .where(inArray(dnsRecords.id, confirmed));
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

/** Open or renew a bounded verification window from an explicit operator action. */
export async function watchManualDns(domainId: string) {
  await db
    .update(domainClaims)
    .set({ dnsWatchUntil: new Date(Date.now() + 30 * 60_000) })
    .where(and(eq(domainClaims.id, domainId), ne(domainClaims.dnsProvider, "cloudflare")));
}

/** FD-27 supplies the IPv6 status. The domain worker reacts to persisted changes and retries withdrawals. */
export async function domainsDueForDns() {
  const [domains, records, endpointRows, [settings], waitingRoutes, orders, issued] = await Promise.all([
    db.select().from(domainClaims),
    db.select().from(dnsRecords),
    db.select().from(endpoints),
    db.select().from(platformSettings).where(eq(platformSettings.id, "default")),
    db
      .select({ endpointId: frontRoutes.endpointId })
      .from(frontRoutes)
      .where(eq(frontRoutes.status, "awaiting_dns")),
    db
      .select({ targetIds: operations.targetIds })
      .from(operations)
      .where(eq(operations.kind, "certificate.issue")),
    db.select({ endpointId: certificates.endpointId }).from(certificates),
  ]);
  const now = new Date();
  const waitingRouteIds = new Set(waitingRoutes.map(({ endpointId }) => endpointId));
  const issuedOrOrdered = new Set([
    ...orders.flatMap(({ targetIds }) => targetIds),
    ...issued.map(({ endpointId }) => endpointId),
  ]);
  return domains.flatMap((domain) => {
    if (publishingDomains.has(domain.id)) return [];
    const stored = records.filter((record) => record.domainId === domain.id);
    const domainEndpoints = endpointRows.filter((row) => row.domainId === domain.id);
    const projected = projectDns(domain, settings, stored, domainEndpoints, now);
    const recent = (at: Date) => now.getTime() - at.getTime() < 30 * 60_000;
    const watching = (domain.dnsWatchUntil?.getTime() ?? 0) > now.getTime();
    const waiting = domainEndpoints.filter(
      (endpoint) =>
        endpoint.exposure === "public" &&
        (endpoint.status === "awaiting_dns" ||
          (endpoint.status === "verified" &&
            (endpoint.kind === "route"
              ? waitingRouteIds.has(endpoint.id)
              : !issuedOrOrdered.has(endpoint.id)))) &&
        projected.some(
          (record) =>
            desiredDns(record) &&
            record.name === endpoint.hostname &&
            (domain.dnsProvider === "cloudflare"
              ? record.publishedAt && recent(record.publishedAt)
              : watching || recent(endpoint.createdAt)),
        ),
    );
    const awaitingOwnership =
      domain.dnsProvider !== "cloudflare" &&
      domain.status !== "verified" &&
      (watching || recent(domain.createdAt));
    const needsReconcile = projected.some(
      (record) =>
        !stored.includes(record) ||
        (pendingWithdrawal(record) &&
          ((domain.dnsProvider === "cloudflare" &&
            (record.providerOwnership !== null || record.providerUpdateIntent !== null)) ||
            watching ||
            (record.withdrawalStartedAt !== null && recent(record.withdrawalStartedAt)))),
    );
    const checksProxy =
      domain.proxyAaaaHosts.length && (domain.dnsProvider === "cloudflare" || watching || waiting.length > 0);
    return needsReconcile || awaitingOwnership || waiting.length || checksProxy
      ? [
          {
            domainId: domain.id,
            routeEndpointsOnly:
              !awaitingOwnership &&
              domainEndpoints.every(
                (endpoint) =>
                  endpoint.kind === "route" ||
                  (!waiting.includes(endpoint) && !domain.proxyAaaaHosts.includes(endpoint.hostname)),
              ),
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
