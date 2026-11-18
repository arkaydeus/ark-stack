import {
  chooseCloudflareMutation,
  cloudflareRecordBody,
  expectedDnsValue,
  planHash,
  type CloudflareOwnership,
  type CloudflareRecordEvidence,
  type DnsReviewAction,
  type DnsWrite,
} from "@ark-stack/shared";

export class DnsReviewError extends Error {
  constructor(
    readonly status: 403 | 404 | 409 | 422 | 502 | 503,
    message: string,
  ) {
    super(message);
  }
}

type Envelope<T> = {
  success?: boolean;
  result?: T;
  result_info?: { total_pages?: number };
  errors?: Array<{ code: number }>;
};

type RecordResult = Omit<CloudflareRecordEvidence, "proxied" | "modifiedOn"> & {
  proxied?: boolean;
  modified_on?: string;
};

const addressTypes = new Set(["A", "AAAA", "CNAME"]);
const cfBase = "https://api.cloudflare.com/client/v4";
const exactName = (name: string) => name.toLowerCase().replace(/\.$/, "");
export const ownershipMarker = (id: string) => `Ark DNS ${id}`;

function evidence(item: RecordResult): CloudflareRecordEvidence {
  if (
    !item?.id ||
    !item.type ||
    !item.name ||
    typeof item.content !== "string" ||
    !item.ttl ||
    (addressTypes.has(item.type) && typeof item.proxied !== "boolean")
  ) {
    throw new DnsReviewError(502, "Cloudflare returned incomplete DNS record evidence.");
  }
  return {
    id: item.id,
    type: item.type,
    name: exactName(item.name),
    content: item.content,
    ttl: item.ttl,
    proxied: item.proxied === true,
    ...(item.priority !== undefined ? { priority: item.priority } : {}),
    ...(item.comment != null ? { comment: item.comment } : {}),
    ...(item.modified_on ? { modifiedOn: item.modified_on } : {}),
  };
}

export function sameRecord(first: CloudflareRecordEvidence, second: CloudflareRecordEvidence) {
  return planHash(first) === planHash(second);
}

function recordPath(zoneId: string, id?: string) {
  const path = `/zones/${encodeURIComponent(zoneId)}/dns_records`;
  return id ? `${path}/${encodeURIComponent(id)}` : path;
}

export class CloudflareDns {
  readonly #token = process.env.DNS_API_TOKEN || process.env.CLOUDFLARE_API_TOKEN;

  async #request<T>(path: string, method = "GET", body?: object, allowMissing = false) {
    if (!this.#token) {
      throw new DnsReviewError(
        422,
        "Configure a Cloudflare DNS token with Zone Read and DNS Edit for this zone.",
      );
    }
    let response: Response;
    let envelope: Envelope<T>;
    try {
      response = await fetch(cfBase + path, {
        method,
        headers: { authorization: `Bearer ${this.#token}`, "content-type": "application/json" },
        ...(method !== "GET" && body ? { body: JSON.stringify(body) } : {}),
        signal: AbortSignal.timeout(8_000),
      });
      envelope = (await response.json()) as Envelope<T>;
    } catch {
      throw new DnsReviewError(
        502,
        `Cloudflare DNS ${method} failed. Check the provider connection and retry.`,
      );
    }
    // A missing record has its own error code. Other 404s can mean the zone or token changed.
    if (
      allowMissing &&
      (response.status === 404 || response.status === 400) &&
      envelope.errors?.some((error) => error.code === 81044)
    ) {
      return null;
    }
    if (!response.ok || envelope.success === false || envelope.result == null) {
      throw new DnsReviewError(
        502,
        `Cloudflare DNS ${method} failed (HTTP ${response.status}). Check zone access and DNS conflicts.`,
      );
    }
    return { result: envelope.result, pages: envelope.result_info?.total_pages ?? 1 };
  }

  async zoneId(zone: string) {
    const query = new URLSearchParams({ name: zone, status: "active", per_page: "5" });
    const reply = (await this.#request<Array<{ id: string; name?: string }>>(`/zones?${query}`))!;
    const zones = reply.result.filter((item) => !item.name || exactName(item.name) === zone);
    if (zones.length !== 1 || reply.pages !== 1 || !zones[0].id) {
      throw new DnsReviewError(
        409,
        `No unique active Cloudflare zone for ${zone}. Check the zone and token scope.`,
      );
    }
    return zones[0].id;
  }

  async records(zoneId: string, name: string) {
    const query = new URLSearchParams({ "name.exact": name, per_page: "100" });
    const records: CloudflareRecordEvidence[] = [];
    let pages = 1;
    for (let page = 1; page <= pages; page++) {
      query.set("page", String(page));
      const reply = (await this.#request<RecordResult[]>(`${recordPath(zoneId)}?${query}`))!;
      records.push(...reply.result.filter((item) => exactName(item.name) === name).map(evidence));
      pages = reply.pages;
    }
    return records.toSorted((a, b) => a.id.localeCompare(b.id));
  }

  async record(zoneId: string, id: string) {
    const reply = await this.#request<RecordResult>(recordPath(zoneId, id), "GET", undefined, true);
    return reply ? evidence(reply.result) : null;
  }

  async write(zoneId: string, action: DnsReviewAction) {
    const after = action.after!;
    const creating = action.action === "create";
    if (!creating) {
      const current = await this.record(zoneId, action.before!.id);
      if (!current || !sameRecord(current, action.before!)) throw drift(after.type, after.name);
    }
    const body = cloudflareRecordBody(after);
    if (creating) body.comment = ownershipMarker(action.recordId);
    const reply = (await this.#request<RecordResult>(
      recordPath(zoneId, creating ? undefined : action.before!.id),
      creating ? "POST" : "PATCH",
      body,
    ))!;
    const written = evidence(reply.result);
    if (
      (!creating && written.id !== action.before!.id) ||
      written.proxied ||
      written.type !== after.type ||
      written.name !== after.name ||
      written.ttl !== after.ttl ||
      expectedDnsValue(written.type, written.content, written.priority) !==
        expectedDnsValue(after.type, after.content, after.priority)
    ) {
      throw new DnsReviewError(
        502,
        `Cloudflare did not confirm the DNS-only ${after.type} record at ${after.name}.`,
      );
    }
    return written;
  }

  async delete(scope: CloudflareOwnership, reviewed: CloudflareRecordEvidence | null) {
    const { zoneId, record } = scope;
    const current = await this.record(zoneId, record.id);
    if (!current && !reviewed) return;
    if (!current || !reviewed || !sameRecord(current, record) || !sameRecord(current, reviewed)) {
      throw drift(record.type, record.name);
    }
    const reply = await this.#request<{ id: string }>(
      recordPath(zoneId, record.id),
      "DELETE",
      undefined,
      true,
    );
    if (!reply) throw drift(record.type, record.name);
    if (reply.result.id !== record.id) {
      throw new DnsReviewError(502, "Cloudflare did not confirm deletion of the reviewed record ID.");
    }
  }
}

export function drift(type: string, name: string) {
  return new DnsReviewError(
    409,
    `Cloudflare ${type} ${name} changed. Review the current records before publishing or remove the conflicting record in Cloudflare.`,
  );
}

export type DesiredCloudflareRecord = DnsWrite & {
  recordId: string;
  ownership: CloudflareOwnership | null;
};

export async function planCloudflare(
  client: CloudflareDns,
  zone: string,
  desired: DesiredCloudflareRecord[],
  withdrawals: Array<{ recordId: string; ownership: CloudflareOwnership }>,
) {
  const zoneId = await client.zoneId(zone);
  const actions: DnsReviewAction[] = [];
  const deleting = new Set<string>();
  for (const { recordId, ownership } of withdrawals) {
    const { record } = ownership;
    if (ownership.zoneId !== zoneId || deleting.has(record.id)) throw drift(record.type, record.name);
    const current = await client.record(zoneId, record.id);
    if (current && !sameRecord(current, record)) throw drift(record.type, record.name);
    actions.push({ recordId, action: "delete", before: current, after: null, deletionScope: ownership });
    deleting.add(record.id);
  }
  const byName = new Map<string, CloudflareRecordEvidence[]>();
  const names = [...new Set(desired.map((record) => record.name))];
  for (let index = 0; index < names.length; index += 8) {
    const batch = names.slice(index, index + 8);
    const snapshots = await Promise.all(batch.map((name) => client.records(zoneId, name)));
    batch.forEach((name, offset) => byName.set(name, snapshots[offset]));
  }
  for (const { recordId, ownership, ...record } of desired) {
    const snapshot = byName.get(record.name)!;
    const surviving = snapshot.filter((item) => !deleting.has(item.id));
    const existing = surviving.filter((item) => item.type === record.type);
    if (
      addressTypes.has(record.type) &&
      (existing.length > 1 || surviving.some((item) => item.type === "CNAME" && record.type !== "CNAME"))
    ) {
      throw new DnsReviewError(
        409,
        `Resolve conflicting Cloudflare records for ${record.name} before publishing.`,
      );
    }
    let mutation: ReturnType<typeof chooseCloudflareMutation>;
    try {
      mutation = chooseCloudflareMutation(existing, record);
    } catch (error) {
      throw new DnsReviewError(409, (error as Error).message);
    }
    const before = mutation.action === "create" ? null : existing.find((item) => item.id === mutation.id)!;
    const action =
      mutation.action === "keep" && before && (before.proxied || before.ttl !== record.ttl)
        ? "update"
        : mutation.action;
    const known =
      before &&
      ((ownership?.zoneId === zoneId && sameRecord(ownership.record, before)) ||
        (!ownership && action === "keep" && before.comment === ownershipMarker(recordId)));
    actions.push({
      recordId,
      action,
      before,
      after: { ...record, proxied: false },
      canAuthorizeWithdrawal: record.type === "AAAA" && (action === "create" || Boolean(known)),
    });
  }
  // Bind the complete matching RRsets, including records that a mutation leaves in place.
  return { zoneId, actions, snapshots: [...byName] };
}
