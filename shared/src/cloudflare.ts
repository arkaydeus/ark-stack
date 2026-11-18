export type DnsWrite = {
  type: string;
  name: string;
  content: string;
  ttl: number;
  priority?: number;
};
import { expectedDnsValue } from "./dns-plan.ts";
export function cloudflareRecordBody(record: DnsWrite) {
  const body: Record<string, unknown> = {
    type: record.type,
    name: record.name,
    content: record.content,
    ttl: record.ttl,
    proxied: false,
  };
  if (record.priority !== undefined) body.priority = record.priority;
  return body;
}

/**
 * Which TXT record a value is. Unrelated TXT records legitimately share one name (SPF next to
 * DMARC next to a provider verification string), so a TXT may only be overwritten by one of
 * the same kind — anything else has to be added alongside it.
 */
function txtKind(value: string) {
  if (/^v=spf1\b/i.test(value)) return "spf";
  if (/^v=DMARC1\b/i.test(value)) return "dmarc";
  if (/^v=DKIM1\b/i.test(value)) return "dkim";
  if (value.startsWith("ark-own-")) return "ark-ownership";
  return null;
}

function normalizeContent(value: string) {
  return value.replace(/^"|"$/g, "").replace(/\.$/, "");
}

export function chooseCloudflareMutation(
  existing: Array<{ id: string; content: string; priority?: number }>,
  record: DnsWrite,
) {
  const type = record.type.toUpperCase();
  const normalize = (value: string) =>
    type === "AAAA" ? expectedDnsValue(type, value) : normalizeContent(value);
  const content = normalize(record.content);
  const exact = existing.find(
    (item) => normalize(item.content) === content && item.priority === record.priority,
  );
  if (exact) return { action: "keep" as const, id: exact.id };
  if (existing.length > 1) {
    throw new Error(
      `Refusing to update ${record.type} ${record.name}: ${existing.length} records already exist. Resolve them manually.`,
    );
  }
  if (existing[0]) {
    const current = normalize(existing[0].content);
    if (type === "TXT") {
      const kind = txtKind(content);
      // Same kind: replace it. Different kind: add ours beside the existing record rather
      // than destroying, for example, a site-verification string.
      return kind !== null && txtKind(current) === kind
        ? { action: "update" as const, id: existing[0].id }
        : { action: "create" as const };
    }
    if (type === "MX") {
      // The apex MX belongs to whoever runs the zone's mail today; taking it over silently
      // would black-hole their inbound mail.
      throw new Error(
        `Refusing to replace the existing MX record at ${record.name} (${current}). Resolve it manually.`,
      );
    }
    // Address records point at Ark-managed hostnames, so updating them is how a host IP change
    // is rolled out.
    return { action: "update" as const, id: existing[0].id };
  }
  return { action: "create" as const };
}
