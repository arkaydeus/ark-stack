export type DnsWrite = {
  type: string;
  name: string;
  content: string;
  ttl: number;
  priority?: number;
};

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

export function chooseCloudflareMutation(
  existing: Array<{ id: string; content: string; priority?: number }>,
  record: DnsWrite,
) {
  const exact = existing.find(
    (item) =>
      item.content.replace(/\.$/, "") === record.content.replace(/\.$/, "") &&
      item.priority === record.priority,
  );
  if (exact) return { action: "keep" as const, id: exact.id };
  if (existing.length > 1) {
    throw new Error(
      `Refusing to update ${record.type} ${record.name}: ${existing.length} records already exist. Resolve them manually.`,
    );
  }
  if (existing[0]) return { action: "update" as const, id: existing[0].id };
  return { action: "create" as const };
}
