import { ValidationError } from "./errors.ts";

const WRITE =
  /\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|copy|call|do|comment|security|listen|notify|vacuum|reindex|cluster|refresh|lock)\b/i;
const MULTI = /;\s*\S/;

export function classifySql(sql: string, readOnly: boolean) {
  const trimmed = sql.trim();
  if (!trimmed) throw new ValidationError("SQL cannot be empty.");
  if (trimmed.length > 20_000) throw new ValidationError("SQL exceeds the 20 KiB statement limit.");
  if (MULTI.test(trimmed)) throw new ValidationError("Multiple SQL statements are not allowed.");
  const writes = WRITE.test(trimmed);
  if (readOnly && writes)
    throw new ValidationError("This workspace is read-only. Write SQL requires an explicit grant.");
  return { writes, fingerprint: trimmed.replace(/\s+/g, " ").slice(0, 200) };
}

export function assertAliasGraph(items: { address: string; targets: string[] }[]) {
  const graph = new Map(
    items.map((item) => [item.address.toLowerCase(), item.targets.map((v) => v.toLowerCase())]),
  );
  const visited = new Set<string>();
  const active = new Set<string>();
  for (const start of graph.keys()) {
    if (visited.has(start)) continue;
    const stack: { address: string; exiting: boolean }[] = [{ address: start, exiting: false }];
    while (stack.length) {
      const current = stack.pop()!;
      if (current.exiting) {
        active.delete(current.address);
        visited.add(current.address);
        continue;
      }
      if (active.has(current.address)) throw new ValidationError("Aliases must not form a forwarding loop.");
      if (visited.has(current.address)) continue;
      active.add(current.address);
      stack.push({ address: current.address, exiting: true });
      for (const target of (graph.get(current.address) ?? []).toReversed()) {
        stack.push({ address: target, exiting: false });
      }
    }
  }
}
