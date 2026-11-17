// Complete tailnet snapshot generations per observation source (docs/design/front-door.md §3.1, §3.2).
//
// `edge` (FD-06, edge-ts) and `backup` (FD-30, backup-ts) are independent: each observer commits only
// its own source, absent peers disappear in the same transaction, and a generation is never mixed
// with, or borrowed from, the other source.
import type { TailnetNode, TailnetSnapshot, TailnetSource } from "@ark-stack/shared";
import { eq } from "drizzle-orm";

import { db, sql } from "../db.ts";
import { tailnetNodes, tailnetSnapshots } from "../schema.ts";

function toNode(row: typeof tailnetNodes.$inferSelect): TailnetNode {
  return {
    source: row.source,
    generation: row.generation,
    stableId: row.stableId,
    dnsName: row.dnsName,
    hostName: row.hostName,
    ipv4: row.ipv4,
    ipv6: row.ipv6,
    tags: row.tags,
    isSelf: row.isSelf,
    online: row.online,
  };
}

/** The persisted snapshot of one source and its nodes. */
export async function loadTailnetSnapshot(source: TailnetSource) {
  const [row] = await db.select().from(tailnetSnapshots).where(eq(tailnetSnapshots.source, source));
  const nodes = (await db.select().from(tailnetNodes).where(eq(tailnetNodes.source, source))).map(toNode);
  const self = nodes.find((node) => node.isSelf) ?? null;
  const snapshot: TailnetSnapshot | null = row
    ? {
        source,
        generation: row.generation,
        completedAt: row.completedAt.toISOString(),
        validUntil: row.validUntil.toISOString(),
      }
    : null;
  return { row: row ?? null, snapshot, self, peers: nodes.filter((node) => !node.isSelf) };
}

export type LoadedSnapshot = Awaited<ReturnType<typeof loadTailnetSnapshot>>;

export function snapshotLeaseValid(loaded: LoadedSnapshot, now: Date) {
  return Boolean(loaded.row && loaded.row.validUntil.getTime() > now.getTime());
}

/** Commits one complete generation of `source`; refuses to replace a newer one. */
export async function commitTailnetGeneration(
  source: TailnetSource,
  input: {
    generation: string;
    self: TailnetNode;
    peers: TailnetNode[];
    completedAt: Date;
    validUntil: Date;
  },
) {
  const nodes = [input.self, ...input.peers];
  if (nodes.some((node) => node.source !== source)) {
    throw new Error(`Refusing to commit nodes of another source into the ${source} snapshot.`);
  }
  const completedAt = input.completedAt.toISOString();
  const validUntil = input.validUntil.toISOString();
  await sql.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(hashtext(${`ark:tailnet:${source}`}))`;
    const [current] = await tx`
      SELECT (extract(epoch FROM completed_at) * 1000)::float8 AS completed_ms
      FROM tailnet_snapshots WHERE source = ${source} FOR UPDATE
    `;
    if (current && Number(current.completed_ms) >= input.completedAt.getTime()) {
      throw new Error(`A newer ${source} observation is already committed; this one is discarded.`);
    }
    await tx`
      INSERT INTO tailnet_snapshots (source, generation, completed_at, valid_until)
      VALUES (${source}, ${input.generation}, ${completedAt}::timestamptz, ${validUntil}::timestamptz)
      ON CONFLICT (source) DO UPDATE
        SET generation = EXCLUDED.generation, completed_at = EXCLUDED.completed_at,
            valid_until = EXCLUDED.valid_until
    `;
    // Peers absent from this generation disappear in the same transaction.
    await tx`DELETE FROM tailnet_nodes WHERE source = ${source}`;
    for (const node of nodes) {
      await tx`
        INSERT INTO tailnet_nodes (source, generation, stable_id, dns_name, host_name, ipv4, ipv6, tags,
          is_self, online, observed_at)
        VALUES (${source}, ${input.generation}, ${node.stableId}, ${node.dnsName}, ${node.hostName},
          ${node.ipv4}, ${node.ipv6}, ${JSON.stringify(node.tags)}::jsonb, ${node.isSelf}, ${node.online},
          ${completedAt}::timestamptz)
      `;
    }
  });
}
