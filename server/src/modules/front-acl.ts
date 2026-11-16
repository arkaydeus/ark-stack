// Tailscale policy snippets for the front door (docs/design/front-door.md §3.7, FD-07).
//
// Loads the public routing facts of every route and tailnet backup target, renders the snippet
// with the pure generator in shared/src/tailnet-acl.ts, and keeps the last generated snippet per
// scope so the owner sees what changed. Ark never writes the tailnet policy and holds no
// Tailscale credential; nothing here reads a secret.

import {
  diffLines,
  generateTailnetAcl,
  sha256Hex,
  tailnetBackupTarget,
  type AclBackupTarget,
  type AclOmission,
  type AclRoute,
  type DiffLine,
} from "@ark-stack/shared";
import { eq } from "drizzle-orm";

import { db } from "../db.ts";
import { backupTargets, endpoints, frontRoutes, tailnetAclSnippets, tailnetNodes } from "../schema.ts";

export type FrontAclScope = { kind: "global" } | { kind: "route"; routeId: string };

export type FrontAclResponse = {
  scope: "global" | "route";
  routeId: string | null;
  tailnet: string | null;
  snippet: string;
  digest: string;
  /** When this exact snippet was first generated. */
  generatedAt: string;
  sshExample: string;
  omitted: AclOmission[];
  /** The snippet generated before this one, if it differed. */
  previous: { digest: string; generatedAt: string | null } | null;
  /** Line diff from `previous` to `snippet`; null when there is nothing to compare. */
  diff: DiffLine[] | null;
  routes: Array<{ id: string; kind: string; hostname: string; listenPort: number; status: string }>;
};

type NodeRow = typeof tailnetNodes.$inferSelect;

function nodeName(nodes: NodeRow[], stableId: string) {
  // The edge observation pins routes; fall back to the backup observation for its own targets.
  const node =
    nodes.find((item) => item.source === "edge" && item.stableId === stableId) ??
    nodes.find((item) => item.stableId === stableId);
  return node?.dnsName ?? null;
}

/** `tail1234.ts.net`, learned from the edge node's own MagicDNS name. */
function tailnetName(nodes: NodeRow[]) {
  const self = nodes.find((item) => item.source === "edge" && item.isSelf);
  const name = self?.dnsName.toLowerCase().replace(/\.$/, "");
  const dot = name?.indexOf(".") ?? -1;
  return name && dot > 0 ? name.slice(dot + 1) : null;
}

async function loadInputs() {
  const [routeRows, nodes, backupRows] = await Promise.all([
    db
      .select({
        id: frontRoutes.id,
        kind: frontRoutes.kind,
        hostname: endpoints.hostname,
        listenPort: frontRoutes.listenPort,
        compatPort: frontRoutes.compatPort,
        tlsMode: frontRoutes.tlsMode,
        targetInput: frontRoutes.targetInput,
        targetIp: frontRoutes.targetIp,
        targetPort: frontRoutes.targetPort,
        targetNodeStableId: frontRoutes.targetNodeStableId,
        status: frontRoutes.status,
      })
      .from(frontRoutes)
      .innerJoin(endpoints, eq(endpoints.id, frontRoutes.endpointId)),
    db.select().from(tailnetNodes),
    // Only the columns the snippet needs: never the credential reference.
    db
      .select({
        id: backupTargets.id,
        name: backupTargets.name,
        restUrl: backupTargets.restUrl,
        targetNodeStableId: backupTargets.targetNodeStableId,
      })
      .from(backupTargets)
      .where(eq(backupTargets.kind, "tailnet_rest")),
  ]);

  const routes: AclRoute[] = routeRows.map((row) => ({
    id: row.id,
    kind: row.kind,
    hostname: row.hostname,
    listenPort: row.listenPort,
    compatPort: row.compatPort,
    tlsMode: row.tlsMode,
    targetIp: row.targetIp,
    targetPort: row.targetPort,
    targetNodeStableId: row.targetNodeStableId,
    targetName:
      nodeName(nodes, row.targetNodeStableId) ??
      (/^[\d.:a-f]+$/i.test(row.targetInput) ? null : row.targetInput),
    status: row.status,
  }));

  // Backup targets resolve against the backup observation first: that node is what dials them.
  const ordered = [
    ...nodes.filter((item) => item.source === "backup"),
    ...nodes.filter((item) => item.source !== "backup"),
  ];
  const backups: AclBackupTarget[] = [];
  const omitted: AclOmission[] = [];
  for (const row of backupRows.toSorted((a, b) => (a.id < b.id ? -1 : 1))) {
    const resolved = tailnetBackupTarget(row, ordered);
    if ("reason" in resolved) omitted.push(resolved);
    else backups.push(resolved);
  }
  return { routes, routeRows, backups, omitted, tailnet: tailnetName(nodes) };
}

/**
 * Renders the snippet for a scope and records it as the latest. Returns null when the route does
 * not exist. The stored baseline only moves when the snippet actually changes, so the diff stays
 * stable across reloads.
 */
export async function frontAclSnippet(scope: FrontAclScope): Promise<FrontAclResponse | null> {
  const inputs = await loadInputs();
  const route = scope.kind === "route" ? inputs.routes.find((item) => item.id === scope.routeId) : null;
  if (scope.kind === "route" && !route) return null;

  const generated = generateTailnetAcl(
    route
      ? {
          routes: [route],
          reservedTargets: inputs.backups,
          tailnet: inputs.tailnet,
          scope: { routeId: route.id, hostname: route.hostname },
        }
      : {
          routes: inputs.routes,
          backupTargets: inputs.backups,
          omitted: inputs.omitted,
          tailnet: inputs.tailnet,
        },
  );
  const snippet = generated.hujson;
  const digest = sha256Hex(snippet);
  const key = route ? `route:${route.id}` : "global";

  const stored = await db.transaction(async (tx) => {
    await tx
      .insert(tailnetAclSnippets)
      .values({ scope: key, routeId: route?.id ?? null, digest, snippet })
      .onConflictDoNothing();
    const [current] = await tx
      .select()
      .from(tailnetAclSnippets)
      .where(eq(tailnetAclSnippets.scope, key))
      .for("update");
    if (!current || current.digest === digest) return current;
    const [shifted] = await tx
      .update(tailnetAclSnippets)
      .set({
        digest,
        snippet,
        generatedAt: new Date(),
        previousDigest: current.digest,
        previousSnippet: current.snippet,
        previousGeneratedAt: current.generatedAt,
      })
      .where(eq(tailnetAclSnippets.scope, key))
      .returning();
    return shifted;
  });

  const previous =
    stored?.previousDigest && stored.previousSnippet !== null
      ? { digest: stored.previousDigest, generatedAt: stored.previousGeneratedAt?.toISOString() ?? null }
      : null;
  return {
    scope: scope.kind,
    routeId: route?.id ?? null,
    tailnet: inputs.tailnet,
    snippet,
    digest,
    generatedAt: (stored?.generatedAt ?? new Date()).toISOString(),
    sshExample: generated.sshExample,
    omitted: generated.omitted,
    previous,
    diff: previous && stored?.previousSnippet ? diffLines(stored.previousSnippet, snippet) : null,
    routes: inputs.routeRows
      .map((row) => ({
        id: row.id,
        kind: row.kind,
        hostname: row.hostname,
        listenPort: row.listenPort,
        status: row.status,
      }))
      .toSorted((a, b) =>
        a.hostname < b.hostname ? -1 : a.hostname > b.hostname ? 1 : a.listenPort - b.listenPort,
      ),
  };
}
