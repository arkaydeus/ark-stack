// `edge.apply` input for front-door HTTP routes (docs/design/front-door.md §3.5, FD-09).
//
// The lease policy (`edgePolicy`, FD-06) decides which routes may be served at all: enabled, `ready`,
// pinned identity still valid, lease fresh. Routes in `awaiting_acl`, `identity_mismatch`,
// `observation_expired`, `disabled` (or any other state) never reach this point, so they are absent
// from both the Caddyfile and the HAProxy 443 map. This module adds what the renderer needs from
// `front_routes` (access mode, bypass paths, HTTP options, apex redirect) and from the latest edge
// observation (the target's other tailnet names and addresses, for the Location policy). `planEdge`
// then omits anything it cannot serve, such as `sso` before FD-11.

import type { EdgeHttpRoute, EdgePolicyRoute } from "@ark-stack/shared";
import { and, eq, inArray } from "drizzle-orm";

import { db } from "../db.ts";
import { frontRoutes, tailnetNodes } from "../schema.ts";

type RouteRow = Pick<
  typeof frontRoutes.$inferSelect,
  "id" | "kind" | "accessMode" | "bypassPaths" | "httpOptions" | "targetInput" | "targetNodeStableId"
>;
type NodeRow = Pick<typeof tailnetNodes.$inferSelect, "stableId" | "dnsName" | "hostName" | "ipv4" | "ipv6">;

/** Pure join of the policy, the route rows and the observed nodes (unit-testable without a database). */
export function httpRoutesFor(policyRoutes: EdgePolicyRoute[], rows: RouteRow[], nodes: NodeRow[]) {
  const byId = new Map(rows.map((row) => [row.id, row]));
  const byStableId = new Map(nodes.map((node) => [node.stableId, node]));
  const routes: EdgeHttpRoute[] = [];
  for (const allowed of policyRoutes) {
    if (allowed.kind !== "http") continue;
    const row = byId.get(allowed.id);
    // The row changed kind or disappeared since the policy was read: serve nothing for it.
    if (!row || row.kind !== "http" || row.targetNodeStableId !== allowed.stableId) continue;
    const node = byStableId.get(allowed.stableId);
    const options = { ...row.httpOptions };
    const redirectTo = typeof options.redirectTo === "string" ? options.redirectTo : null;
    delete options.redirectTo;
    routes.push({
      id: allowed.id,
      hostname: allowed.hostname,
      stableId: allowed.stableId,
      ip: allowed.ip,
      port: allowed.port,
      access: row.accessMode,
      bypassPaths: row.bypassPaths,
      redirectTo,
      options,
      internalNames: [row.targetInput, node?.dnsName, node?.hostName].filter(
        (name): name is string => typeof name === "string" && name.length > 0,
      ),
      internalIps: [node?.ipv4, node?.ipv6].filter(
        (ip): ip is string => typeof ip === "string" && ip.length > 0 && ip !== allowed.ip,
      ),
    });
  }
  return routes;
}

/** Reads `front_routes` and the edge observation for the routes the lease policy allows. */
export async function edgeHttpRoutes(policyRoutes: EdgePolicyRoute[]) {
  const ids = policyRoutes.filter((route) => route.kind === "http").map((route) => route.id);
  if (!ids.length) return [];
  const rows = await db
    .select({
      id: frontRoutes.id,
      kind: frontRoutes.kind,
      accessMode: frontRoutes.accessMode,
      bypassPaths: frontRoutes.bypassPaths,
      httpOptions: frontRoutes.httpOptions,
      targetInput: frontRoutes.targetInput,
      targetNodeStableId: frontRoutes.targetNodeStableId,
    })
    .from(frontRoutes)
    .where(inArray(frontRoutes.id, ids));
  const stableIds = [...new Set(rows.map((row) => row.targetNodeStableId))];
  const nodes = stableIds.length
    ? await db
        .select({
          stableId: tailnetNodes.stableId,
          dnsName: tailnetNodes.dnsName,
          hostName: tailnetNodes.hostName,
          ipv4: tailnetNodes.ipv4,
          ipv6: tailnetNodes.ipv6,
        })
        .from(tailnetNodes)
        .where(and(eq(tailnetNodes.source, "edge"), inArray(tailnetNodes.stableId, stableIds)))
    : [];
  return httpRoutesFor(policyRoutes, rows, nodes);
}
