// `edge.apply` input for front-door HTTP routes (docs/design/front-door.md §3.5, FD-09).
//
// The lease policy (`edgePolicy`, FD-06) decides which routes may be served at all: enabled, `ready`,
// pinned identity still valid, lease fresh. Routes in `awaiting_acl`, `identity_mismatch`,
// `observation_expired`, `disabled` (or any other state) never reach this point, so they are absent
// from both the Caddyfile and the HAProxy 443 map. This module adds what the renderer needs from
// `front_routes` (access mode, bypass paths, HTTP options, apex redirect) and from the latest edge
// observation (the target's other tailnet names and addresses, for the Location policy). `planEdge`
// then omits anything it cannot serve, such as `sso` before FD-11.

import type { EdgePolicyRoute } from "@ark-stack/shared";
import { and, eq, inArray } from "drizzle-orm";

import { db } from "../db.ts";
import { frontRoutes, tailnetNodes } from "../schema.ts";

export { httpRoutesFor } from "./edge-route-input.ts";
import { httpRoutesFor } from "./edge-route-input.ts";

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
