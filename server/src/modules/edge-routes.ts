// `edge.apply` input for front-door HTTP routes (docs/design/front-door.md §3.5, FD-09).
//
// The lease policy (`edgePolicy`, FD-06) decides which routes may be served at all: enabled, `ready`,
// pinned identity still valid, lease fresh. Routes in `awaiting_acl`, `identity_mismatch`,
// `observation_expired`, `disabled` (or any other state) never reach this point, so they are absent
// from both the Caddyfile and the HAProxy 443 map. This module adds what the renderer needs from
// `front_routes` (access mode, bypass paths, HTTP options, apex redirect, rate limit) and from the latest
// edge observation (the target's other tailnet names and addresses, for the Location policy). HTTP mTLS
// routes (FD-23) also get their CA and the client certificates it admits right now. `planEdge` then
// omits anything it cannot serve, such as an SSO bypass of the whole site or an unreadable client CA.

import type { EdgePolicyRoute, HttpClientAuth } from "@ark-stack/shared";
import { and, eq, inArray } from "drizzle-orm";

import { db } from "../db.ts";
import { clientCertificates, frontRoutes, privateCas, tailnetNodes } from "../schema.ts";
import { admittedClientCertificates, caCertificateDer } from "./route-crl.ts";

export { httpRoutesFor } from "./edge-route-input.ts";
import { httpRoutesFor } from "./edge-route-input.ts";

/** Reads `front_routes` and the edge observation for the routes the lease policy allows. */
export async function edgeHttpRoutes(policyRoutes: EdgePolicyRoute[], now = new Date()) {
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
      rateLimit: frontRoutes.rateLimit,
      clientCaId: frontRoutes.clientCaId,
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
  return httpRoutesFor(policyRoutes, rows, nodes, await httpClientAuth(rows, now));
}

/**
 * HTTP mTLS (FD-23): each route CA's certificate and the client certificates it admits now. A CA that
 * is not active admits nobody; one whose certificate cannot be read is left out, so its route is omitted.
 */
async function httpClientAuth(rows: Array<{ clientCaId: string | null }>, now: Date) {
  const caIds = [...new Set(rows.flatMap((row) => (row.clientCaId ? [row.clientCaId] : [])))];
  const result = new Map<string, HttpClientAuth>();
  if (!caIds.length) return result;
  const [cas, certificates] = await Promise.all([
    db.select().from(privateCas).where(inArray(privateCas.id, caIds)),
    db.select().from(clientCertificates).where(inArray(clientCertificates.caId, caIds)),
  ]);
  for (const ca of cas) {
    const caCertificate = caCertificateDer(ca.certPem);
    if (!caCertificate) continue;
    result.set(ca.id, {
      caCertificate,
      certificates:
        ca.status === "active"
          ? admittedClientCertificates({
              crlPem: ca.crlPem,
              certificates: certificates.filter((item) => item.caId === ca.id),
              now,
            })
          : [],
    });
  }
  return result;
}
