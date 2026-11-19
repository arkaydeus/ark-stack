import type { EdgeHttpRoute, EdgePolicyRoute, HttpClientAuth, HttpRateLimit } from "@ark-stack/shared";
import type { frontRoutes, tailnetNodes } from "../schema.ts";

export type RouteRow = Pick<
  typeof frontRoutes.$inferSelect,
  "id" | "kind" | "accessMode" | "bypassPaths" | "httpOptions" | "targetInput" | "targetNodeStableId"
> &
  Partial<Pick<typeof frontRoutes.$inferSelect, "rateLimit" | "clientCaId">>;
export type NodeRow = Pick<
  typeof tailnetNodes.$inferSelect,
  "stableId" | "dnsName" | "hostName" | "ipv4" | "ipv6"
>;

/** A client CA that cannot be rendered: `checkedHttpRoute` refuses it, so the route is omitted. */
const UNUSABLE_CLIENT_AUTH: HttpClientAuth = { caCertificate: "", certificates: [] };

/**
 * Pure join of the policy, the route rows and the observed nodes (unit-testable without a database).
 * `clientAuth` holds each HTTP mTLS route CA's certificate and admitted client certificates (FD-23);
 * a route whose CA is missing from it is passed on unusable and omitted by the planner (fail closed).
 * The stored rate limit is passed through unchanged; the renderer validates it.
 */
export function httpRoutesFor(
  policyRoutes: EdgePolicyRoute[],
  rows: RouteRow[],
  nodes: NodeRow[],
  clientAuth: ReadonlyMap<string, HttpClientAuth> = new Map(),
) {
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
      ...(row.rateLimit != null ? { rateLimit: row.rateLimit as HttpRateLimit } : {}),
      ...(row.clientCaId ? { clientAuth: clientAuth.get(row.clientCaId) ?? UNUSABLE_CLIENT_AUTH } : {}),
    });
  }
  return routes;
}
