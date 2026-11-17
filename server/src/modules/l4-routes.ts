// TLS-TCP and raw-TCP routes (docs/design/front-door.md §3.8, FD-14): their stored admission policy,
// its fingerprint in the lease (so a policy change or a client certificate revocation fences and
// drains the route's old HAProxy servers in every worker), and the `edge.l4_apply` input built from
// the routes the lease allows: the certificate for terminated routes, the route CA and its CRL.

import {
  isTcpRoutePort,
  l4Limits,
  l4PolicyFingerprint,
  parseSniPorts,
  routeAllowlist,
  type EdgeL4TcpRoute,
  type EdgeL4TlsMode,
  type EdgeL4TlsRoute,
  type EdgePolicyRoute,
  type L4Limits,
} from "@ark-stack/shared";
import { and, eq, inArray } from "drizzle-orm";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { db, type DbTransaction } from "../db.ts";
import { clientCertificates, frontRoutes, privateCas } from "../schema.ts";

import { routeCrlCovers } from "./route-crl.ts";

type RouteRow = typeof frontRoutes.$inferSelect;

/** Shared SNI ports enabled at install time (`ARK_EDGE_SNI_PORTS`, published on edge-ts). */
export function enabledSniPorts(env: Record<string, string | undefined> = process.env) {
  return parseSniPorts(env.ARK_EDGE_SNI_PORTS);
}

export type StoredL4Settings = {
  kind: "tls" | "tcp";
  listenPort: number;
  tlsMode: EdgeL4TlsMode | "plain";
  sourceCidrs: string[];
  allowInternet: boolean;
  protocolAuthConfirmed: boolean;
  limits: L4Limits;
  clientCaId: string | null;
};

/** The stored L4 settings of a route row, or null for HTTP/Postgres rows and invalid stored values. */
export function storedL4Settings(
  row: Pick<
    RouteRow,
    | "kind"
    | "listenPort"
    | "tlsMode"
    | "sourceCidrs"
    | "allowInternet"
    | "protocolAuthConfirmed"
    | "tcpOptions"
    | "clientCaId"
  >,
): StoredL4Settings | null {
  if (row.kind !== "tls" && row.kind !== "tcp") return null;
  try {
    const kind = row.kind;
    const tlsMode = row.tlsMode;
    if (!tlsMode || (kind === "tcp" ? tlsMode !== "plain" : tlsMode === "plain")) return null;
    if (kind === "tcp" && !isTcpRoutePort(row.listenPort)) return null;
    const sourceCidrs = Array.isArray(row.sourceCidrs) ? row.sourceCidrs.map(String) : [];
    routeAllowlist({ sourceCidrs, allowInternet: false });
    return {
      kind,
      listenPort: row.listenPort,
      tlsMode,
      sourceCidrs,
      allowInternet: row.allowInternet,
      protocolAuthConfirmed: row.protocolAuthConfirmed,
      limits: l4Limits(kind, row.tcpOptions as Partial<Record<keyof L4Limits, unknown>>),
      clientCaId: row.clientCaId,
    };
  } catch {
    return null;
  }
}

/** Revoked serials per CA, for the policy fingerprint of `terminate_mtls` routes. */
export async function revokedSerials(caIds: string[], executor: Pick<typeof db, "select"> = db) {
  const ids = [...new Set(caIds)];
  const result = new Map<string, string[]>();
  if (!ids.length) return result;
  const rows = await executor
    .select({ caId: clientCertificates.caId, serial: clientCertificates.serial })
    .from(clientCertificates)
    .where(and(inArray(clientCertificates.caId, ids), eq(clientCertificates.status, "revoked")));
  for (const row of rows) result.set(row.caId, [...(result.get(row.caId) ?? []), row.serial]);
  return result;
}

/** The lease policy fingerprint of an L4 route (`EdgePolicyRoute.policy`). */
export function l4RoutePolicy(settings: StoredL4Settings, revoked: Map<string, string[]>) {
  return l4PolicyFingerprint({
    ...settings,
    clientCaId: settings.tlsMode === "terminate_mtls" ? settings.clientCaId : null,
    revokedSerials:
      settings.tlsMode === "terminate_mtls" ? (revoked.get(settings.clientCaId ?? "") ?? []) : [],
  });
}

/** A route the lease allows but `edge.l4_apply` cannot serve, and why (omitted from both configs). */
export type OmittedL4Route = { id: string; hostname: string; reason: string };

/**
 * The `tls` and `tcp` routes of an `edge.l4_apply` input: only routes in the lease policy, rendered
 * with exactly the policy fingerprint the lease names (a route whose stored policy moved on since
 * the lease was read waits for the next apply rather than rendering an unauthorised server).
 */
export async function edgeL4Routes(input: {
  policyRoutes: EdgePolicyRoute[];
  certDir?: string;
  sniPorts?: number[];
}) {
  const l4 = input.policyRoutes.filter((route) => route.kind === "tls" || route.kind === "tcp");
  const omitted: OmittedL4Route[] = [];
  const tlsRoutes: EdgeL4TlsRoute[] = [];
  const tcpRoutes: EdgeL4TcpRoute[] = [];
  if (!l4.length) return { tlsRoutes, tcpRoutes, omitted };
  const sniPorts = input.sniPorts ?? enabledSniPorts();
  // One MVCC snapshot: never pair a newly committed policy with an earlier CRL.
  const { rows, revoked, cas } = await db.transaction(
    async (tx: DbTransaction) => {
      const snapshotRows = await tx
        .select()
        .from(frontRoutes)
        .where(
          inArray(
            frontRoutes.id,
            l4.map((route) => route.id),
          ),
        );
      const caIds = snapshotRows.map((row) => row.clientCaId).filter((id): id is string => Boolean(id));
      const [snapshotRevoked, snapshotCas] = await Promise.all([
        revokedSerials(caIds, tx),
        caIds.length ? tx.select().from(privateCas).where(inArray(privateCas.id, caIds)) : [],
      ]);
      return { rows: snapshotRows, revoked: snapshotRevoked, cas: snapshotCas };
    },
    { isolationLevel: "repeatable read" },
  );
  const byId = new Map(rows.map((row) => [row.id, row]));
  const caById = new Map(cas.map((ca) => [ca.id, ca]));
  const certDir = input.certDir ?? process.env.ARK_CERT_DIR ?? join(process.cwd(), "tmp", "certs");
  for (const route of l4) {
    const row = byId.get(route.id);
    const settings = row ? storedL4Settings(row) : null;
    const omit = (reason: string) => omitted.push({ id: route.id, hostname: route.hostname, reason });
    if (!row || !settings) {
      omit("stored settings are invalid");
      continue;
    }
    if (l4RoutePolicy(settings, revoked) !== route.policy) {
      omit("the stored policy changed after the lease was read; the next apply renders it");
      continue;
    }
    const base = {
      id: route.id,
      hostname: route.hostname,
      stableId: route.stableId,
      ip: route.ip,
      port: route.port,
      policy: route.policy,
      sourceCidrs: settings.sourceCidrs,
      allowInternet: settings.allowInternet,
      limits: settings.limits,
    };
    if (settings.kind === "tcp") {
      tcpRoutes.push({ ...base, listenPort: settings.listenPort });
      continue;
    }
    if (settings.listenPort !== 443 && !sniPorts.includes(settings.listenPort)) {
      omit(`shared SNI port ${settings.listenPort} is not enabled on this host`);
      continue;
    }
    const tls: EdgeL4TlsRoute = {
      ...base,
      listenPort: settings.listenPort,
      tlsMode: settings.tlsMode as EdgeL4TlsMode,
    };
    if (settings.tlsMode !== "passthrough") {
      try {
        const directory = join(certDir, route.hostname);
        const [chain, key] = await Promise.all([
          readFile(join(directory, "fullchain.pem"), "utf8"),
          readFile(join(directory, "privkey.pem"), "utf8"),
        ]);
        tls.certificatePem = `${chain.trim()}\n${key.trim()}\n`;
      } catch (error) {
        omit(`its certificate could not be read: ${(error as Error).message}`);
        continue;
      }
    }
    if (settings.tlsMode === "terminate_mtls") {
      const ca = settings.clientCaId ? caById.get(settings.clientCaId) : undefined;
      if (!ca || ca.status !== "active" || !ca.crlPem) {
        omit(
          !ca
            ? "its route CA is missing"
            : ca.status !== "active"
              ? `its route CA is ${ca.status}`
              : "its route CA has no CRL yet",
        );
        continue;
      }
      if (!routeCrlCovers(ca.crlPem, revoked.get(ca.id) ?? [])) {
        omit("its route CRL does not cover every revoked certificate");
        continue;
      }
      tls.clientCaPem = ca.certPem;
      tls.clientCrlPem = ca.crlPem;
    }
    tlsRoutes.push(tls);
  }
  return { tlsRoutes, tcpRoutes, omitted };
}
