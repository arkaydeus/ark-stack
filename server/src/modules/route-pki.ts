// Route CAs for `terminate_mtls` TLS-TCP routes (docs/design/front-door.md §3.8.4, §3.8.6, §3.10.1,
// FD-13, FD-14). Each such route has its own `tcp-client` CA. HAProxy checks client certificates
// against it and its CRL, which must exist (OpenSSL fails CRL checks for an issuer without one) and
// must be current (an expired CRL fails every handshake). Revoking a certificate regenerates the CRL;
// the serial also enters the route's lease policy fingerprint, so the running HAProxy servers of the
// old policy are fenced and their sessions drained in every worker before the new CRL is reloaded.
//
// HTTP mTLS routes (FD-23) have an `http-client` CA. Caddy has no CRL support, so the edge renders the
// CA's certificates that are neither revoked nor listed in its CRL (`admittedClientCertificates`); the
// CRL is still kept current here, for clients and audits that read it.

import { eq, and, inArray } from "drizzle-orm";

import { db } from "../db.ts";
import { privateCas } from "../schema.ts";
import * as pki from "./pki.ts";
import { revokedSerials } from "./l4-routes.ts";
import { routeCrlCovers } from "./route-crl.ts";

/** Regenerate a route CA's CRL once fewer than this many days remain (14-day CRLs, weekly refresh). */
export const ROUTE_CRL_REFRESH_DAYS = 7;

/** Route CAs whose CRL is missing or due for its weekly refresh. */
export async function routeCrlsDue(now = new Date()) {
  const threshold = new Date(now.getTime() + ROUTE_CRL_REFRESH_DAYS * 86_400_000);
  const cas = await db
    .select()
    .from(privateCas)
    .where(and(inArray(privateCas.purpose, ["tcp-client", "http-client"]), eq(privateCas.status, "active")));
  const revoked = await revokedSerials(cas.map((ca) => ca.id));
  return cas
    .filter(
      (ca) =>
        !ca.crlNextUpdate ||
        ca.crlNextUpdate < threshold ||
        !routeCrlCovers(ca.crlPem, revoked.get(ca.id) ?? []),
    )
    .map((ca) => ({ id: ca.id }));
}

/** Generates every missing or due route CA CRL. Returns the refreshed CA IDs. */
export async function refreshRouteCrls(now = new Date()) {
  const refreshed: string[] = [];
  for (const { id } of await routeCrlsDue(now)) {
    await pki.generateCaCrl({ caId: id, now });
    refreshed.push(id);
  }
  return refreshed;
}
