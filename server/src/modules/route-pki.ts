// Route CAs for `terminate_mtls` TLS-TCP routes (docs/design/front-door.md §3.8.4, §3.8.6, §3.10.1,
// FD-13, FD-14). Each such route has its own `tcp-client` CA. HAProxy checks client certificates
// against it and its CRL, which must exist (OpenSSL fails CRL checks for an issuer without one) and
// must be current (an expired CRL fails every handshake). Revoking a certificate regenerates the CRL;
// the serial also enters the route's lease policy fingerprint, so the running HAProxy servers of the
// old policy are fenced and their sessions drained in every worker before the new CRL is reloaded.

import { and, eq, lt, isNull, or } from "drizzle-orm";

import { db } from "../db.ts";
import { privateCas } from "../schema.ts";
import * as pki from "./pki.ts";

/** Regenerate a route CA's CRL once fewer than this many days remain (14-day CRLs, weekly refresh). */
export const ROUTE_CRL_REFRESH_DAYS = 7;

/** Route CAs whose CRL is missing or due for its weekly refresh. */
export async function routeCrlsDue(now = new Date()) {
  const threshold = new Date(now.getTime() + ROUTE_CRL_REFRESH_DAYS * 86_400_000);
  return db
    .select({ id: privateCas.id })
    .from(privateCas)
    .where(
      and(
        eq(privateCas.purpose, "tcp-client"),
        eq(privateCas.status, "active"),
        or(
          isNull(privateCas.crlPem),
          isNull(privateCas.crlNextUpdate),
          lt(privateCas.crlNextUpdate, threshold),
        ),
      ),
    );
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
