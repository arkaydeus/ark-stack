import { fromPem, parseCrl } from "./x509.ts";

const serialKey = (hex: string) => BigInt(`0x${hex}`).toString();

/** A stored CRL must represent every committed revocation, including recovery of older failures. */
export function routeCrlCovers(crlPem: string | null, serials: string[]) {
  if (!crlPem) return false;
  try {
    const crl = parseCrl(fromPem(crlPem, ["X509 CRL"]));
    const revoked = new Set(crl.revoked.map((entry) => serialKey(entry.serial)));
    return serials.every((serial) => revoked.has(serialKey(serial)));
  } catch {
    return false;
  }
}

export type RouteClientCertificate = {
  serial: string;
  status: string;
  notBefore: Date;
  notAfter: Date;
  certPem: string | null;
};

/**
 * The client certificates an HTTP mTLS route admits (FD-23), as base64 DER for the Caddy `leaf`
 * verifier: certificates of the route CA that are `issued` (never revoked or expired), currently
 * valid, and whose serial is not in the CA's CRL. A missing or unreadable CRL admits nobody, as an
 * unreadable CRL fails every HAProxy handshake for `terminate_mtls` routes.
 */
export function admittedClientCertificates(input: {
  crlPem: string | null;
  certificates: RouteClientCertificate[];
  now?: Date;
}) {
  if (!input.crlPem) return [];
  let revoked: Set<string>;
  try {
    revoked = new Set(
      parseCrl(fromPem(input.crlPem, ["X509 CRL"])).revoked.map((entry) => serialKey(entry.serial)),
    );
  } catch {
    return [];
  }
  const now = (input.now ?? new Date()).getTime();
  const admitted: string[] = [];
  for (const certificate of input.certificates) {
    if (certificate.status !== "issued" || !certificate.certPem) continue;
    if (certificate.notBefore.getTime() > now || certificate.notAfter.getTime() <= now) continue;
    try {
      if (revoked.has(serialKey(certificate.serial))) continue;
      admitted.push(fromPem(certificate.certPem, ["CERTIFICATE"]).toString("base64"));
    } catch {
      // A malformed stored row is never admitted.
    }
  }
  return admitted.toSorted();
}

/** The route CA certificate as base64 DER, or null when it cannot be read (the route is then omitted). */
export function caCertificateDer(certPem: string | null | undefined) {
  if (!certPem) return null;
  try {
    return fromPem(certPem, ["CERTIFICATE"]).toString("base64");
  } catch {
    return null;
  }
}
