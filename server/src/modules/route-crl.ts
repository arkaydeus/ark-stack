import { fromPem, parseCrl } from "./x509.ts";

/** A stored CRL must represent every committed revocation, including recovery of older failures. */
export function routeCrlCovers(crlPem: string | null, serials: string[]) {
  if (!crlPem) return false;
  try {
    const crl = parseCrl(fromPem(crlPem, ["X509 CRL"]));
    const revoked = new Set(crl.revoked.map((entry) => BigInt(`0x${entry.serial}`).toString()));
    return serials.every((serial) => revoked.has(BigInt(`0x${serial}`).toString()));
  } catch {
    return false;
  }
}
