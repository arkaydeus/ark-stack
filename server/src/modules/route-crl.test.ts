// FD-23: which client certificates an HTTP mTLS route admits (the Caddy `leaf` allowlist), from the
// route CA's certificate rows and its CRL, built with the production PKI functions.
import { expect, test } from "bun:test";
import { generateKeyPairSync, X509Certificate } from "node:crypto";

import { admittedClientCertificates, caCertificateDer, routeCrlCovers } from "./route-crl.ts";

process.env.DATABASE_URL ??= "postgres://unused:unused@127.0.0.1:9/unused";
const { buildCrl, createCaMaterial, signClientCertificate } = await import("./pki.ts");

const now = new Date("2026-11-18T12:00:00Z");
const ca = createCaMaterial({ id: "pca_fd23", purpose: "http-client", name: "Route rt_fd23", now });
const issue = (name: string, at = now) =>
  signClientCertificate({
    ca,
    subjectCn: name,
    publicKey: generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey,
    now: at,
  });
const good = issue("good");
const revoked = issue("revoked");
const listed = issue("listed-only");
const crl = (serials: string[]) =>
  buildCrl({
    ca,
    revoked: serials.map((serial) => ({ serial, revokedAt: now })),
    thisUpdate: now,
    nextUpdate: new Date(now.getTime() + 14 * 86_400_000),
    crlNumber: 2n,
  }).crlPem;
const row = (certificate: typeof good, status = "issued") => ({ ...certificate, status });
const der = (pem: string) => new X509Certificate(pem).raw.toString("base64");

test("admits issued, current certificates that the CRL does not list", () => {
  const admitted = admittedClientCertificates({
    crlPem: crl([listed.serial]),
    certificates: [row(good), row(revoked, "revoked"), row(listed)],
    now,
  });
  expect(admitted).toEqual([der(good.certPem)]);
});

test("expired, not-yet-valid and malformed rows are never admitted", () => {
  const later = new Date(now.getTime() + 91 * 86_400_000);
  expect(admittedClientCertificates({ crlPem: crl([]), certificates: [row(good)], now: later })).toEqual([]);
  const future = issue("future", new Date(now.getTime() + 86_400_000));
  expect(admittedClientCertificates({ crlPem: crl([]), certificates: [row(future)], now })).toEqual([]);
  expect(
    admittedClientCertificates({
      crlPem: crl([]),
      certificates: [
        { ...row(good), certPem: null },
        { ...row(good), certPem: "-----BEGIN X-----" },
      ],
      now,
    }),
  ).toEqual([]);
});

test("a missing or unreadable CRL admits nobody", () => {
  expect(admittedClientCertificates({ crlPem: null, certificates: [row(good)], now })).toEqual([]);
  expect(admittedClientCertificates({ crlPem: "not a crl", certificates: [row(good)], now })).toEqual([]);
});

test("the CA certificate is passed as base64 DER, or null when unreadable", () => {
  expect(caCertificateDer(ca.certPem)).toBe(der(ca.certPem));
  expect(caCertificateDer(null)).toBeNull();
  expect(caCertificateDer("garbage")).toBeNull();
  // The CRL coverage check of the refresh loop reads the same CRL.
  expect(routeCrlCovers(crl([revoked.serial]), [revoked.serial])).toBe(true);
});
