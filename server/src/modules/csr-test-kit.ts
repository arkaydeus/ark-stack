// Test-only helpers for the FD-17 CSR hardening suites. Nothing in production imports this file.
//
// `buildCsr` assembles a PKCS#10 request from parts and signs it, so a test can place one
// malformed element inside an otherwise valid, correctly signed request: the parser must then
// reject the structure itself rather than relying on the signature check.

import { sign, type KeyObject } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import * as x509 from "./x509.ts";

export const corpusDir = join(import.meta.dir, "testdata", "csr-corpus");

/** The committed OpenSSL-made CSRs (public data only; their keys were discarded). */
export function loadCorpus() {
  return readdirSync(corpusDir)
    .filter((name) => name.endsWith(".csr"))
    .toSorted()
    .map((name) => {
      const pem = readFileSync(join(corpusDir, name), "utf8");
      return { name, pem, der: x509.fromPem(pem, ["CERTIFICATE REQUEST"]) };
    });
}

export const toCsrPem = (der: Buffer) => x509.toPem("CERTIFICATE REQUEST", der);

/** Encode a TLV with an exact, possibly lying, length header. */
export function rawTlv(tag: number, lengthBytes: number[], content: Buffer) {
  return Buffer.concat([Buffer.from([tag, ...lengthBytes]), content]);
}

/** A raw OBJECT IDENTIFIER from content bytes, for OID edge cases the encoder would refuse. */
export const rawOid = (content: number[] | Buffer) => x509.tlv(0x06, Buffer.from(content));

export function extensionRequest(extensions: Buffer[]) {
  return x509.sequence(x509.oid(x509.OID.extensionRequest), x509.set(x509.sequence(...extensions)));
}

export type CsrParts = {
  key: KeyObject;
  /** SubjectPublicKeyInfo DER. Defaults to the key's own. */
  spki?: Buffer;
  version?: Buffer;
  subject?: Buffer;
  /** Complete Attribute DERs placed inside `[0]`. */
  attributes?: Buffer[];
  /** Omit the `[0]` attributes field entirely. */
  noAttributes?: boolean;
  /** Extra DER appended inside CertificationRequestInfo, after the attributes. */
  infoTrailer?: Buffer;
  signatureAlgorithm?: Buffer;
  /** Hash used to sign; defaults to sha256. */
  hash?: string;
  /** Replace the signature value (the BIT STRING content after the unused-bits byte). */
  signature?: (info: Buffer) => Buffer;
  /** Replace the whole signature BIT STRING. */
  signatureBitString?: (signature: Buffer) => Buffer;
  /** Extra DER appended inside the outer CertificationRequest SEQUENCE. */
  outerTrailer?: Buffer;
};

export function buildCsr(parts: CsrParts) {
  const keyType = parts.key.asymmetricKeyType;
  const info = x509.sequence(
    parts.version ?? x509.integer(0),
    parts.subject ?? x509.name([{ type: "CN", value: "fd17 test" }]),
    parts.spki ?? x509.spkiDer(parts.key),
    ...(parts.noAttributes ? [] : [x509.tlv(0xa0, ...(parts.attributes ?? []))]),
    ...(parts.infoTrailer ? [parts.infoTrailer] : []),
  );
  const hash = parts.hash ?? "sha256";
  const signature =
    parts.signature?.(info) ??
    sign(hash, info, keyType === "ec" ? { key: parts.key, dsaEncoding: "der" } : parts.key);
  const algorithm =
    parts.signatureAlgorithm ??
    (keyType === "ec"
      ? x509.sequence(x509.oid(x509.OID.ecdsaWithSha256))
      : x509.sequence(x509.oid(x509.OID.sha256WithRsa), x509.tlv(0x05)));
  const der = x509.sequence(
    info,
    algorithm,
    parts.signatureBitString ? parts.signatureBitString(signature) : x509.bitString(signature),
    ...(parts.outerTrailer ? [parts.outerTrailer] : []),
  );
  return { der, pem: toCsrPem(der), info };
}

/** The byte offsets of every TLV header in a DER value, walking constructed values. */
export function headerOffsets(der: Buffer) {
  const offsets: number[] = [];
  const walk = (buffer: Buffer, base: number, depth: number) => {
    for (let offset = 0; offset < buffer.length;) {
      let node: x509.Node;
      try {
        node = x509.readNode(buffer, offset);
      } catch {
        return;
      }
      offsets.push(base + offset);
      const headerLength = node.raw.length - node.content.length;
      if (node.tag & 0x20 && depth < 32) walk(node.content, base + offset + headerLength, depth + 1);
      // BIT STRING and OCTET STRING values often wrap DER (keys, extension values).
      if ((node.tag === 0x04 || node.tag === 0x03) && depth < 32) {
        const skip = node.tag === 0x03 ? 1 : 0;
        walk(node.content.subarray(skip), base + offset + headerLength + skip, depth + 1);
      }
      offset += node.raw.length;
    }
  };
  walk(der, 0, 0);
  return [...new Set(offsets)].toSorted((a, b) => a - b);
}

/** A small, fast, seedable PRNG (mulberry32), so every fuzz run is reproducible from its seed. */
export function prng(seed: number) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    int: (max: number) => Math.floor(next() * max),
    pick: <T>(items: readonly T[]) => items[Math.floor(next() * items.length)]!,
    bytes: (count: number) => Buffer.from(Array.from({ length: count }, () => Math.floor(next() * 256))),
  };
}
