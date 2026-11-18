// Minimal DER and X.509 primitives for the private CA module (pki.ts, front door §3.10.1).
//
// Certificates, CRLs and CSR parsing are built in-process on node:crypto so private keys stay in
// memory as KeyObjects: no key file, no subprocess, no temporary directory. Signing and signature
// verification use node:crypto; this file only encodes and decodes the ASN.1 around them. The Bun
// tests check every structure produced here with OpenSSL (`openssl verify -x509_strict`, `crl`).

import { createHash, createPublicKey, sign, type KeyObject } from "node:crypto";

// ---- OIDs --------------------------------------------------------------------------------------

export const OID = {
  ecPublicKey: "1.2.840.10045.2.1",
  rsaEncryption: "1.2.840.113549.1.1.1",
  ecdsaWithSha256: "1.2.840.10045.4.3.2",
  ecdsaWithSha384: "1.2.840.10045.4.3.3",
  ecdsaWithSha512: "1.2.840.10045.4.3.4",
  sha256WithRsa: "1.2.840.113549.1.1.11",
  sha384WithRsa: "1.2.840.113549.1.1.12",
  sha512WithRsa: "1.2.840.113549.1.1.13",
  commonName: "2.5.4.3",
  serialNumber: "2.5.4.5",
  organizationName: "2.5.4.10",
  subjectKeyIdentifier: "2.5.29.14",
  keyUsage: "2.5.29.15",
  subjectAltName: "2.5.29.17",
  basicConstraints: "2.5.29.19",
  crlNumber: "2.5.29.20",
  crlReason: "2.5.29.21",
  authorityKeyIdentifier: "2.5.29.35",
  extendedKeyUsage: "2.5.29.37",
  clientAuth: "1.3.6.1.5.5.7.3.2",
  serverAuth: "1.3.6.1.5.5.7.3.1",
  extensionRequest: "1.2.840.113549.1.9.14",
} as const;

// ---- Encoder -----------------------------------------------------------------------------------

function encodeLength(length: number) {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  for (let value = length; value > 0; value = Math.floor(value / 256)) bytes.unshift(value & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function tlv(tag: number, ...contents: Buffer[]) {
  const body = Buffer.concat(contents);
  return Buffer.concat([Buffer.from([tag]), encodeLength(body.length), body]);
}

export const sequence = (...items: Buffer[]) => tlv(0x30, ...items);
export const set = (...items: Buffer[]) => tlv(0x31, ...items);
export const octetString = (value: Buffer) => tlv(0x04, value);
export const utf8String = (value: string) => tlv(0x0c, Buffer.from(value, "utf8"));
export function printableString(value: string) {
  if (!/^[A-Za-z0-9 '()+,./:=?-]*$/.test(value)) throw new DerError("Invalid PrintableString character.");
  return tlv(0x13, Buffer.from(value, "ascii"));
}
export const booleanTrue = () => tlv(0x01, Buffer.from([0xff]));
/** `[n] EXPLICIT` (constructed context-specific). */
export const explicit = (tagNumber: number, value: Buffer) => tlv(0xa0 | tagNumber, value);
/** A BIT STRING whose content is whole bytes. */
export const bitString = (value: Buffer, unusedBits = 0) => tlv(0x03, Buffer.from([unusedBits]), value);

/** A non-negative INTEGER from big-endian magnitude bytes. */
export function integerFromBytes(magnitude: Buffer) {
  let start = 0;
  while (start < magnitude.length - 1 && magnitude[start] === 0) start += 1;
  const trimmed = magnitude.subarray(start);
  const body = trimmed[0]! & 0x80 ? Buffer.concat([Buffer.from([0]), trimmed]) : trimmed;
  return tlv(0x02, body);
}

export function integer(value: number | bigint) {
  let hex = BigInt(value).toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return integerFromBytes(Buffer.from(hex, "hex"));
}

export function enumerated(value: number) {
  const encoded = integer(value);
  encoded[0] = 0x0a;
  return encoded;
}

export function oid(dotted: string) {
  const parts = dotted.split(".").map((part) => BigInt(part));
  const bytes: number[] = [];
  const first = parts[0]! * 40n + parts[1]!;
  for (const arc of [first, ...parts.slice(2)]) {
    const chunk: number[] = [Number(arc & 0x7fn)];
    for (let rest = arc >> 7n; rest > 0n; rest >>= 7n) chunk.unshift(Number((rest & 0x7fn) | 0x80n));
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
}

/** RFC 5280 §4.1.2.5: UTCTime through 2049, GeneralizedTime from 2050. Always whole seconds, Z. */
export function time(date: Date) {
  const iso = date.toISOString(); // 2026-11-16T19:32:11.000Z
  const digits = `${iso.slice(0, 4)}${iso.slice(5, 7)}${iso.slice(8, 10)}${iso.slice(11, 13)}${iso.slice(14, 16)}${iso.slice(17, 19)}Z`;
  const year = date.getUTCFullYear();
  if (year >= 1950 && year < 2050) return tlv(0x17, Buffer.from(digits.slice(2), "ascii"));
  return tlv(0x18, Buffer.from(digits, "ascii"));
}

export type NameAttribute = { type: "CN" | "O" | "serialNumber"; value: string };

export function name(attributes: NameAttribute[]) {
  return sequence(
    ...attributes.map((attribute) => {
      const value =
        attribute.type === "serialNumber" ? printableString(attribute.value) : utf8String(attribute.value);
      const type =
        attribute.type === "CN"
          ? OID.commonName
          : attribute.type === "O"
            ? OID.organizationName
            : OID.serialNumber;
      return set(sequence(oid(type), value));
    }),
  );
}

export function extension(id: string, critical: boolean, value: Buffer) {
  return critical
    ? sequence(oid(id), booleanTrue(), octetString(value))
    : sequence(oid(id), octetString(value));
}

/** KeyUsage named bits (RFC 5280 §4.2.1.3), DER-encoded with trailing zero bits removed. */
export const KEY_USAGE_BITS = {
  digitalSignature: 0,
  nonRepudiation: 1,
  keyEncipherment: 2,
  dataEncipherment: 3,
  keyAgreement: 4,
  keyCertSign: 5,
  cRLSign: 6,
  encipherOnly: 7,
  decipherOnly: 8,
} as const;
export type KeyUsage = keyof typeof KEY_USAGE_BITS;

export function keyUsageValue(usages: KeyUsage[]) {
  const highest = Math.max(...usages.map((usage) => KEY_USAGE_BITS[usage]));
  const bytes = Buffer.alloc(Math.floor(highest / 8) + 1);
  for (const usage of usages) {
    const bit = KEY_USAGE_BITS[usage];
    const index = Math.floor(bit / 8);
    bytes[index] = (bytes[index] ?? 0) | (0x80 >> (bit % 8));
  }
  const last = bytes[bytes.length - 1]!;
  let unused = 0;
  while (unused < 7 && !(last & (1 << unused))) unused += 1;
  return bitString(bytes, unused);
}

export function basicConstraintsValue(ca: boolean, pathLength?: number) {
  if (!ca) return sequence();
  return pathLength === undefined ? sequence(booleanTrue()) : sequence(booleanTrue(), integer(pathLength));
}

export const extendedKeyUsageValue = (purposes: string[]) => sequence(...purposes.map(oid));
export const subjectKeyIdentifierValue = (keyId: Buffer) => octetString(keyId);
/** AuthorityKeyIdentifier with only `[0] IMPLICIT keyIdentifier`. */
export const authorityKeyIdentifierValue = (keyId: Buffer) => sequence(tlv(0x80, keyId));

// ---- Decoder -----------------------------------------------------------------------------------

export type Node = {
  tag: number;
  /** The whole encoding, header included. */
  raw: Buffer;
  content: Buffer;
};

/**
 * Every decoding failure. Parsing is iterative and schema-driven (no generic recursion), every
 * length is bounded by the input, and the caps below bound the work any single value can cause,
 * so hostile input is rejected in time and memory linear in its size (FD-17 CSR hardening).
 */
export class DerError extends Error {
  override name = "DerError";
}

/** OBJECT IDENTIFIER contents longer than this are refused (real OIDs are well under 40 bytes). */
export const MAX_OID_BYTES = 64;
/** INTEGERs Ark reads as numbers (versions, path lengths, CRL numbers) fit in 20 bytes (RFC 5280). */
export const MAX_SMALL_INTEGER_BYTES = 20;
/** More extensions than this in one certificate or request is refused. */
export const MAX_EXTENSIONS = 32;

export function readNode(buffer: Buffer, offset = 0): Node {
  if (!Number.isInteger(offset) || offset < 0) throw new DerError("Invalid DER offset.");
  if (offset + 2 > buffer.length) throw new DerError("Truncated DER header.");
  const tag = buffer[offset]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError("Multi-byte DER tags are not supported.");
  if (tag === 0x00) throw new DerError("End-of-contents octets are not DER.");
  let length = buffer[offset + 1]!;
  let header = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0) throw new DerError("Indefinite lengths are not DER.");
    if (count > 4) throw new DerError("DER length is too large.");
    if (offset + 2 + count > buffer.length) throw new DerError("Truncated DER length.");
    length = 0;
    for (let index = 0; index < count; index += 1) length = length * 256 + buffer[offset + 2 + index]!;
    if (length < 0x80 || buffer[offset + 2] === 0) throw new DerError("Non-minimal DER length.");
    header += count;
  }
  const end = offset + header + length;
  if (end > buffer.length) throw new DerError("DER value runs past the end of its container.");
  return { tag, raw: buffer.subarray(offset, end), content: buffer.subarray(offset + header, end) };
}

/** Decode exactly one value occupying the whole buffer. */
export function decode(buffer: Buffer) {
  const node = readNode(buffer);
  if (node.raw.length !== buffer.length) throw new DerError("Trailing data after DER value.");
  return node;
}

export function children(node: Node | undefined) {
  if (!node || !(node.tag & 0x20)) throw new DerError("Expected a constructed DER value.");
  const items: Node[] = [];
  for (let offset = 0; offset < node.content.length;) {
    const child = readNode(node.content, offset);
    items.push(child);
    offset += child.raw.length;
  }
  return items;
}

/** "a CSR version" -> "CSR version", for messages that start with an adjective. */
const noun = (what: string) => what.replace(/^(?:a|an) /, "");

export function expectTag(node: Node | undefined, tag: number, what: string): Node {
  if (!node || node.tag !== tag) throw new DerError(`Expected ${what}.`);
  return node;
}

/** A DER BOOLEAN: exactly one byte, 0x00 or 0xFF. */
export function decodeBoolean(node: Node | undefined, what = "a BOOLEAN") {
  expectTag(node, 0x01, what);
  if (node!.content.length !== 1 || (node!.content[0] !== 0x00 && node!.content[0] !== 0xff))
    throw new DerError(`Malformed ${noun(what)}.`);
  return node!.content[0] === 0xff;
}

/**
 * A minimally encoded INTEGER of at most `maxBytes` content bytes. `nonNegative` refuses values
 * with the sign bit set.
 */
export function decodeInteger(
  node: Node | undefined,
  what = "an INTEGER",
  options: { maxBytes?: number; nonNegative?: boolean } = {},
) {
  expectTag(node, 0x02, what);
  const content = node!.content;
  if (!content.length) throw new DerError(`Empty ${noun(what)}.`);
  if (content.length > (options.maxBytes ?? MAX_SMALL_INTEGER_BYTES))
    throw new DerError(`Oversized ${noun(what)}.`);
  if (
    content.length > 1 &&
    ((content[0] === 0x00 && !(content[1]! & 0x80)) || (content[0] === 0xff && content[1]! & 0x80))
  )
    throw new DerError(`Non-minimal ${noun(what)}.`);
  const negative = (content[0]! & 0x80) !== 0;
  if (negative && options.nonNegative) throw new DerError(`Negative ${noun(what)}.`);
  let value = BigInt(`0x${content.toString("hex")}`);
  if (negative) value -= 1n << BigInt(content.length * 8);
  return value;
}

/** A DER BIT STRING: unused-bit count 0-7, zero when empty, and zero padding bits. */
export function decodeBitString(node: Node | undefined, what = "a BIT STRING") {
  expectTag(node, 0x03, what);
  const content = node!.content;
  if (!content.length) throw new DerError(`Empty ${noun(what)}.`);
  const unused = content[0]!;
  if (unused > 7 || (content.length === 1 && unused !== 0)) throw new DerError(`Malformed ${noun(what)}.`);
  if (unused && content[content.length - 1]! & ((1 << unused) - 1))
    throw new DerError(`Non-zero padding bits in ${noun(what)}.`);
  return { unused, bytes: content.subarray(1) };
}

export function decodeOid(node: Node | undefined) {
  expectTag(node, 0x06, "an OBJECT IDENTIFIER");
  const content = node!.content;
  if (!content.length) throw new DerError("Empty OBJECT IDENTIFIER.");
  if (content.length > MAX_OID_BYTES) throw new DerError("Oversized OBJECT IDENTIFIER.");
  if (content[content.length - 1]! & 0x80) throw new DerError("Truncated OBJECT IDENTIFIER arc.");
  const arcs: bigint[] = [];
  let value = 0n;
  let start = true;
  for (const byte of content) {
    if (start && byte === 0x80) throw new DerError("Non-minimal OBJECT IDENTIFIER arc.");
    value = (value << 7n) | BigInt(byte & 0x7f);
    start = !(byte & 0x80);
    if (start) {
      arcs.push(value);
      value = 0n;
    }
  }
  const first = arcs[0]!;
  const head = first < 40n ? [0n, first] : first < 80n ? [1n, first - 40n] : [2n, first - 80n];
  return [...head, ...arcs.slice(1)].join(".");
}

export function decodeTime(node: Node | undefined) {
  const text = node?.content.toString("latin1") ?? "";
  const match =
    node?.tag === 0x17
      ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text)
      : node?.tag === 0x18
        ? /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text)
        : null;
  if (!match || match[0] !== text) throw new DerError("Expected a UTCTime or GeneralizedTime.");
  const year = node?.tag === 0x17 ? `${Number(match[1]) >= 50 ? "19" : "20"}${match[1]}` : match[1];
  const iso = `${year}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}.000Z`;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime()) || date.toISOString() !== iso) throw new DerError("Invalid DER time.");
  return date;
}

/** Canonical serial text: uppercase hex of the integer magnitude, as `openssl x509 -serial` prints. */
export function serialHex(node: Node | undefined) {
  const serial = expectTag(node, 0x02, "an INTEGER serial");
  decodeInteger(serial, "a serial number", { nonNegative: true });
  const start = serial.content.length > 1 && serial.content[0] === 0 ? 1 : 0;
  return serial.content.subarray(start).toString("hex").toUpperCase();
}

// ---- PEM ---------------------------------------------------------------------------------------

export function toPem(label: string, der: Buffer) {
  const body = der
    .toString("base64")
    .replace(/(.{64})/g, "$1\n")
    .replace(/\n$/, "");
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

/**
 * Decode exactly one PEM block with one of `labels` (RFC 7468 strict form). Only whitespace may
 * surround the block; the body must be canonical base64 with padding only at the end. A lenient
 * decoder would silently skip junk, so anything else is refused rather than guessed at.
 */
export function fromPem(pem: string, labels: string[]) {
  if (typeof pem !== "string") throw new DerError(`Expected a PEM ${labels.join(" or ")}.`);
  const match =
    /^\s*-----BEGIN ([A-Z0-9 ]{1,40})-----\r?\n([A-Za-z0-9+/=\r\n\t ]*?)-----END \1-----\s*$/.exec(pem);
  if (!match) {
    if ((pem.match(/-----BEGIN /g) ?? []).length > 1) throw new DerError("Expected exactly one PEM block.");
    throw new DerError(`Expected a PEM ${labels.join(" or ")}.`);
  }
  if (!labels.includes(match[1]!)) throw new DerError(`Expected a PEM ${labels.join(" or ")}.`);
  const body = match[2]!.replace(/\s+/g, "");
  if (!body || !/^[A-Za-z0-9+/]*={0,2}$/.test(body) || body.length % 4 !== 0)
    throw new DerError("The PEM body is not canonical base64.");
  const der = Buffer.from(body, "base64");
  if (der.toString("base64") !== body) throw new DerError("The PEM body is not canonical base64.");
  return der;
}

// ---- Keys, signatures, structure helpers --------------------------------------------------------

/** The DER SubjectPublicKeyInfo of a public (or private) key, re-exported canonically. */
export function spkiDer(key: KeyObject) {
  // Bun's createPublicKey rejects a KeyObject that is already public, so only derive from private.
  return (key.type === "public" ? key : createPublicKey(key)).export({ type: "spki", format: "der" });
}

/** RFC 7093 §2 method 1: leftmost 160 bits of SHA-256 over the subjectPublicKey BIT STRING value. */
export function keyIdentifier(spki: Buffer) {
  const parts = children(decode(spki));
  const subjectPublicKey = decodeBitString(parts[1], "a subjectPublicKey BIT STRING");
  return createHash("sha256").update(subjectPublicKey.bytes).digest().subarray(0, 20);
}

/** ecdsa-with-SHA256: the AlgorithmIdentifier has no parameters (RFC 5758 §3.2). */
export const ecdsaWithSha256 = () => sequence(oid(OID.ecdsaWithSha256));

/** Sign a TBS structure with an ECDSA key and wrap it as Certificate, CertificateList or similar. */
export function signStructure(tbs: Buffer, issuerKey: KeyObject) {
  if (issuerKey.asymmetricKeyType !== "ec") throw new Error("Issuer keys must be ECDSA.");
  const signature = sign("sha256", tbs, { key: issuerKey, dsaEncoding: "der" });
  return sequence(tbs, ecdsaWithSha256(), bitString(signature));
}

export function sha256Hex(der: Buffer) {
  return createHash("sha256").update(der).digest("hex");
}

export type ParsedExtension = { id: string; critical: boolean; value: Buffer };

export function parseExtensions(node: Node | undefined): ParsedExtension[] {
  const items = children(expectTag(node, 0x30, "an Extensions SEQUENCE"));
  // RFC 5280: Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension.
  if (!items.length) throw new DerError("Empty Extensions SEQUENCE.");
  if (items.length > MAX_EXTENSIONS) throw new DerError("Too many extensions.");
  return items.map((item) => {
    const parts = children(expectTag(item, 0x30, "an Extension"));
    const id = decodeOid(parts[0]);
    let index = 1;
    let critical = false;
    if (parts[index]?.tag === 0x01) {
      critical = decodeBoolean(parts[index], "an Extension critical flag");
      if (!critical) throw new DerError("The default Extension critical flag must be omitted.");
      index += 1;
    }
    const value = expectTag(parts[index], 0x04, "an extnValue OCTET STRING").content;
    if (parts.length !== index + 1) throw new DerError("Malformed Extension.");
    return { id, critical, value: Buffer.from(value) };
  });
}

/** The named bits set in a DER KeyUsage BIT STRING. */
export function decodeKeyUsage(value: Buffer): KeyUsage[] {
  const { bytes, unused } = decodeBitString(decode(value), "a KeyUsage BIT STRING");
  if (bytes.length > 2) throw new DerError("Oversized KeyUsage BIT STRING.");
  if (bytes.length * 8 - unused > 9) throw new DerError("Unknown KeyUsage bits.");
  if (!bytes.length || !(bytes[bytes.length - 1]! & (1 << unused)))
    throw new DerError("Non-minimal KeyUsage BIT STRING.");
  return (Object.entries(KEY_USAGE_BITS) as [KeyUsage, number][])
    .filter(([, bit]) => ((bytes[Math.floor(bit / 8)] ?? 0) & (0x80 >> (bit % 8))) !== 0)
    .map(([usage]) => usage);
}

export function decodeBasicConstraints(value: Buffer) {
  const parts = children(expectTag(decode(value), 0x30, "a BasicConstraints SEQUENCE"));
  let index = 0;
  let ca = false;
  if (parts[index]?.tag === 0x01) {
    ca = decodeBoolean(parts[index], "a BasicConstraints cA flag");
    if (!ca) throw new DerError("The default BasicConstraints cA flag must be omitted.");
    index += 1;
  }
  let pathLength: number | undefined;
  if (parts[index]?.tag === 0x02) {
    const length = decodeInteger(parts[index], "a pathLenConstraint", { maxBytes: 4, nonNegative: true });
    if (!ca) throw new DerError("BasicConstraints pathLenConstraint requires cA.");
    pathLength = Number(length);
    index += 1;
  }
  if (parts.length !== index) throw new DerError("Malformed BasicConstraints.");
  return { ca, pathLength };
}

export function decodeExtendedKeyUsage(value: Buffer) {
  const purposes = children(expectTag(decode(value), 0x30, "an ExtKeyUsageSyntax SEQUENCE"));
  if (!purposes.length) throw new DerError("Empty ExtKeyUsageSyntax.");
  if (purposes.length > MAX_EXTENSIONS) throw new DerError("Too many extended key usages.");
  return purposes.map((purpose) => decodeOid(purpose));
}

export function decodeSubjectKeyIdentifier(value: Buffer) {
  return Buffer.from(expectTag(decode(value), 0x04, "a KeyIdentifier OCTET STRING").content);
}

export function decodeAuthorityKeyIdentifier(value: Buffer) {
  const keyId = children(expectTag(decode(value), 0x30, "an AuthorityKeyIdentifier")).find(
    (part) => part.tag === 0x80,
  );
  return keyId ? Buffer.from(keyId.content) : null;
}

function parseExplicitExtensions(wrapper: Node) {
  const fields = children(wrapper);
  if (fields.length !== 1) throw new DerError("Malformed extensions wrapper.");
  return parseExtensions(fields[0]);
}

/** The parts of a DER certificate the PKI module and its tests need. */
export function parseCertificate(der: Buffer) {
  const parts = children(expectTag(decode(der), 0x30, "a Certificate"));
  if (parts.length !== 3) throw new DerError("Malformed Certificate.");
  const [tbs, algorithm, signature] = parts;
  const certificate = expectTag(tbs, 0x30, "a TBSCertificate");
  const fields = children(certificate);
  let index = 0;
  let version = 1;
  if (fields[0]?.tag === 0xa0) {
    const versionFields = children(fields[0]);
    if (versionFields.length !== 1) throw new DerError("Malformed certificate version.");
    version = Number(decodeInteger(versionFields[0], "a certificate version", { maxBytes: 1 })) + 1;
    index = 1;
  }
  const serial = serialHex(fields[index++]);
  expectTag(fields[index++], 0x30, "a TBSCertificate signature AlgorithmIdentifier");
  const issuer = expectTag(fields[index++], 0x30, "an issuer Name");
  const validity = children(expectTag(fields[index++], 0x30, "a Validity"));
  if (validity.length !== 2) throw new DerError("Malformed certificate Validity.");
  const [notBefore, notAfter] = validity;
  const subject = expectTag(fields[index++], 0x30, "a subject Name");
  const spki = expectTag(fields[index++], 0x30, "a SubjectPublicKeyInfo");
  if (fields[index]?.tag === 0x81) index += 1; // issuerUniqueID
  if (fields[index]?.tag === 0x82) index += 1; // subjectUniqueID
  const extensions = fields[index]?.tag === 0xa3 ? parseExplicitExtensions(fields[index++]!) : [];
  if (index !== fields.length) throw new DerError("Unexpected TBSCertificate field.");
  return {
    version,
    serial,
    issuerDer: Buffer.from(issuer.raw),
    subjectDer: Buffer.from(subject.raw),
    notBefore: decodeTime(notBefore),
    notAfter: decodeTime(notAfter),
    spki: Buffer.from(spki.raw),
    extensions,
    tbs: Buffer.from(certificate.raw),
    signatureAlgorithm: decodeOid(children(expectTag(algorithm, 0x30, "a signature AlgorithmIdentifier"))[0]),
    signature: Buffer.from(decodeBitString(signature, "a signature BIT STRING").bytes),
  };
}

export type ParsedCertificate = ReturnType<typeof parseCertificate>;

/** The parts of a DER CRL the PKI module and its tests need. */
export function parseCrl(der: Buffer) {
  const parts = children(expectTag(decode(der), 0x30, "a CertificateList"));
  if (parts.length !== 3) throw new DerError("Malformed CertificateList.");
  const [tbs, algorithm, signature] = parts;
  const certList = expectTag(tbs, 0x30, "a TBSCertList");
  const fields = children(certList);
  let index = fields[0]?.tag === 0x02 ? 1 : 0;
  expectTag(fields[index++], 0x30, "a TBSCertList signature AlgorithmIdentifier");
  const issuer = expectTag(fields[index++], 0x30, "an issuer Name");
  const thisUpdate = decodeTime(fields[index++]);
  const nextUpdate =
    fields[index] && [0x17, 0x18].includes(fields[index]!.tag) ? decodeTime(fields[index++]) : null;
  const revoked =
    fields[index]?.tag === 0x30
      ? children(fields[index++]!).map((entry) => {
          const entryFields = children(expectTag(entry, 0x30, "a revoked certificate entry SEQUENCE"));
          if (entryFields.length > 3) throw new DerError("Unexpected revoked certificate entry field.");
          const [serial, revokedAt, entryExtensions] = entryFields;
          const reason = entryExtensions
            ? parseExtensions(entryExtensions).find((item) => item.id === OID.crlReason)
            : undefined;
          return {
            serial: serialHex(serial),
            revokedAt: decodeTime(revokedAt),
            reasonCode: reason ? (decode(reason.value).content[0] ?? 0) : null,
          };
        })
      : [];
  const extensions = fields[index]?.tag === 0xa0 ? parseExplicitExtensions(fields[index++]!) : [];
  if (index !== fields.length) throw new DerError("Unexpected TBSCertList field.");
  const numberExtension = extensions.find((item) => item.id === OID.crlNumber);
  const crlNumber = numberExtension
    ? decodeInteger(decode(numberExtension.value), "a CRLNumber", { nonNegative: true })
    : null;
  return {
    issuerDer: Buffer.from(issuer.raw),
    thisUpdate,
    nextUpdate,
    revoked,
    extensions,
    crlNumber,
    tbs: Buffer.from(certList.raw),
    signatureAlgorithm: decodeOid(children(expectTag(algorithm, 0x30, "a signature AlgorithmIdentifier"))[0]),
    signature: Buffer.from(decodeBitString(signature, "a signature BIT STRING").bytes),
  };
}
