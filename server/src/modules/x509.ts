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
export const printableString = (value: string) => tlv(0x13, Buffer.from(value, "ascii"));
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

export class DerError extends Error {}

export function readNode(buffer: Buffer, offset = 0): Node {
  if (offset + 2 > buffer.length) throw new DerError("Truncated DER header.");
  const tag = buffer[offset]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError("Multi-byte DER tags are not supported.");
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

export function children(node: Node) {
  const items: Node[] = [];
  for (let offset = 0; offset < node.content.length;) {
    const child = readNode(node.content, offset);
    items.push(child);
    offset += child.raw.length;
  }
  return items;
}

export function expectTag(node: Node | undefined, tag: number, what: string): Node {
  if (!node || node.tag !== tag) throw new DerError(`Expected ${what}.`);
  return node;
}

export function decodeOid(node: Node) {
  expectTag(node, 0x06, "an OBJECT IDENTIFIER");
  const arcs: bigint[] = [];
  let value = 0n;
  for (const byte of node.content) {
    value = (value << 7n) | BigInt(byte & 0x7f);
    if (!(byte & 0x80)) {
      arcs.push(value);
      value = 0n;
    }
  }
  if (!arcs.length) throw new DerError("Empty OBJECT IDENTIFIER.");
  const first = arcs[0]!;
  const head = first < 40n ? [0n, first] : first < 80n ? [1n, first - 40n] : [2n, first - 80n];
  return [...head, ...arcs.slice(1)].join(".");
}

export function decodeTime(node: Node) {
  const text = node.content.toString("ascii");
  const match =
    node.tag === 0x17
      ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text)
      : node.tag === 0x18
        ? /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text)
        : null;
  if (!match) throw new DerError("Expected a UTCTime or GeneralizedTime.");
  let year = Number(match[1]);
  if (node.tag === 0x17) year += year >= 50 ? 1900 : 2000;
  return new Date(
    Date.UTC(
      year,
      Number(match[2]) - 1,
      Number(match[3]),
      Number(match[4]),
      Number(match[5]),
      Number(match[6]),
    ),
  );
}

/** Canonical serial text: uppercase hex of the integer magnitude, as `openssl x509 -serial` prints. */
export function serialHex(node: Node) {
  expectTag(node, 0x02, "an INTEGER serial");
  let start = 0;
  while (start < node.content.length - 1 && node.content[start] === 0) start += 1;
  return node.content.subarray(start).toString("hex").toUpperCase();
}

// ---- PEM ---------------------------------------------------------------------------------------

export function toPem(label: string, der: Buffer) {
  const body = der
    .toString("base64")
    .replace(/(.{64})/g, "$1\n")
    .replace(/\n$/, "");
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

export function fromPem(pem: string, labels: string[]) {
  const match = /-----BEGIN ([A-Z0-9 ]+)-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END \1-----/.exec(pem);
  if (!match || !labels.includes(match[1]!)) throw new DerError(`Expected a PEM ${labels.join(" or ")}.`);
  const rest = pem.slice((match.index ?? 0) + match[0].length).trim();
  if (rest) throw new DerError("Expected exactly one PEM block.");
  return Buffer.from(match[2]!.replace(/\s+/g, ""), "base64");
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
  const subjectPublicKey = expectTag(parts[1], 0x03, "a subjectPublicKey BIT STRING");
  return createHash("sha256").update(subjectPublicKey.content.subarray(1)).digest().subarray(0, 20);
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

export function parseExtensions(node: Node): ParsedExtension[] {
  expectTag(node, 0x30, "an Extensions SEQUENCE");
  return children(node).map((item) => {
    const parts = children(expectTag(item, 0x30, "an Extension"));
    const id = decodeOid(parts[0]!);
    let index = 1;
    let critical = false;
    if (parts[index]?.tag === 0x01) {
      critical = parts[index]!.content[0] !== 0;
      index += 1;
    }
    const value = expectTag(parts[index], 0x04, "an extnValue OCTET STRING").content;
    if (parts.length !== index + 1) throw new DerError("Malformed Extension.");
    return { id, critical, value: Buffer.from(value) };
  });
}

/** The named bits set in a DER KeyUsage BIT STRING. */
export function decodeKeyUsage(value: Buffer): KeyUsage[] {
  const node = expectTag(decode(value), 0x03, "a KeyUsage BIT STRING");
  const bytes = node.content.subarray(1);
  return (Object.entries(KEY_USAGE_BITS) as [KeyUsage, number][])
    .filter(([, bit]) => ((bytes[Math.floor(bit / 8)] ?? 0) & (0x80 >> (bit % 8))) !== 0)
    .map(([usage]) => usage);
}

export function decodeBasicConstraints(value: Buffer) {
  const parts = children(expectTag(decode(value), 0x30, "a BasicConstraints SEQUENCE"));
  let index = 0;
  let ca = false;
  if (parts[index]?.tag === 0x01) {
    ca = parts[index]!.content[0] !== 0;
    index += 1;
  }
  const pathLength =
    parts[index]?.tag === 0x02 ? Number(BigInt(`0x${parts[index]!.content.toString("hex")}`)) : undefined;
  return { ca, pathLength };
}

export function decodeExtendedKeyUsage(value: Buffer) {
  return children(expectTag(decode(value), 0x30, "an ExtKeyUsageSyntax SEQUENCE")).map(decodeOid);
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

/** The parts of a DER certificate the PKI module and its tests need. */
export function parseCertificate(der: Buffer) {
  const [tbs, algorithm, signature] = children(expectTag(decode(der), 0x30, "a Certificate"));
  const fields = children(expectTag(tbs, 0x30, "a TBSCertificate"));
  let index = 0;
  let version = 1;
  if (fields[0]?.tag === 0xa0) {
    version = Number(children(fields[0])[0]!.content[0]) + 1;
    index = 1;
  }
  const serial = serialHex(fields[index]!);
  const issuer = fields[index + 2]!;
  const [notBefore, notAfter] = children(expectTag(fields[index + 3], 0x30, "a Validity"));
  const subject = fields[index + 4]!;
  const spki = expectTag(fields[index + 5], 0x30, "a SubjectPublicKeyInfo");
  const extensionsWrapper = fields.slice(index + 6).find((field) => field.tag === 0xa3);
  const extensions = extensionsWrapper ? parseExtensions(children(extensionsWrapper)[0]!) : [];
  return {
    version,
    serial,
    issuerDer: Buffer.from(issuer.raw),
    subjectDer: Buffer.from(subject.raw),
    notBefore: decodeTime(notBefore!),
    notAfter: decodeTime(notAfter!),
    spki: Buffer.from(spki.raw),
    extensions,
    tbs: Buffer.from(tbs!.raw),
    signatureAlgorithm: decodeOid(children(algorithm!)[0]!),
    signature: Buffer.from(expectTag(signature, 0x03, "a signature BIT STRING").content.subarray(1)),
  };
}

export type ParsedCertificate = ReturnType<typeof parseCertificate>;

/** The parts of a DER CRL the PKI module and its tests need. */
export function parseCrl(der: Buffer) {
  const [tbs, algorithm, signature] = children(expectTag(decode(der), 0x30, "a CertificateList"));
  const fields = children(expectTag(tbs, 0x30, "a TBSCertList"));
  let index = fields[0]?.tag === 0x02 ? 1 : 0;
  index += 1; // signature AlgorithmIdentifier
  const issuer = fields[index++]!;
  const thisUpdate = decodeTime(fields[index++]!);
  const nextUpdate =
    fields[index] && [0x17, 0x18].includes(fields[index]!.tag) ? decodeTime(fields[index++]!) : null;
  const revoked =
    fields[index]?.tag === 0x30
      ? children(fields[index++]!).map((entry) => {
          const [serial, revokedAt, entryExtensions] = children(entry);
          const reason = entryExtensions
            ? parseExtensions(entryExtensions).find((item) => item.id === OID.crlReason)
            : undefined;
          return {
            serial: serialHex(serial!),
            revokedAt: decodeTime(revokedAt!),
            reasonCode: reason ? (decode(reason.value).content[0] ?? 0) : null,
          };
        })
      : [];
  const extensionsWrapper = fields[index]?.tag === 0xa0 ? fields[index] : undefined;
  const extensions = extensionsWrapper ? parseExtensions(children(extensionsWrapper)[0]!) : [];
  const numberExtension = extensions.find((item) => item.id === OID.crlNumber);
  const crlNumber = numberExtension
    ? BigInt(
        `0x${expectTag(decode(numberExtension.value), 0x02, "a CRLNumber").content.toString("hex") || "0"}`,
      )
    : null;
  return {
    issuerDer: Buffer.from(issuer.raw),
    thisUpdate,
    nextUpdate,
    revoked,
    extensions,
    crlNumber,
    tbs: Buffer.from(tbs!.raw),
    signatureAlgorithm: decodeOid(children(algorithm!)[0]!),
    signature: Buffer.from(expectTag(signature, 0x03, "a signature BIT STRING").content.subarray(1)),
  };
}
