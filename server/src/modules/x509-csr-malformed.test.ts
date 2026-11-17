// Malformed-input suite for CSR parsing (x509.ts + pki.validateCsr), ticket FD-17.
//
// CSR submission is the first API surface that feeds attacker-chosen DER to the hand-written
// decoder. Every case here must be refused with the typed `CsrError` (never a crash, never a
// generic fallback), within a fixed time bound, and without unbounded memory growth. Many cases
// put one bad element inside an otherwise valid request that is correctly re-signed, so the
// structural checks themselves are exercised, not only the signature check.
//
// The suite prints a summary (case count per category, slowest case) for the PR record.

import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";

import {
  buildCsr,
  extensionRequest,
  headerOffsets,
  loadCorpus,
  rawOid,
  rawTlv,
  toCsrPem,
} from "./csr-test-kit.ts";

process.env.DATABASE_URL ??= "postgres://unused:unused@127.0.0.1:9/unused";
const pki = await import("./pki.ts");
const x509 = await import("./x509.ts");

/** Every case must be refused within this bound (milliseconds). */
const CASE_BOUND_MS = 250;
/** Heap growth allowed across the whole suite after a forced collection. */
const HEAP_BOUND_BYTES = 64 * 1024 * 1024;

type Case = { category: string; name: string; input: unknown; expect?: RegExp };

const ec256 = generateKeyPairSync("ec", { namedCurve: "P-256" });
const ec256b = generateKeyPairSync("ec", { namedCurve: "P-256" });
const ec384 = generateKeyPairSync("ec", { namedCurve: "P-384" });
const ec521 = generateKeyPairSync("ec", { namedCurve: "P-521" });
const ed = generateKeyPairSync("ed25519");
const rsa3072 = generateKeyPairSync("rsa", { modulusLength: 3072 });
const rsa2048 = generateKeyPairSync("rsa", { modulusLength: 2048 });
const corpus = loadCorpus();
const base = corpus.find((item) => item.name === "p256-extensions.csr")!;

const ext = (id: string, critical: boolean, value: Buffer) => x509.extension(id, critical, value);
const keyUsageExt = ext(x509.OID.keyUsage, true, x509.keyUsageValue(["digitalSignature"]));
const signed = (parts: Omit<Parameters<typeof buildCsr>[0], "key"> & { key?: KeyObject }) =>
  buildCsr({ key: ec256.privateKey, ...parts }).pem;
const withExtensions = (...extensions: Buffer[]) => signed({ attributes: [extensionRequest(extensions)] });

function nested(depth: number, leaf: Buffer) {
  let value = leaf;
  for (let level = 0; level < depth; level++) value = x509.sequence(value);
  return value;
}

function rsaSpki(modulus: Buffer, exponent: Buffer) {
  return x509.sequence(
    x509.sequence(x509.oid(x509.OID.rsaEncryption), x509.tlv(0x05)),
    x509.bitString(x509.sequence(x509.integerFromBytes(modulus), x509.integerFromBytes(exponent))),
  );
}

function oddModulus(bits: number) {
  const bytes = randomBytes(bits / 8);
  bytes[0] = bytes[0]! | 0x80;
  bytes[bytes.length - 1] = bytes[bytes.length - 1]! | 0x01;
  return bytes;
}

/** P-256 SPKI with the point in compressed form (valid, but not Ark's canonical encoding). */
function compressedSpki(key: KeyObject) {
  const jwk = key.export({ format: "jwk" }) as { x: string; y: string };
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  const point = Buffer.concat([Buffer.from([y[y.length - 1]! & 1 ? 0x03 : 0x02]), x]);
  return x509.sequence(
    x509.sequence(x509.oid(x509.OID.ecPublicKey), x509.oid("1.2.840.10045.3.1.7")),
    x509.bitString(point),
  );
}

function withLength(der: Buffer, offset: number, delta: number) {
  const copy = Buffer.from(der);
  const length = copy[offset + 1]!;
  if (length & 0x80) {
    const count = length & 0x7f;
    let value = 0;
    for (let index = 0; index < count; index++) value = value * 256 + copy[offset + 2 + index]!;
    value = Math.max(0, value + delta);
    for (let index = count - 1; index >= 0; index--) {
      copy[offset + 2 + index] = value & 0xff;
      value = Math.floor(value / 256);
    }
  } else {
    copy[offset + 1] = Math.min(0x7f, Math.max(0, length + delta));
  }
  return copy;
}

function cases(): Case[] {
  const list: Case[] = [];
  const add = (category: string, name: string, input: unknown, expectMessage?: RegExp) =>
    list.push({ category, name, input, expect: expectMessage });
  const der = base.der;
  const headers = headerOffsets(der);

  // ---- truncated ---------------------------------------------------------------------------
  for (let length = 0; length < der.length; length++) {
    add("truncated", `DER prefix ${length}/${der.length}`, toCsrPem(der.subarray(0, length)));
  }
  add("truncated", "PEM cut in half", base.pem.slice(0, Math.floor(base.pem.length / 2)));
  add("truncated", "PEM without END line", base.pem.replace(/-----END[^\n]*\n?$/, ""));
  add(
    "truncated",
    "PEM with an empty body",
    "-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----\n",
  );

  // ---- wrong lengths -----------------------------------------------------------------------
  for (const offset of headers) {
    for (const delta of [1, -1]) {
      const changed = withLength(der, offset, delta);
      // A zero length cannot shrink; skip the no-op rather than count it as a case.
      if (!changed.equals(der))
        add("bad length", `header @${offset} length ${delta > 0 ? "+" : ""}${delta}`, toCsrPem(changed));
    }
  }
  const body = der.subarray(der[1]! & 0x80 ? 2 + (der[1]! & 0x7f) : 2);
  add(
    "bad length",
    "4 GiB length claim",
    toCsrPem(rawTlv(0x30, [0x84, 0xff, 0xff, 0xff, 0xff], body)),
    /past the end/,
  );
  add("bad length", "5-byte length field", toCsrPem(rawTlv(0x30, [0x85, 0, 0, 0, 1, 0], body)), /too large/);
  add(
    "bad length",
    "non-minimal long form (0x81 for < 128)",
    toCsrPem(rawTlv(0x30, [0x81, 0x05], Buffer.alloc(5))),
    /Non-minimal/,
  );
  add(
    "bad length",
    "non-minimal long form (leading zero)",
    toCsrPem(rawTlv(0x30, [0x82, 0x00, body.length], body)),
    /Non-minimal/,
  );
  add("bad length", "zero-length outer SEQUENCE", toCsrPem(Buffer.from([0x30, 0x00])));

  // ---- indefinite length ---------------------------------------------------------------------
  add(
    "indefinite length",
    "outer SEQUENCE",
    toCsrPem(Buffer.concat([Buffer.from([0x30, 0x80]), body, Buffer.from([0, 0])])),
    /Indefinite/,
  );
  const info = x509.children(x509.decode(der))[0]!;
  const rest = der.subarray(der.length - (body.length - info.raw.length));
  const indefiniteInfo = Buffer.concat([Buffer.from([0x30, 0x80]), info.content, Buffer.from([0, 0]), rest]);
  add(
    "indefinite length",
    "CertificationRequestInfo",
    toCsrPem(x509.sequence(indefiniteInfo)),
    /Indefinite|End-of-contents/,
  );
  add(
    "indefinite length",
    "6000 nested indefinite SEQUENCEs",
    toCsrPem(Buffer.alloc(12_000, Buffer.from([0x30, 0x80]))),
    /Indefinite/,
  );
  add(
    "indefinite length",
    "end-of-contents tag as a field",
    toCsrPem(x509.sequence(Buffer.from([0x00, 0x00]), body)),
    /End-of-contents/,
  );

  // ---- deep nesting --------------------------------------------------------------------------
  let depth = 2900;
  let deep = nested(depth, x509.integer(0));
  while (toCsrPem(deep).length > pki.MAX_CSR_PEM_BYTES) deep = nested((depth -= 100), x509.integer(0));
  add("deep nesting", `${depth} nested SEQUENCEs as the whole request`, toCsrPem(deep));
  add(
    "deep nesting",
    "nested SEQUENCEs inside the subject (signed)",
    signed({
      subject: x509.sequence(x509.set(nested(400, x509.sequence(x509.oid("2.5.4.3"), x509.utf8String("x"))))),
    }),
    /AttributeTypeAndValue|subject/,
  );
  add(
    "deep nesting",
    "nested SEQUENCEs as a subject value (signed)",
    signed({
      subject: x509.sequence(x509.set(x509.sequence(x509.oid("2.5.4.3"), nested(400, x509.utf8String("x"))))),
    }),
    /subject string/,
  );
  add(
    "deep nesting",
    "nested SEQUENCEs as basicConstraints (signed)",
    withExtensions(ext(x509.OID.basicConstraints, true, nested(500, x509.sequence()))),
    /BasicConstraints/,
  );
  add(
    "deep nesting",
    "nested SEQUENCEs as an EKU purpose (signed)",
    withExtensions(
      ext(x509.OID.extendedKeyUsage, false, x509.sequence(nested(500, x509.oid(x509.OID.clientAuth)))),
    ),
    /OBJECT IDENTIFIER/,
  );
  add(
    "deep nesting",
    "nested SEQUENCEs as the attribute values (signed)",
    signed({ attributes: [x509.sequence(x509.oid(x509.OID.extensionRequest), nested(500, x509.set()))] }),
    /attribute value SET/,
  );
  add(
    "deep nesting",
    "nested SEQUENCEs as an attribute (signed)",
    signed({ attributes: [nested(300, x509.set())] }),
    /OBJECT IDENTIFIER/,
  );

  // ---- oversized -----------------------------------------------------------------------------
  add(
    "oversized",
    "PEM of 16 KiB + 1",
    `${base.pem}${" ".repeat(pki.MAX_CSR_PEM_BYTES + 1 - base.pem.length)}`,
    /larger than 16 KiB/,
  );
  add("oversized", "1 MiB PEM", toCsrPem(randomBytes(768 * 1024)), /larger than 16 KiB/);
  add(
    "oversized",
    "multi-byte UTF-8 over the byte cap",
    `${base.pem}${"€".repeat(6000)}`,
    /larger than 16 KiB/,
  );
  add(
    "oversized",
    "33 requested extensions (signed)",
    withExtensions(
      ...Array.from({ length: 33 }, (_, index) => ext(`1.3.6.1.4.1.55555.${index}`, false, x509.sequence())),
    ),
    /Too many extensions/,
  );
  add(
    "oversized",
    "5 attributes (signed)",
    signed({ attributes: Array.from({ length: 5 }, () => extensionRequest([keyUsageExt])) }),
    /too many attributes/,
  );
  add(
    "oversized",
    "17-component subject (signed)",
    signed({ subject: x509.name(Array.from({ length: 17 }, () => ({ type: "CN" as const, value: "x" }))) }),
    /too many components/,
  );
  add(
    "oversized",
    "9-attribute RDN (signed)",
    signed({
      subject: x509.sequence(
        x509.set(
          ...Array.from({ length: 9 }, () => x509.sequence(x509.oid("2.5.4.3"), x509.utf8String("x"))),
        ),
      ),
    }),
    /RelativeDistinguishedName/,
  );
  add(
    "oversized",
    "RSA 16 384-bit modulus",
    signed({ spki: rsaSpki(oddModulus(16_384), Buffer.from([1, 0, 1])) }),
    /at most 8192 bits|cannot be read/,
  );
  add(
    "oversized",
    "RSA 8 200-bit modulus",
    signed({ spki: rsaSpki(oddModulus(8_200), Buffer.from([1, 0, 1])) }),
    /at most 8192 bits|cannot be read/,
  );

  // ---- trailing data -------------------------------------------------------------------------
  add(
    "trailing data",
    "one byte after the DER",
    toCsrPem(Buffer.concat([der, Buffer.from([0])])),
    /Trailing data/,
  );
  add(
    "trailing data",
    "a NULL after the DER",
    toCsrPem(Buffer.concat([der, x509.tlv(0x05)])),
    /Trailing data/,
  );
  add("trailing data", "100 random bytes after the DER", toCsrPem(Buffer.concat([der, randomBytes(100)])));
  add(
    "trailing data",
    "an extra field in the outer SEQUENCE (signed)",
    buildCsr({ key: ec256.privateKey, outerTrailer: x509.tlv(0x05) }).pem,
    /Malformed CertificationRequest/,
  );
  add(
    "trailing data",
    "an extra field after the attributes (signed)",
    signed({ infoTrailer: x509.tlv(0x05) }),
    /CertificationRequestInfo/,
  );
  add(
    "trailing data",
    "an extra field in the SubjectPublicKeyInfo (signed)",
    signed({
      spki: x509.sequence(
        ...x509.children(x509.decode(x509.spkiDer(ec256.publicKey))).map((node) => node.raw),
        x509.tlv(0x05),
      ),
    }),
    /SubjectPublicKeyInfo/,
  );
  add(
    "trailing data",
    "an extra byte inside the EC point (signed)",
    signed({
      spki: x509.sequence(
        x509.sequence(x509.oid(x509.OID.ecPublicKey), x509.oid("1.2.840.10045.3.1.7")),
        x509.bitString(
          Buffer.concat([
            x509.decodeBitString(x509.children(x509.decode(x509.spkiDer(ec256.publicKey)))[1]).bytes,
            Buffer.from([0]),
          ]),
        ),
      ),
    }),
    /cannot be read|canonical/,
  );
  add(
    "trailing data",
    "an extra byte in an extension value (signed)",
    withExtensions(
      ext(
        x509.OID.keyUsage,
        true,
        Buffer.concat([x509.keyUsageValue(["digitalSignature"]), Buffer.from([0])]),
      ),
    ),
    /Trailing data/,
  );
  add(
    "trailing data",
    "NULL parameters on an ECDSA signature algorithm (signed)",
    signed({ signatureAlgorithm: x509.sequence(x509.oid(x509.OID.ecdsaWithSha256), x509.tlv(0x05)) }),
    /unexpected parameters/,
  );
  add("trailing data", "text after the PEM END line", `${base.pem}junk\n`, /Expected a PEM/);
  add("trailing data", "a second PEM block", `${base.pem}${base.pem}`, /exactly one PEM block/);

  // ---- unknown critical extensions -----------------------------------------------------------
  add(
    "unknown critical extension",
    "private-arc OID, critical",
    withExtensions(ext("1.3.6.1.4.1.99999.1", true, x509.sequence())),
    /1\.3\.6\.1\.4\.1\.99999\.1/,
  );
  add(
    "unknown critical extension",
    "private-arc OID, not critical",
    withExtensions(ext("1.3.6.1.4.1.99999.2", false, x509.sequence())),
    /99999\.2/,
  );
  add(
    "unknown critical extension",
    "nameConstraints, critical",
    withExtensions(ext("2.5.29.30", true, x509.sequence())),
    /2\.5\.29\.30/,
  );
  add(
    "unknown critical extension",
    "subjectAltName, critical",
    withExtensions(ext(x509.OID.subjectAltName, true, x509.sequence())),
    /2\.5\.29\.17/,
  );
  add(
    "unknown critical extension",
    "certificatePolicies",
    withExtensions(ext("2.5.29.32", false, x509.sequence())),
    /2\.5\.29\.32/,
  );
  add(
    "unknown critical extension",
    "a repeated keyUsage",
    withExtensions(keyUsageExt, keyUsageExt),
    /repeats extension/,
  );
  add(
    "unknown critical extension",
    "an empty extension request",
    signed({ attributes: [extensionRequest([])] }),
    /Empty Extensions/,
  );
  add(
    "unknown critical extension",
    "critical flag encoded as 0x01",
    withExtensions(
      Buffer.concat([
        x509.sequence(
          x509.oid(x509.OID.keyUsage),
          x509.tlv(0x01, Buffer.from([1])),
          x509.octetString(x509.keyUsageValue(["digitalSignature"])),
        ),
      ]),
    ),
    /critical flag/,
  );
  add(
    "unknown critical extension",
    "critical flag of two bytes",
    withExtensions(
      x509.sequence(
        x509.oid(x509.OID.keyUsage),
        x509.tlv(0x01, Buffer.from([0xff, 0xff])),
        x509.octetString(x509.keyUsageValue(["digitalSignature"])),
      ),
    ),
    /critical flag/,
  );
  add(
    "unknown critical extension",
    "challengePassword attribute",
    signed({
      attributes: [x509.sequence(x509.oid("1.2.840.113549.1.9.7"), x509.set(x509.utf8String("pw")))],
    }),
    /attribute 1\.2\.840\.113549\.1\.9\.7/,
  );
  add(
    "unknown critical extension",
    "two extension requests",
    signed({ attributes: [extensionRequest([keyUsageExt]), extensionRequest([keyUsageExt])] }),
    /repeats its extension request/,
  );
  add(
    "unknown critical extension",
    "a CA request",
    withExtensions(ext(x509.OID.basicConstraints, true, x509.basicConstraintsValue(true, 0))),
    /CA certificate/,
  );
  add(
    "unknown critical extension",
    "keyUsage with padding bits set",
    withExtensions(ext(x509.OID.keyUsage, true, x509.tlv(0x03, Buffer.from([0x07, 0x81])))),
    /padding bits/,
  );
  add(
    "unknown critical extension",
    "keyUsage of 3 bytes",
    withExtensions(ext(x509.OID.keyUsage, true, x509.tlv(0x03, Buffer.from([0x00, 0x80, 0x00, 0x00])))),
    /Oversized KeyUsage/,
  );

  // ---- bad signature -------------------------------------------------------------------------
  const flipped = Buffer.from(der);
  flipped[der.length - 5] = flipped[der.length - 5]! ^ 0x01;
  add("bad signature", "one bit flipped in the signature", toCsrPem(flipped), /does not verify|malformed/);
  for (const [index, item] of corpus.entries()) {
    const copy = Buffer.from(item.der);
    copy[copy.length - 1] = copy[copy.length - 1]! ^ 0x80;
    add(
      "bad signature",
      `last signature byte flipped (${item.name}, #${index})`,
      toCsrPem(copy),
      /does not verify|malformed/,
    );
  }
  add(
    "bad signature",
    "signed by a different key",
    signed({ signature: (data) => sign("sha256", data, { key: ec256b.privateKey, dsaEncoding: "der" }) }),
    /does not verify/,
  );
  add(
    "bad signature",
    "signature over different data",
    signed({
      signature: () => sign("sha256", Buffer.from("other"), { key: ec256.privateKey, dsaEncoding: "der" }),
    }),
    /does not verify/,
  );
  add(
    "bad signature",
    "empty signature value",
    signed({ signature: () => Buffer.alloc(0) }),
    /Malformed CSR signature/,
  );
  add(
    "bad signature",
    "signature BIT STRING with no content",
    signed({ signatureBitString: () => x509.tlv(0x03) }),
    /Empty signature BIT STRING/,
  );
  add(
    "bad signature",
    "signature BIT STRING with 3 unused bits",
    signed({
      signatureBitString: (value) =>
        x509.tlv(
          0x03,
          Buffer.from([3]),
          Buffer.concat([value.subarray(0, -1), Buffer.from([value[value.length - 1]! & 0xf8])]),
        ),
    }),
    /Malformed CSR signature/,
  );
  add(
    "bad signature",
    "ECDSA r = 0, s = 0",
    signed({ signature: () => x509.sequence(x509.integer(0), x509.integer(0)) }),
    /does not verify/,
  );
  add(
    "bad signature",
    "ECDSA signature with 1000-byte integers",
    signed({
      signature: () =>
        x509.sequence(
          x509.integerFromBytes(Buffer.alloc(1000, 0x7f)),
          x509.integerFromBytes(Buffer.alloc(1000, 0x7f)),
        ),
    }),
    /does not verify/,
  );
  add(
    "bad signature",
    "random bytes as the signature",
    signed({ signature: () => randomBytes(72) }),
    /does not verify/,
  );
  add("bad signature", "sha384 signature labelled sha256", signed({ hash: "sha384" }), /does not verify/);
  add(
    "bad signature",
    "RSA-PSS signature labelled PKCS#1 v1.5",
    buildCsr({
      key: rsa3072.privateKey,
      signature: (data) => sign("sha256", data, { key: rsa3072.privateKey, padding: 6 }),
    }).pem,
    /does not verify/,
  );
  add(
    "bad signature",
    "signature BIT STRING replaced by an OCTET STRING",
    signed({ signatureBitString: (value) => x509.octetString(value) }),
    /signature BIT STRING/,
  );

  // ---- mismatched key ------------------------------------------------------------------------
  add(
    "mismatched key",
    "EC key with sha256WithRSAEncryption",
    signed({ signatureAlgorithm: x509.sequence(x509.oid(x509.OID.sha256WithRsa), x509.tlv(0x05)) }),
    /not accepted for its key/,
  );
  add(
    "mismatched key",
    "RSA key with ecdsa-with-SHA256",
    buildCsr({
      key: rsa3072.privateKey,
      signatureAlgorithm: x509.sequence(x509.oid(x509.OID.ecdsaWithSha256)),
    }).pem,
    /not accepted for its key/,
  );
  add(
    "mismatched key",
    "rsaEncryption SPKI around an EC point",
    signed({
      spki: x509.sequence(
        x509.sequence(x509.oid(x509.OID.rsaEncryption), x509.tlv(0x05)),
        x509.children(x509.decode(x509.spkiDer(ec256.publicKey)))[1]!.raw,
      ),
    }),
    /cannot be read/,
  );
  add(
    "mismatched key",
    "P-384 curve OID around a P-256 point",
    signed({
      spki: x509.sequence(
        x509.sequence(x509.oid(x509.OID.ecPublicKey), x509.oid("1.3.132.0.34")),
        x509.children(x509.decode(x509.spkiDer(ec256.publicKey)))[1]!.raw,
      ),
    }),
    /cannot be read/,
  );
  add(
    "mismatched key",
    "explicit EC curve parameters",
    signed({
      spki: x509.sequence(
        x509.sequence(x509.oid(x509.OID.ecPublicKey), x509.sequence(x509.integer(1))),
        x509.children(x509.decode(x509.spkiDer(ec256.publicKey)))[1]!.raw,
      ),
    }),
    /name their curve/,
  );
  add(
    "mismatched key",
    "SPKI of key B, signed by key A",
    signed({ spki: x509.spkiDer(ec256b.publicKey) }),
    /does not verify/,
  );
  add(
    "mismatched key",
    "compressed P-256 point",
    signed({ spki: compressedSpki(ec256.publicKey) }),
    /canonically encoded/,
  );
  add(
    "mismatched key",
    "Ed25519 key",
    buildCsr({
      key: ed.privateKey,
      signature: (data) => sign(null, data, ed.privateKey),
      signatureAlgorithm: x509.sequence(rawOid([0x2b, 0x65, 0x70])),
    }).pem,
    /ed25519/,
  );
  add("mismatched key", "P-521 key", buildCsr({ key: ec521.privateKey }).pem, /curve are not accepted/);
  add("mismatched key", "RSA-2048 key", buildCsr({ key: rsa2048.privateKey }).pem, /at least 3072 bits/);
  add(
    "mismatched key",
    "P-384 key with an RSA OID in the algorithm",
    buildCsr({
      key: ec384.privateKey,
      signatureAlgorithm: x509.sequence(x509.oid(x509.OID.sha384WithRsa), x509.tlv(0x05)),
    }).pem,
    /not accepted for its key/,
  );
  add(
    "mismatched key",
    "DSA key algorithm OID",
    signed({
      spki: x509.sequence(
        x509.sequence(rawOid([0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01])),
        x509.bitString(Buffer.from([0x02, 0x01, 0x01])),
      ),
    }),
    /type dsa/,
  );

  // ---- huge integers -------------------------------------------------------------------------
  add(
    "huge integer",
    "1000-byte version (signed)",
    signed({ version: x509.integerFromBytes(Buffer.alloc(1000, 0x01)) }),
    /Oversized CSR version/,
  );
  add(
    "huge integer",
    "non-minimal version 00 00 (signed)",
    signed({ version: x509.tlv(0x02, Buffer.from([0, 0])) }),
    /Non-minimal|Oversized/,
  );
  add(
    "huge integer",
    "empty version INTEGER (signed)",
    signed({ version: x509.tlv(0x02) }),
    /Empty CSR version/,
  );
  add(
    "huge integer",
    "negative version (signed)",
    signed({ version: x509.tlv(0x02, Buffer.from([0xff])) }),
    /version 1/,
  );
  add("huge integer", "version 2 (signed)", signed({ version: x509.integer(1) }), /version 1/);
  add(
    "huge integer",
    "version as an OCTET STRING (signed)",
    signed({ version: x509.octetString(Buffer.from([0])) }),
    /CSR version/,
  );
  add(
    "huge integer",
    "100-byte pathLenConstraint (signed)",
    withExtensions(
      ext(x509.OID.basicConstraints, true, x509.sequence(x509.integerFromBytes(Buffer.alloc(100, 0x11)))),
    ),
    /Oversized pathLenConstraint/,
  );
  add(
    "huge integer",
    "negative pathLenConstraint (signed)",
    withExtensions(ext(x509.OID.basicConstraints, true, x509.sequence(x509.tlv(0x02, Buffer.from([0x80]))))),
    /Negative/,
  );
  add(
    "huge integer",
    "RSA-3072 with a 4096-bit exponent",
    signed({ spki: rsaSpki(oddModulus(3072), oddModulus(4096)) }),
    /public exponent|cannot be read/,
  );
  add(
    "huge integer",
    "RSA-3072 with exponent 1",
    signed({ spki: rsaSpki(oddModulus(3072), Buffer.from([1])) }),
    /public exponent|cannot be read/,
  );
  add(
    "huge integer",
    "RSA-3072 with an even exponent",
    signed({ spki: rsaSpki(oddModulus(3072), Buffer.from([1, 0, 0])) }),
    /public exponent|cannot be read/,
  );

  // ---- OID edge cases ------------------------------------------------------------------------
  const sigAlg = (oid: Buffer) => signed({ signatureAlgorithm: x509.sequence(oid) });
  add("OID edge case", "empty signature algorithm OID", sigAlg(rawOid([])), /Empty OBJECT IDENTIFIER/);
  add("OID edge case", "OID ending mid-arc", sigAlg(rawOid([0x2a, 0x86])), /Truncated OBJECT IDENTIFIER/);
  add(
    "OID edge case",
    "OID arc with a 0x80 pad",
    sigAlg(rawOid([0x2a, 0x80, 0x86, 0x48])),
    /Non-minimal OBJECT IDENTIFIER/,
  );
  add(
    "OID edge case",
    "OID whose first arc is padded",
    sigAlg(rawOid([0x80, 0x2a])),
    /Non-minimal OBJECT IDENTIFIER/,
  );
  add(
    "OID edge case",
    "65-byte OID",
    sigAlg(rawOid([0x2a, ...Array<number>(64).fill(0x01)])),
    /Oversized OBJECT IDENTIFIER/,
  );
  add(
    "OID edge case",
    "OID with a 400-bit arc",
    withExtensions(
      x509.sequence(rawOid([0x69, ...Array<number>(57).fill(0xff), 0x7f]), x509.octetString(x509.sequence())),
    ),
    /not carry/,
  );
  add(
    "OID edge case",
    "unknown signature algorithm (md5WithRSA)",
    sigAlg(x509.oid("1.2.840.113549.1.1.4")),
    /not accepted for its key/,
  );
  add(
    "OID edge case",
    "extensionRequest OID off by one",
    signed({
      attributes: [x509.sequence(x509.oid("1.2.840.113549.1.9.15"), x509.set(x509.sequence(keyUsageExt)))],
    }),
    /attribute 1\.2\.840\.113549\.1\.9\.15/,
  );
  add(
    "OID edge case",
    "an INTEGER where the extension OID belongs",
    withExtensions(x509.sequence(x509.integer(5), x509.octetString(x509.sequence()))),
    /OBJECT IDENTIFIER/,
  );
  add(
    "OID edge case",
    "OID as a constructed value",
    sigAlg(x509.tlv(0x26, x509.oid("1.2.840.10045.4.3.2"))),
    /OBJECT IDENTIFIER/,
  );
  add(
    "OID edge case",
    "multi-byte tag in place of the OID",
    sigAlg(Buffer.from([0x1f, 0x81, 0x01, 0x00])),
    /Multi-byte DER tags/,
  );
  add(
    "OID edge case",
    "secp256k1 curve OID",
    signed({
      spki: x509.sequence(
        x509.sequence(x509.oid(x509.OID.ecPublicKey), x509.oid("1.3.132.0.10")),
        x509.children(x509.decode(x509.spkiDer(ec256.publicKey)))[1]!.raw,
      ),
    }),
    /curve are not accepted/,
  );
  add(
    "OID edge case",
    "subject attribute OID with a truncated arc",
    signed({
      subject: x509.sequence(x509.set(x509.sequence(rawOid([0x55, 0x04, 0x83]), x509.utf8String("x")))),
    }),
    /Truncated OBJECT IDENTIFIER/,
  );

  // ---- PEM only ------------------------------------------------------------------------------
  add("PEM only", "raw DER as a string", der.toString("latin1"), /Expected a PEM/);
  add("PEM only", "base64 without armour", der.toString("base64"), /Expected a PEM/);
  add(
    "PEM only",
    "a certificate label",
    base.pem.replaceAll("CERTIFICATE REQUEST", "CERTIFICATE"),
    /Expected a PEM/,
  );
  add(
    "PEM only",
    "mismatched BEGIN and END labels",
    base.pem.replace("END CERTIFICATE REQUEST", "END NEW CERTIFICATE REQUEST"),
    /Expected a PEM/,
  );
  add(
    "PEM only",
    "openssl text output before the block",
    `Certificate Request:\n    Data: ...\n${base.pem}`,
    /Expected a PEM/,
  );
  add(
    "PEM only",
    "padding in the middle of the body",
    base.pem.replace(/\n([A-Za-z0-9+/]{4})/, "\n$1=="),
    /canonical base64/,
  );
  add(
    "PEM only",
    "an invalid base64 character",
    base.pem.replace(/\n([A-Za-z0-9+/])/, "\n*"),
    /Expected a PEM/,
  );
  add(
    "PEM only",
    "non-zero base64 padding bits",
    toCsrPem(Buffer.concat([der, Buffer.from([0])])).replace(/A==\n/, "B==\n"),
    /canonical base64|Trailing data/,
  );
  add("PEM only", "an empty string", "", /missing/);
  add("PEM only", "only whitespace", " \n\t ", /Expected a PEM/);
  for (const value of [null, undefined, 42, {}, [], Buffer.from(base.pem)]) {
    add(
      "PEM only",
      `non-string input (${Array.isArray(value) ? "array" : Buffer.isBuffer(value) ? "Buffer" : typeof value})`,
      value,
      /missing/,
    );
  }
  return list;
}

describe("CSR parsing rejects malformed input cleanly (FD-17 hardening)", () => {
  test("controls: the corpus and a re-signed default request are accepted", () => {
    for (const item of corpus) expect(() => pki.validateCsr(item.pem), item.name).not.toThrow();
    const accepted = pki.validateCsr(signed({ attributes: [extensionRequest([keyUsageExt])] }));
    expect(x509.spkiDer(accepted)).toEqual(x509.spkiDer(ec256.publicKey));
    expect(() => pki.validateCsr(signed({ noAttributes: true }))).not.toThrow();
    expect(() => pki.validateCsr(buildCsr({ key: rsa3072.privateKey }).pem)).not.toThrow();
  });

  test("every malformed case is a CsrError within the time bound", () => {
    const all = cases();
    Bun.gc(true);
    const heapBefore = process.memoryUsage().heapUsed;
    const perCategory = new Map<string, number>();
    let slowest = { name: "", ms: 0 };
    for (const item of all) {
      const label = `${item.category}: ${item.name}`;
      const started = performance.now();
      let error: unknown;
      try {
        pki.validateCsr(item.input as string);
      } catch (caught) {
        error = caught;
      }
      const ms = performance.now() - started;
      expect(error, label).toBeInstanceOf(pki.CsrError);
      expect(error, label).toBeInstanceOf(pki.PkiPolicyError);
      const message = (error as Error).message;
      // Every rejection is classified by an explicit check, not by the catch-all fallback.
      expect(message, label).not.toBe("The CSR is malformed.");
      if (item.expect) expect(message, label).toMatch(item.expect);
      expect(ms, label).toBeLessThan(CASE_BOUND_MS);
      if (ms > slowest.ms) slowest = { name: label, ms };
      perCategory.set(item.category, (perCategory.get(item.category) ?? 0) + 1);
    }
    Bun.gc(true);
    const heapGrowth = process.memoryUsage().heapUsed - heapBefore;
    expect(heapGrowth).toBeLessThan(HEAP_BOUND_BYTES);
    console.log(
      `CSR malformed-input suite: ${all.length} cases rejected with CsrError; ` +
        `${[...perCategory].map(([category, count]) => `${category} ${count}`).join(", ")}; ` +
        `max ${slowest.ms.toFixed(2)} ms (${slowest.name}); bound ${CASE_BOUND_MS} ms; ` +
        `heap growth ${(heapGrowth / 1024 / 1024).toFixed(1)} MiB (bound ${HEAP_BOUND_BYTES / 1024 / 1024} MiB)`,
    );
  });
});
