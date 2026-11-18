// Test fixtures with expected fields specified independently of the structure decoders.
import { type prng, rawTlv } from "./csr-test-kit.ts";
import * as x509 from "./x509.ts";

type Random = ReturnType<typeof prng>;

export type DerCase<T> = {
  name: string;
  build: (random: Random) => { der: Buffer; expected: T | RegExp };
};

function deepDer(depth: number) {
  let der = x509.tlv(0x05);
  for (let i = 0; i < depth; i++) der = x509.sequence(der);
  return der;
}

const depths = [64, 512, 2400];
const nestedValues = depths.map(deepDer);
export const nestedDer = (random: Random) => random.pick(nestedValues);

function editDer(der: Buffer, path: readonly number[], edit: (node: Buffer) => Buffer[]) {
  function visit(node: x509.Node, depth: number): Buffer[] {
    if (depth === path.length) return edit(node.raw);
    const fields = x509.children(node);
    const index = path[depth]!;
    if (!fields[index]) throw new Error(`Invalid fixture path ${path.join(".")}.`);
    return [
      x509.tlv(
        node.tag,
        ...fields.flatMap((field, at) => (at === index ? visit(field, depth + 1) : [field.raw])),
      ),
    ];
  }
  return visit(x509.decode(der), 0)[0]!;
}

const encodeExtensions = (extensions: x509.ParsedExtension[]) =>
  x509.sequence(...extensions.map(({ id, critical, value }) => x509.extension(id, critical, value)));

const reject = (name: string, expected: RegExp, build: (random: Random) => Buffer): DerCase<never> => ({
  name,
  build: (random) => ({ der: build(random), expected }),
});

const randomSerial = (random: Random) => Buffer.from([0x80 + random.int(0x80), random.int(0x100)]);

export function structuredCases(spki: Buffer) {
  const issuer = x509.name([{ type: "CN", value: "fuzz issuer" }]);
  const subject = x509.name([{ type: "CN", value: "fuzz subject" }]);
  const before = new Date("2026-01-01T00:00:00Z");
  const after = new Date("2050-01-01T00:00:00Z");
  const algorithm = x509.ecdsaWithSha256();
  // These decoders extract signature bytes. The fixtures do not need to be signed.
  const signature = x509.sequence(x509.integer(1), x509.integer(2));
  const signed = (tbs: Buffer) => x509.sequence(tbs, algorithm, x509.bitString(signature));
  const keyId = x509.keyIdentifier(spki);
  const certValues: x509.ParsedExtension[] = [
    { id: x509.OID.basicConstraints, critical: true, value: x509.basicConstraintsValue(true, 0) },
    {
      id: x509.OID.keyUsage,
      critical: true,
      value: x509.keyUsageValue(["digitalSignature", "keyAgreement"]),
    },
    { id: x509.OID.subjectKeyIdentifier, critical: false, value: x509.subjectKeyIdentifierValue(keyId) },
    { id: x509.OID.authorityKeyIdentifier, critical: false, value: x509.authorityKeyIdentifierValue(keyId) },
  ];
  const crlValues: x509.ParsedExtension[] = [
    { id: x509.OID.crlNumber, critical: false, value: x509.integer(1) },
  ];
  const certExtensions = encodeExtensions(certValues);
  const certificateBody = x509.sequence(
    x509.explicit(0, x509.integer(2)),
    x509.integer(1),
    algorithm,
    issuer,
    x509.sequence(x509.time(before), x509.time(after)),
    subject,
    spki,
    x509.explicit(3, certExtensions),
  );
  const crlBody = x509.sequence(
    x509.integer(1),
    algorithm,
    issuer,
    x509.time(before),
    x509.time(after),
    x509.sequence(
      x509.sequence(
        x509.integer(1),
        x509.time(before),
        x509.sequence(x509.extension(x509.OID.crlReason, false, x509.enumerated(1))),
      ),
    ),
    x509.explicit(0, encodeExtensions(crlValues)),
  );

  const certificate = signed(certificateBody);
  const crl = signed(crlBody);
  const expectedCertificate: x509.ParsedCertificate = {
    version: 3,
    serial: "01",
    issuerDer: issuer,
    subjectDer: subject,
    notBefore: before,
    notAfter: after,
    spki: Buffer.from(spki),
    extensions: certValues,
    tbs: certificateBody,
    signatureAlgorithm: x509.OID.ecdsaWithSha256,
    signature,
  };
  const expectedCrl: ReturnType<typeof x509.parseCrl> = {
    issuerDer: issuer,
    thisUpdate: before,
    nextUpdate: after,
    revoked: [{ serial: "01", revokedAt: before, reasonCode: 1 }],
    extensions: crlValues,
    crlNumber: 1n,
    tbs: crlBody,
    signatureAlgorithm: x509.OID.ecdsaWithSha256,
    signature,
  };

  function fixtures<T extends { tbs: Buffer; signature: Buffer }>(seed: Buffer, baseline: T) {
    const accept = (
      name: string,
      build: (random: Random) => { der: Buffer; fields: Partial<T> },
    ): DerCase<T> => ({
      name,
      build: (random) => {
        const { der, fields } = build(random);
        const tbs = x509.children(x509.decode(der))[0]!.raw;
        return { der, expected: { ...baseline, ...fields, tbs } };
      },
    });
    const baselineCase: DerCase<T> = {
      name: "unchanged DER",
      build: () => ({ der: seed, expected: baseline }),
    };
    const envelopeCases = [
      accept("replace signature bytes", (random) => {
        const newSignature = random.bytes(1 + random.int(72));
        return {
          der: editDer(seed, [2], () => [x509.bitString(newSignature)]),
          fields: { ...baseline, signature: newSignature },
        };
      }),
      reject("truncate outer DER", /DER/, (random) => seed.subarray(0, random.int(seed.length))),
      reject("append trailing bytes", /Trailing data/, (random) =>
        Buffer.concat([seed, random.bytes(1 + random.int(32))]),
      ),
    ];
    return { accept, baselineCase, envelopeCases };
  }

  const cert = fixtures(certificate, expectedCertificate);
  const list = fixtures(crl, expectedCrl);
  // Corrupt a nested length while the enclosing TBS and outer lengths stay valid.
  const badLength = rawTlv(0x30, [0x84, 0xff, 0xff, 0xff, 0xff], Buffer.alloc(0));
  const impossibleTime = x509.tlv(0x17, Buffer.from("260230000000Z"));

  return {
    certificate,
    crl,
    certExtensions,
    certificateCases: [
      cert.baselineCase,
      cert.accept("replace certificate serial", (random) => {
        const bytes = randomSerial(random);
        return {
          der: editDer(certificate, [0, 1], () => [x509.integerFromBytes(bytes)]),
          fields: { serial: bytes.toString("hex").toUpperCase() },
        };
      }),
      cert.accept("remove optional certificate extensions", () => ({
        der: editDer(certificate, [0, 7], () => []),
        fields: { extensions: [] },
      })),
      reject("remove certificate validity date", /Malformed certificate Validity/, () =>
        editDer(certificate, [0, 4, 1], () => []),
      ),
      reject("duplicate certificate extensions", /Unexpected TBSCertificate field/, () =>
        editDer(certificate, [0, 7], (node) => [node, node]),
      ),
      reject("nested certificate validity date", /Expected a UTCTime or GeneralizedTime/, (random) =>
        editDer(certificate, [0, 4, random.int(2)], () => [nestedDer(random)]),
      ),
      reject("invalid certificate calendar date", /Invalid DER time/, () =>
        editDer(certificate, [0, 4, 0], () => [impossibleTime]),
      ),
      reject("overrunning certificate field", /past the end/, () =>
        editDer(certificate, [0, 7], () => [badLength]),
      ),
      ...cert.envelopeCases,
    ],
    crlCases: [
      list.baselineCase,
      list.accept("replace CRL number", (random) => {
        const crlNumber = BigInt(2 + random.int(10_000));
        const value = x509.integer(crlNumber);
        return {
          der: editDer(crl, [0, 6, 0, 0, 1], () => [x509.octetString(value)]),
          fields: { crlNumber, extensions: [{ ...crlValues[0]!, value }] },
        };
      }),
      list.accept("replace revoked serial", (random) => {
        const bytes = randomSerial(random);
        return {
          der: editDer(crl, [0, 5, 0, 0], () => [x509.integerFromBytes(bytes)]),
          fields: {
            revoked: [{ serial: bytes.toString("hex").toUpperCase(), revokedAt: before, reasonCode: 1 }],
          },
        };
      }),
      list.accept("remove optional CRL nextUpdate", () => ({
        der: editDer(crl, [0, 4], () => []),
        fields: { nextUpdate: null },
      })),
      reject("duplicate CRL extensions", /Unexpected TBSCertList field/, () =>
        editDer(crl, [0, 6], (node) => [node, node]),
      ),
      reject("duplicate revoked entry fields", /Unexpected revoked certificate entry field/, () =>
        editDer(crl, [0, 5, 0, 2], (node) => [node, node]),
      ),
      reject("nested CRL number", /Expected a CRLNumber/, (random) =>
        editDer(crl, [0, 6, 0, 0, 1], () => [x509.octetString(nestedDer(random))]),
      ),
      reject("invalid CRL calendar date", /Invalid DER time/, () =>
        editDer(crl, [0, 5, 0, 1], () => [impossibleTime]),
      ),
      reject("overrunning CRL entry field", /past the end/, () =>
        editDer(crl, [0, 5, 0, 2], () => [badLength]),
      ),
      ...list.envelopeCases,
    ],
  };
}
