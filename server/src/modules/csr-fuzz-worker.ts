// Isolate the synchronous parser so the fuzz test can stop a stuck input.
import { parentPort, workerData } from "node:worker_threads";

import { headerOffsets, loadCorpus, prng, rawTlv, toCsrPem } from "./csr-test-kit.ts";
import * as x509 from "./x509.ts";

process.env.DATABASE_URL ??= "postgres://unused:unused@127.0.0.1:9/unused";
const { CsrError, validateCsr } = await import("./pki.ts");
const { progress, seed, iterations, caseBoundMs } = workerData as {
  progress: BigInt64Array;
  seed: number;
  iterations: number;
  caseBoundMs: number;
};

export type FuzzResult = { csrAccepted: number; slowestMs: number };
type Random = ReturnType<typeof prng>;

function derSeed(der: Buffer) {
  const root = x509.decode(der);
  const childGroups = root.tag & 0x20 ? x509.children(root) : [];
  return { der, root, childGroups, headers: headerOffsets(der) };
}
type DerSeed = ReturnType<typeof derSeed>;

const deep = [64, 512, 2400].map((depth) => {
  let der = x509.tlv(0x05);
  for (let i = 0; i < depth; i++) der = x509.sequence(der);
  return der;
});

function replaceChild(nodes: x509.Node[], index: number, replacement: Buffer[]) {
  return nodes.flatMap((node, at) => (at === index ? replacement : [node.raw]));
}

function editChild(random: Random, item: DerSeed, duplicate: boolean) {
  if (!item.childGroups.length) return duplicate ? Buffer.concat([item.der, item.der]) : Buffer.alloc(0);

  const index = random.int(item.childGroups.length);
  const child = item.childGroups[index]!;
  if (child.tag & 0x20 && child.content.length && random.int(2) === 0) {
    const nodes = x509.children(child);
    const nestedIndex = random.int(nodes.length);
    const replacement = duplicate ? [nodes[nestedIndex]!.raw, nodes[nestedIndex]!.raw] : [];
    const newChild = x509.tlv(child.tag, ...replaceChild(nodes, nestedIndex, replacement));
    return x509.tlv(item.root.tag, ...replaceChild(item.childGroups, index, [newChild]));
  }

  return x509.tlv(
    item.root.tag,
    ...replaceChild(item.childGroups, index, duplicate ? [child.raw, child.raw] : []),
  );
}

const mutations = [
  {
    name: "random bytes",
    apply: (random: Random) => random.bytes(random.int(random.int(16) ? 1024 : 12_200)),
  },
  {
    name: "bit flip",
    apply: (random: Random, { der }: DerSeed) => {
      const changed = Buffer.from(der);
      const index = random.int(der.length);
      changed[index] = changed[index]! ^ (1 << random.int(8));
      return changed;
    },
  },
  {
    name: "truncation",
    apply: (random: Random, { der }: DerSeed) => der.subarray(0, random.int(der.length)),
  },
  { name: "duplicate TLV", apply: (random: Random, item: DerSeed) => editChild(random, item, true) },
  { name: "remove TLV", apply: (random: Random, item: DerSeed) => editChild(random, item, false) },
  {
    name: "rewrite length",
    apply: (random: Random, { der, headers }: DerSeed) => {
      const changed = Buffer.from(der);
      changed[random.pick(headers) + 1] = random.pick([0x00, 0x7f, 0x81, 0x82, 0x84, 0x85, 0xff]);
      return changed;
    },
  },
  {
    name: "non-minimal long-form length",
    apply: (_random: Random, { der, root }: DerSeed) => {
      const length = der.subarray(1, der.length - root.content.length);
      const bytes = length[0]! < 0x80 ? length : length.subarray(1);
      return rawTlv(root.tag, [0x81 + bytes.length, 0, ...bytes], root.content);
    },
  },
  {
    name: "indefinite length",
    apply: (_random: Random, { root }: DerSeed) =>
      rawTlv(root.tag, [0x80], Buffer.concat([root.content, Buffer.from([0, 0])])),
  },
  {
    name: "oversized length",
    apply: (random: Random, { root }: DerSeed) =>
      rawTlv(
        root.tag,
        random.pick([
          [0x84, 0xff, 0xff, 0xff, 0xff],
          [0x85, 1, 0, 0, 0, 0],
        ]),
        root.content,
      ),
  },
  {
    name: "trailing bytes",
    apply: (random: Random, { der }: DerSeed) => Buffer.concat([der, random.bytes(1 + random.int(16))]),
  },
  {
    name: "deep nesting",
    apply: (random: Random, { der }: DerSeed) => x509.sequence(random.pick(deep), der),
  },
  { name: "unchanged DER", apply: (_random: Random, { der }: DerSeed) => der },
];

function splitRequest(der: Buffer) {
  const [info, algorithm, signature] = x509.children(x509.decode(der));
  return { info: info!.raw, oid: x509.decodeOid(x509.children(algorithm)[0]), signature: signature!.raw };
}

const corpus = loadCorpus().map(({ der }) => {
  const request = splitRequest(der);
  return { der, ...request, spki: x509.children(x509.decode(request.info))[2]!.raw };
});

function fuzzPem(der: Buffer, random: Random, unchanged: boolean) {
  const pem = toCsrPem(der);
  if (unchanged) return `\n${pem.replaceAll("\n", "\r\n")}\t`;
  const at = random.int(pem.length);
  switch (random.int(8)) {
    case 0:
      return pem.slice(0, at);
    case 1:
      return `${pem.slice(0, at)}${String.fromCharCode(random.int(128))}${pem.slice(at + 1)}`;
    case 2:
      return pem + pem;
    default:
      return pem;
  }
}

const derTarget = (
  name: string,
  parse: (der: Buffer, random: Random, unchanged: boolean) => unknown,
  ...seeds: Buffer[]
) => ({
  name,
  parse,
  seeds: seeds.map(derSeed),
  domain: x509.DerError,
});

const spki = corpus[0]!.spki;
const subject = x509.name([{ type: "CN", value: "fuzz test" }]);
const utcTime = x509.time(new Date("2026-01-01T00:00:00Z"));
const generalizedTime = x509.time(new Date("2050-01-01T00:00:00Z"));
const algorithm = x509.ecdsaWithSha256();
const keyId = x509.keyIdentifier(spki);
const basic = x509.basicConstraintsValue(true, 0);
const usage = x509.keyUsageValue(["digitalSignature", "keyAgreement"]);
const eku = x509.extendedKeyUsageValue([x509.OID.clientAuth]);
const ski = x509.subjectKeyIdentifierValue(keyId);
const aki = x509.authorityKeyIdentifierValue(keyId);
const certExtensions = x509.sequence(
  x509.extension(x509.OID.basicConstraints, true, basic),
  x509.extension(x509.OID.keyUsage, true, usage),
  x509.extension(x509.OID.subjectKeyIdentifier, false, ski),
  x509.extension(x509.OID.authorityKeyIdentifier, false, aki),
);
// These structure decoders do not verify signatures. Use fixed bytes to keep the seeds reproducible.
const signature = x509.bitString(x509.sequence(x509.integer(1), x509.integer(2)));
const certificate = x509.sequence(
  x509.sequence(
    x509.explicit(0, x509.integer(2)),
    x509.integer(1),
    algorithm,
    subject,
    x509.sequence(utcTime, generalizedTime),
    subject,
    spki,
    x509.explicit(3, certExtensions),
  ),
  algorithm,
  signature,
);
const crl = x509.sequence(
  x509.sequence(
    x509.integer(1),
    algorithm,
    subject,
    utcTime,
    generalizedTime,
    x509.sequence(
      x509.sequence(
        x509.integer(1),
        utcTime,
        x509.sequence(x509.extension(x509.OID.crlReason, false, x509.enumerated(1))),
      ),
    ),
    x509.explicit(0, x509.sequence(x509.extension(x509.OID.crlNumber, false, x509.integer(1)))),
  ),
  algorithm,
  signature,
);

const targets = [
  {
    name: "validateCsr",
    seeds: corpus.map(({ der }) => derSeed(der)),
    parse: (der: Buffer, random: Random, unchanged: boolean) => {
      const input = fuzzPem(der, random, unchanged);
      const key = validateCsr(input);
      const accepted = splitRequest(x509.fromPem(input, ["CERTIFICATE REQUEST"]));
      // The signed bytes contain the subject, extensions and key. RSA's optional NULL
      // signature parameter can change without changing the request or its signature.
      const original = corpus.find(
        (item) =>
          item.info.equals(accepted.info) &&
          item.oid === accepted.oid &&
          item.signature.equals(accepted.signature),
      );
      if (!original || !original.spki.equals(x509.spkiDer(key)))
        throw new Error("Accepted a mutation that changed the request or its public key.");
    },
    domain: CsrError,
  },
  derTarget(
    "readNode",
    (der, random, unchanged) =>
      x509.readNode(der, unchanged ? 0 : random.pick([0, -1, 0.5, random.int(der.length + 2)])),
    subject,
  ),
  derTarget("decode", x509.decode, subject, certificate, crl),
  derTarget("children", (der) => x509.children(x509.decode(der)), subject),
  derTarget("expectTag", (der) => x509.expectTag(x509.decode(der), 0x30, "a SEQUENCE"), subject),
  derTarget("decodeBoolean", (der) => x509.decodeBoolean(x509.decode(der)), x509.booleanTrue()),
  derTarget("decodeInteger", (der) => x509.decodeInteger(x509.decode(der)), x509.integer(128)),
  derTarget("decodeBitString", (der) => x509.decodeBitString(x509.decode(der)), usage),
  derTarget("decodeOid", (der) => x509.decodeOid(x509.decode(der)), x509.oid(x509.OID.ecPublicKey)),
  derTarget("decodeTime", (der) => x509.decodeTime(x509.decode(der)), utcTime, generalizedTime),
  derTarget("serialHex", (der) => x509.serialHex(x509.decode(der)), x509.integer(128)),
  derTarget(
    "fromPem",
    (der, random, unchanged) => x509.fromPem(fuzzPem(der, random, unchanged), ["CERTIFICATE REQUEST"]),
    corpus[0]!.der,
  ),
  derTarget("keyIdentifier", x509.keyIdentifier, spki),
  derTarget("parseExtensions", (der) => x509.parseExtensions(x509.decode(der)), certExtensions),
  derTarget("decodeKeyUsage", x509.decodeKeyUsage, usage),
  derTarget("decodeBasicConstraints", x509.decodeBasicConstraints, basic),
  derTarget("decodeExtendedKeyUsage", x509.decodeExtendedKeyUsage, eku),
  derTarget("decodeSubjectKeyIdentifier", x509.decodeSubjectKeyIdentifier, ski),
  derTarget("decodeAuthorityKeyIdentifier", x509.decodeAuthorityKeyIdentifier, aki),
  derTarget("parseCertificate", x509.parseCertificate, certificate),
  derTarget("parseCrl", x509.parseCrl, crl),
];

// oxlint-disable-next-line unicorn/require-post-message-target-origin -- Node MessagePort has no target origin.
parentPort!.postMessage(targets.map(({ name }) => name));
const random = prng(seed);
const result: FuzzResult = { csrAccepted: 0, slowestMs: 0 };
for (let iteration = 0; iteration < iterations; iteration++) {
  for (const [index, target] of targets.entries()) {
    const baseline = iteration < target.seeds.length;
    const item = baseline ? target.seeds[iteration]! : random.pick(target.seeds);
    const mutation = baseline
      ? mutations.at(-1)!
      : mutations[(iteration - target.seeds.length) % mutations.length]!;
    const label = `Seed ${seed}, ${target.name}, iteration ${iteration} (${mutation.name})`;
    const started = process.hrtime.bigint();
    Atomics.store(progress, 0, BigInt(iteration * targets.length + index + 1));
    try {
      target.parse(mutation.apply(random, item), random, mutation.name === "unchanged DER");
      if (target.name === "validateCsr") result.csrAccepted += 1;
    } catch (error) {
      if (baseline || !(error instanceof target.domain)) {
        const details = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
        throw new Error(`${label}: ${details}`, { cause: error });
      }
    } finally {
      Atomics.store(progress, 0, 0n);
    }
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    if (ms > caseBoundMs) throw new Error(`${label} took ${ms.toFixed(2)} ms (bound ${caseBoundMs} ms).`);
    result.slowestMs = Math.max(ms, result.slowestMs);
  }
}
// oxlint-disable-next-line unicorn/require-post-message-target-origin -- Node MessagePort has no target origin.
parentPort!.postMessage(result);
