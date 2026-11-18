// Isolate the synchronous parser so the fuzz test can stop a stuck input.
import { generateKeyPairSync } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { parentPort, workerData } from "node:worker_threads";

import {
  buildCsr,
  extensionRequest,
  headerOffsets,
  loadCorpus,
  prng,
  rawTlv,
  toCsrPem,
} from "./csr-test-kit.ts";
import { type DerCase, nestedDer, structuredCases } from "./x509-fuzz-cases.ts";
import * as x509 from "./x509.ts";

process.env.DATABASE_URL ??= "postgres://unused:unused@127.0.0.1:9/unused";
const { CsrError, validateCsr } = await import("./pki.ts");
const { progress, seed, iterations, caseBoundMs } = workerData as {
  progress: BigInt64Array;
  seed: number;
  iterations: number;
  caseBoundMs: number;
};

export type FuzzResult = { csrAccepted: number; csrMutations: string[]; slowestMs: number };
type Random = ReturnType<typeof prng>;

function derSeed(der: Buffer) {
  const root = x509.decode(der);
  const childGroups = root.tag & 0x20 ? x509.children(root) : [];
  return { der, root, childGroups };
}
type DerSeed = ReturnType<typeof derSeed>;

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

type ByteEdit = (random: Random, der: Buffer, spliceSource: Buffer) => Buffer;

const interestingBytes = [
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x1f, 0x30, 0x31, 0x7f, 0x80, 0x81, 0x82, 0x84, 0x85, 0xa0, 0xff,
];
const insert = (der: Buffer, at: number, bytes: Buffer) =>
  Buffer.concat([der.subarray(0, at), bytes, der.subarray(at)]);

function rewriteHeader(random: Random, der: Buffer, offset: number) {
  const headers = headerOffsets(der);
  if (!headers.length) return der;
  const changed = Buffer.from(der);
  const index = random.pick(headers) + offset;
  changed[index] =
    offset && random.int(2) === 0
      ? (changed[index]! + random.int(5) - 2) & 0xff
      : random.pick(interestingBytes);
  return changed;
}

const byteEdits = new Map<string, ByteEdit>([
  [
    "bit flip",
    (random, der) => {
      const changed = Buffer.from(der);
      const index = random.int(der.length);
      changed[index] = changed[index]! ^ (1 << random.int(8));
      return changed;
    },
  ],
  [
    "interesting byte",
    (random, der) => {
      const changed = Buffer.from(der);
      changed[random.int(der.length)] = random.pick(interestingBytes);
      return changed;
    },
  ],
  ["insert bytes", (random, der) => insert(der, random.int(der.length + 1), random.bytes(1 + random.int(8)))],
  [
    "delete bytes",
    (random, der) => {
      const at = random.int(der.length);
      return Buffer.concat([der.subarray(0, at), der.subarray(at + 1 + random.int(8))]);
    },
  ],
  [
    "duplicate byte chunk",
    (random, der) => {
      const from = random.int(der.length);
      return insert(der, random.int(der.length + 1), der.subarray(from, from + 1 + random.int(48)));
    },
  ],
  [
    "cross-corpus splice",
    (random, der, other) =>
      Buffer.concat([der.subarray(0, random.int(der.length)), other.subarray(random.int(other.length))]),
  ],
  ["truncation", (random, der) => der.subarray(0, random.int(der.length))],
  ["rewrite tag", (random, der) => rewriteHeader(random, der, 0)],
  ["rewrite length", (random, der) => rewriteHeader(random, der, 1)],
  ["trailing bytes", (random, der) => Buffer.concat([der, random.bytes(1 + random.int(32))])],
]);
const stackableEdits = [...byteEdits.values()];

type Mutation = { name: string; apply: (random: Random, item: DerSeed, spliceSource: Buffer) => Buffer };
const mutations: Mutation[] = [
  ...[...byteEdits].map(([name, edit]) => ({
    name,
    apply: (random: Random, { der }: DerSeed, spliceSource: Buffer) => edit(random, der, spliceSource),
  })),
  {
    name: "stacked byte edits",
    apply: (random, { der }, spliceSource) => {
      const rounds = 2 + random.int(3);
      for (let round = 0; round < rounds; round++)
        der = random.pick(stackableEdits)(random, der, spliceSource);
      return der;
    },
  },
  { name: "random bytes", apply: (random) => random.bytes(random.int(random.int(16) ? 1024 : 12_200)) },
  { name: "duplicate TLV", apply: (random, item) => editChild(random, item, true) },
  { name: "remove TLV", apply: (random, item) => editChild(random, item, false) },
  {
    name: "non-minimal long-form length",
    apply: (_random, { der, root }) => {
      const length = der.subarray(1, der.length - root.content.length);
      const bytes = length[0]! < 0x80 ? length : length.subarray(1);
      return rawTlv(root.tag, [0x81 + bytes.length, 0, ...bytes], root.content);
    },
  },
  {
    name: "indefinite length",
    apply: (_random, { root }) =>
      rawTlv(root.tag, [0x80], Buffer.concat([root.content, Buffer.from([0, 0])])),
  },
  {
    name: "oversized length",
    apply: (random, { root }) =>
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
    name: "outer nesting",
    apply: (random, { der }) => x509.sequence(nestedDer(random), der),
  },
  { name: "unchanged DER", apply: (_random, { der }) => der },
];

function splitRequest(der: Buffer) {
  const [info, algorithm, signature] = x509.children(x509.decode(der));
  return { info: info!.raw, oid: x509.decodeOid(x509.children(algorithm)[0]), signature: signature!.raw };
}

const corpus = loadCorpus().map(({ der }) => {
  const request = splitRequest(der);
  return { der, ...request, spki: x509.children(x509.decode(request.info))[2]!.raw };
});

const csrLabels = ["CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"];
const pemEdits = {
  "PEM whitespace": (random: Random, pem: string) => {
    const at = random.int(pem.length);
    return pem.slice(0, at) + random.pick([" ", "\n", "\t", "\r\n"]) + pem.slice(at);
  },
  "PEM character": (random: Random, pem: string) => {
    const at = random.int(pem.length);
    return pem.slice(0, at) + String.fromCharCode(random.int(128)) + pem.slice(at + 1);
  },
  "PEM truncation": (random: Random, pem: string) => pem.slice(0, random.int(pem.length)),
  "PEM prefix or suffix": (random: Random, pem: string) =>
    random.pick(["junk\n", "Certificate Request:\n", "\ufeff", ""]) + pem + random.pick(["", "x", pem]),
  "PEM label": (random: Random, pem: string) =>
    pem.replaceAll(
      "CERTIFICATE REQUEST",
      random.pick(["CERTIFICATE", "NEW CERTIFICATE REQUEST", "X509 CRL", "certificate request"]),
    ),
  "PEM padding": (random: Random, pem: string) => {
    const at = random.int(pem.length);
    return pem.slice(0, at) + "=" + pem.slice(at);
  },
};
const pemCases = Object.entries(pemEdits);

type FuzzCase = { name: string; run: (random: Random) => void };
type FuzzTarget = { name: string; baselines: FuzzCase[]; cases: FuzzCase[] };
type DomainError = typeof CsrError | typeof x509.DerError;

function allowRejection<T>(parse: () => T, domain: DomainError) {
  try {
    return parse();
  } catch (error) {
    if (!(error instanceof domain)) throw error;
    return undefined;
  }
}

function expectRejection(parse: () => unknown, domain: DomainError, expected: RegExp) {
  try {
    parse();
  } catch (error) {
    if (error instanceof domain && expected.test(error.message)) return;
    throw new Error(`Expected ${domain.name} matching ${expected}, got ${String(error)}.`, { cause: error });
  }
  throw new Error(`Accepted malformed input, expected ${domain.name} matching ${expected}.`);
}

function seedMutations(seeds: DerSeed[], parse: (der: Buffer, random: Random, unchanged: boolean) => void) {
  return mutations.map((mutation): FuzzCase => ({
    name: mutation.name,
    run: (random) => {
      const seedIndex = random.int(seeds.length);
      const item = seeds[seedIndex]!;
      // Choose a different corpus request for the splice when there is more than one seed.
      const spliceSource = seeds[(seedIndex + 1 + random.int(seeds.length - 1)) % seeds.length]!.der;
      parse(mutation.apply(random, item, spliceSource), random, mutation.name === "unchanged DER");
    },
  }));
}

function derTarget(
  name: string,
  parse: (der: Buffer, random: Random, unchanged: boolean) => unknown,
  ...seeds: Buffer[]
): FuzzTarget {
  return {
    name,
    baselines: seeds.map((der) => ({
      name: "unchanged DER",
      run: (random) => {
        parse(der, random, true);
      },
    })),
    cases: seedMutations(seeds.map(derSeed), (der, random, unchanged) => {
      allowRejection(() => parse(der, random, unchanged), x509.DerError);
    }),
  };
}

function structuredTarget<T>(name: string, parse: (der: Buffer) => T, cases: DerCase<T>[]): FuzzTarget {
  const checks = cases.map(({ name: caseName, build }): FuzzCase => ({
    name: caseName,
    run: (random) => {
      const { der, expected } = build(random);
      if (expected instanceof RegExp) {
        expectRejection(() => parse(der), x509.DerError, expected);
      } else if (!isDeepStrictEqual(parse(der), expected)) {
        throw new Error("Decoded fields differ from the fixture.");
      }
    },
  }));
  return { name, baselines: [checks[0]!], cases: checks };
}

const spki = corpus[0]!.spki;
const subject = x509.name([{ type: "CN", value: "fuzz test" }]);
const utcTime = x509.time(new Date("2026-01-01T00:00:00Z"));
const generalizedTime = x509.time(new Date("2050-01-01T00:00:00Z"));
const { privateKey: signingKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const signingSpki = x509.spkiDer(signingKey);
const keyId = x509.keyIdentifier(spki);
const basic = x509.basicConstraintsValue(true, 0);
const usage = x509.keyUsageValue(["digitalSignature", "keyAgreement"]);
const eku = x509.extendedKeyUsageValue([x509.OID.clientAuth]);
const ski = x509.subjectKeyIdentifierValue(keyId);
const aki = x509.authorityKeyIdentifierValue(keyId);
const { certificate, crl, certExtensions, certificateCases, crlCases } = structuredCases(spki);

let csrAccepted = 0;
function checkCorpusCsr(input: string, unchanged = false) {
  const key = unchanged ? validateCsr(input) : allowRejection(() => validateCsr(input), CsrError);
  if (!key) return;
  const accepted = splitRequest(x509.fromPem(input, csrLabels));
  // RSA's optional NULL parameter can change without changing the signed request or its signature.
  const original = corpus.find(
    (item) =>
      item.info.equals(accepted.info) &&
      item.oid === accepted.oid &&
      item.signature.equals(accepted.signature),
  );
  if (!original || !original.spki.equals(x509.spkiDer(key)))
    throw new Error("Accepted a mutation that changed the request or its public key.");
  csrAccepted += 1;
}

const clientUsage = (random: Random) =>
  x509.extension(
    x509.OID.keyUsage,
    true,
    x509.keyUsageValue(["digitalSignature", random.pick(["keyAgreement", "keyEncipherment"] as const)]),
  );
const subjectKeyId = (value: Buffer) => x509.extension(x509.OID.subjectKeyIdentifier, false, value);

function signedAttributes(name: string, build: (random: Random) => Buffer[], rejection?: RegExp): FuzzCase {
  return {
    name,
    run: (random) => {
      const { pem } = buildCsr({ key: signingKey, attributes: build(random) });
      if (rejection) {
        expectRejection(() => validateCsr(pem), CsrError, rejection);
      } else {
        if (!signingSpki.equals(x509.spkiDer(validateCsr(pem))))
          throw new Error("Signed request decoded to the wrong public key.");
        csrAccepted += 1;
      }
    },
  };
}

const csrTarget: FuzzTarget = {
  name: "validateCsr",
  baselines: corpus.map(({ der }) => ({
    name: "unchanged DER",
    run: () => checkCorpusCsr(`\n${toCsrPem(der).replaceAll("\n", "\r\n")}\t`, true),
  })),
  cases: [
    ...seedMutations(
      corpus.map(({ der }) => derSeed(der)),
      (der, random, unchanged) => {
        const pem = toCsrPem(der);
        checkCorpusCsr(
          !unchanged && random.next() < 0.15 ? random.pick(pemCases)[1](random, pem) : pem,
          unchanged,
        );
      },
    ),
    ...pemCases.map(([name, edit]): FuzzCase => ({
      name,
      run: (random) => checkCorpusCsr(edit(random, toCsrPem(random.pick(corpus).der))),
    })),
    signedAttributes("signed allowed extensions", (random) => [
      extensionRequest([clientUsage(random), subjectKeyId(x509.subjectKeyIdentifierValue(random.bytes(20)))]),
    ]),
    signedAttributes(
      "signed repeated extension",
      (random) => {
        const extension = clientUsage(random);
        return [extensionRequest([extension, extension])];
      },
      /repeats extension/,
    ),
    signedAttributes(
      "signed forbidden KeyUsage",
      (random) => [
        extensionRequest([
          x509.extension(
            x509.OID.keyUsage,
            true,
            x509.keyUsageValue(["digitalSignature", random.pick(["keyCertSign", "cRLSign"] as const)]),
          ),
        ]),
      ],
      /key usages outside the client policy/,
    ),
    signedAttributes(
      "signed nested extension value",
      (random) => [extensionRequest([clientUsage(random), subjectKeyId(nestedDer(random))])],
      /Expected a KeyIdentifier OCTET STRING/,
    ),
  ],
};

const parsePem = derTarget("fromPem", (der) => x509.fromPem(toCsrPem(der), csrLabels), corpus[0]!.der);
parsePem.cases.push(
  ...pemCases.map(([name, edit]): FuzzCase => ({
    name,
    run: (random) => {
      allowRejection(
        () => x509.fromPem(edit(random, toCsrPem(random.pick(corpus).der)), csrLabels),
        x509.DerError,
      );
    },
  })),
);

const targets = [
  csrTarget,
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
  parsePem,
  derTarget("keyIdentifier", x509.keyIdentifier, spki),
  derTarget("parseExtensions", (der) => x509.parseExtensions(x509.decode(der)), certExtensions),
  derTarget("decodeKeyUsage", x509.decodeKeyUsage, usage),
  derTarget("decodeBasicConstraints", x509.decodeBasicConstraints, basic),
  derTarget("decodeExtendedKeyUsage", x509.decodeExtendedKeyUsage, eku),
  derTarget("decodeSubjectKeyIdentifier", x509.decodeSubjectKeyIdentifier, ski),
  derTarget("decodeAuthorityKeyIdentifier", x509.decodeAuthorityKeyIdentifier, aki),
  structuredTarget("parseCertificate", x509.parseCertificate, certificateCases),
  structuredTarget("parseCrl", x509.parseCrl, crlCases),
];

// oxlint-disable-next-line unicorn/require-post-message-target-origin -- Node MessagePort has no target origin.
parentPort!.postMessage(targets.map(({ name }) => name));
const random = prng(seed);
const csrMutations = new Set<string>();
let slowestMs = 0;
for (let iteration = 0; iteration < iterations; iteration++) {
  for (const [index, target] of targets.entries()) {
    const baseline = iteration < target.baselines.length;
    const fuzzCase = baseline
      ? target.baselines[iteration]!
      : target.cases[(iteration - target.baselines.length) % target.cases.length]!;
    const label = `Seed ${seed}, ${target.name}, iteration ${iteration} (${fuzzCase.name})`;
    const started = process.hrtime.bigint();
    Atomics.store(progress, 0, BigInt(iteration * targets.length + index + 1));
    try {
      fuzzCase.run(random);
      if (!baseline && target === csrTarget) csrMutations.add(fuzzCase.name);
    } catch (error) {
      const details = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
      throw new Error(`${label}: ${details}`, { cause: error });
    } finally {
      Atomics.store(progress, 0, 0n);
    }
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    if (ms > caseBoundMs) throw new Error(`${label} took ${ms.toFixed(2)} ms (bound ${caseBoundMs} ms).`);
    slowestMs = Math.max(ms, slowestMs);
  }
}
// oxlint-disable-next-line unicorn/require-post-message-target-origin -- Node MessagePort has no target origin.
parentPort!.postMessage({ csrAccepted, csrMutations: [...csrMutations], slowestMs } satisfies FuzzResult);
