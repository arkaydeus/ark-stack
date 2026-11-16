// Seeded mutation fuzz test for CSR parsing (x509.ts + pki.validateCsr), ticket FD-17.
//
// Starting from the committed OpenSSL-made corpus, each iteration applies one to four random
// mutations (bit flips, interesting bytes, insertions, deletions, truncation, length and tag
// rewrites at real TLV headers, chunk duplication, cross-corpus splices, PEM text edits) and
// checks the property:
//
//   validateCsr either throws the typed CsrError within the time bound, or returns a key whose
//   self-signature verifies: the key must be one of the corpus keys, and OpenSSL
//   (`openssl req -verify`), an independent parser, must verify the mutated request.
//
// Runs are reproducible: ARK_CSR_FUZZ_SEED (default 0x00fd17) and ARK_CSR_FUZZ_ITERATIONS
// (default 10 000, the CI size) select the run. The summary line is the PR record.

import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { testOpenSsl } from "./test-openssl.ts";

import { headerOffsets, loadCorpus, prng, sha256, toCsrPem } from "./csr-test-kit.ts";

process.env.DATABASE_URL ??= "postgres://unused:unused@127.0.0.1:9/unused";
const pki = await import("./pki.ts");
const x509 = await import("./x509.ts");

const SEED = Number(process.env.ARK_CSR_FUZZ_SEED ?? 0x00fd17);
const ITERATIONS = Number(process.env.ARK_CSR_FUZZ_ITERATIONS ?? 10_000);
/** Each iteration must finish within this bound (milliseconds). */
const ITERATION_BOUND_MS = 250;
const INTERESTING = [
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x1f, 0x30, 0x31, 0x7f, 0x80, 0x81, 0x82, 0x84, 0x85, 0xa0, 0xff,
];

const corpus = loadCorpus().map((item) => ({
  ...item,
  headers: headerOffsets(item.der),
  spki: x509.spkiDer(pki.validateCsr(item.pem)),
}));

const corpusSpkis = corpus.map((item) => item.spki);

type Random = ReturnType<typeof prng>;

function mutateDer(random: Random, input: Buffer, item: (typeof corpus)[number]) {
  let der = Buffer.from(input);
  const position = () => random.int(Math.max(1, der.length));
  const header = () => item.headers[random.int(item.headers.length)]!;
  const operator = random.int(11);
  switch (operator) {
    case 0: {
      const at = position();
      der[at] = der[at]! ^ (1 << random.int(8));
      break;
    }
    case 1:
      der[position()] = random.pick(INTERESTING);
      break;
    case 2: {
      const at = position();
      der = Buffer.concat([der.subarray(0, at), random.bytes(1 + random.int(8)), der.subarray(at)]);
      break;
    }
    case 3: {
      const at = position();
      der = Buffer.concat([der.subarray(0, at), der.subarray(Math.min(der.length, at + 1 + random.int(8)))]);
      break;
    }
    case 4:
      der = der.subarray(0, random.int(der.length));
      break;
    case 5:
      der = Buffer.concat([der, random.bytes(1 + random.int(32))]);
      break;
    case 6: {
      // Rewrite a real length byte: off by a little, a long-form prefix, or an interesting value.
      const at = header() + 1;
      if (at < der.length)
        der[at] = random.next() < 0.5 ? (der[at]! + random.int(5) - 2) & 0xff : random.pick(INTERESTING);
      break;
    }
    case 7: {
      const at = header();
      if (at < der.length) der[at] = random.pick(INTERESTING);
      break;
    }
    case 8: {
      // Duplicate a chunk somewhere else (repeated fields, nested copies).
      const from = position();
      const chunk = der.subarray(from, Math.min(der.length, from + 1 + random.int(48)));
      const to = position();
      der = Buffer.concat([der.subarray(0, to), chunk, der.subarray(to)]);
      break;
    }
    case 9: {
      // Splice the head of this request onto the tail of another one.
      const other = random.pick(corpus).der;
      der = Buffer.concat([der.subarray(0, position()), other.subarray(random.int(other.length))]);
      break;
    }
    default: {
      // Wrap the whole value, or a nested header, in an extra SEQUENCE or indefinite length.
      der =
        random.next() < 0.5
          ? x509.sequence(der)
          : Buffer.concat([Buffer.from([0x30, 0x80]), der, Buffer.from([0, 0])]);
      break;
    }
  }
  return der;
}

function mutatePem(random: Random, pem: string) {
  const at = random.int(pem.length);
  switch (random.int(6)) {
    case 0:
      return `${pem.slice(0, at)}${random.pick([" ", "\n", "\t", "\r\n"])}${pem.slice(at)}`;
    case 1:
      return `${pem.slice(0, at)}${String.fromCharCode(random.int(128))}${pem.slice(at + 1)}`;
    case 2:
      return pem.slice(0, at);
    case 3:
      return `${random.pick(["junk\n", "Certificate Request:\n", "﻿", ""])}${pem}${random.pick(["", "x", pem])}`;
    case 4:
      return pem.replace(
        "CERTIFICATE REQUEST",
        random.pick(["CERTIFICATE", "NEW CERTIFICATE REQUEST", "X509 CRL", "certificate request"]),
      );
    default:
      return `${pem.slice(0, at)}=${pem.slice(at)}`;
  }
}

describe("CSR parser seeded mutation fuzz (FD-17 hardening)", () => {
  test(
    `${ITERATIONS} mutations from seed ${SEED}: clean rejection or a verified signature`,
    () => {
      const random = prng(SEED);
      const opensslBin = testOpenSsl();
      const work = mkdtempSync(join(tmpdir(), "ark-csr-fuzz-"));
      const outcomes = new Map<string, number>();
      const verifiedByOpenssl = new Set<string>();
      let accepted = 0;
      let slowest = 0;
      let totalMs = 0;
      try {
        for (let iteration = 0; iteration < ITERATIONS; iteration++) {
          const item = random.pick(corpus);
          let der = item.der;
          const rounds = 1 + random.int(4);
          for (let round = 0; round < rounds; round++) der = mutateDer(random, der, item);
          let pem = toCsrPem(der);
          if (random.next() < 0.15) pem = mutatePem(random, pem);

          const started = performance.now();
          let key: ReturnType<typeof pki.validateCsr> | null = null;
          let error: unknown;
          try {
            key = pki.validateCsr(pem);
          } catch (caught) {
            error = caught;
          }
          const ms = performance.now() - started;
          totalMs += ms;
          slowest = Math.max(slowest, ms);
          const label = `seed ${SEED} iteration ${iteration} (${item.name})`;
          expect(ms, label).toBeLessThan(ITERATION_BOUND_MS);

          if (!key) {
            if (!(error instanceof pki.CsrError)) {
              throw new Error(`${label}: escaped as ${(error as Error)?.name}: ${(error as Error)?.message}`);
            }
            const reason = error.message
              .replace(/[0-9.]{6,}/g, "<oid>")
              .replace(/^The CSR is malformed: /, "");
            outcomes.set(reason, (outcomes.get(reason) ?? 0) + 1);
            continue;
          }

          // Accepted: the key must be one of the corpus keys (splices can rebuild another corpus
          // request whole), and the request must verify in OpenSSL. A self-signature for any
          // other key cannot be forged without that key.
          accepted += 1;
          const acceptedSpki = x509.spkiDer(key);
          expect(
            corpusSpkis.some((spki) => spki.equals(acceptedSpki)),
            label,
          ).toBe(true);
          const parsedDer = x509.fromPem(pem, ["CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"]);
          const digest = sha256(parsedDer);
          if (!verifiedByOpenssl.has(digest)) {
            const path = join(work, `${digest}.der`);
            writeFileSync(path, parsedDer);
            const check = Bun.spawnSync([
              opensslBin,
              "req",
              "-inform",
              "DER",
              "-in",
              path,
              "-verify",
              "-noout",
            ]);
            expect(check.exitCode, `${label}: openssl req -verify ${check.stderr.toString()}`).toBe(0);
            verifiedByOpenssl.add(digest);
          }
        }
      } finally {
        rmSync(work, { recursive: true, force: true });
      }
      expect(verifiedByOpenssl.size, "The independent signature oracle must execute").toBeGreaterThan(0);
      const top = [...outcomes].toSorted((a, b) => b[1] - a[1]).slice(0, 6);
      console.log(
        `CSR fuzz: seed ${SEED}, ${ITERATIONS} iterations, ${ITERATIONS - accepted} rejected with CsrError, ` +
          `${accepted} accepted (all with a corpus key; ${verifiedByOpenssl.size} distinct DER verified by ` +
          `openssl req -verify); max ${slowest.toFixed(2)} ms, ` +
          `mean ${(totalMs / ITERATIONS).toFixed(3)} ms, bound ${ITERATION_BOUND_MS} ms; top rejections: ` +
          top.map(([reason, count]) => `${reason} ×${count}`).join("; "),
      );
    },
    { timeout: 120_000 },
  );
});
