import { expect, test } from "bun:test";
import { Worker } from "node:worker_threads";

import type { FuzzResult } from "./csr-fuzz-worker.ts";
import * as x509 from "./x509.ts";

const SEED = Number(process.env.ARK_CSR_FUZZ_SEED ?? 0x00fd17);
const ITERATIONS = Number(process.env.ARK_CSR_FUZZ_ITERATIONS ?? 10_000);
const CASE_BOUND_MS = 250;
const STARTUP_BOUND_MS = 15_000;

function watchWorker(worker: Worker, progress: BigInt64Array, caseBoundMs: number) {
  const launched = performance.now();
  let targets: string[] | undefined;
  let watchdog: ReturnType<typeof setInterval> | undefined;
  let previous = 0n;
  let lastProgress = launched;
  return new Promise<{ result: FuzzResult; targets: string[] }>((resolve, reject) => {
    worker.on("message", (message: string[] | FuzzResult) => {
      if (Array.isArray(message)) targets = message;
      else if (targets) resolve({ result: message, targets });
      else reject(new Error("Fuzz worker reported results before naming its targets."));
    });
    worker.once("error", reject);
    worker.once("exit", (code) =>
      reject(new Error(`Fuzz worker exited with code ${code} before reporting results.`)),
    );

    // A timer on the parser's own thread cannot detect a synchronous loop.
    watchdog = setInterval(() => {
      const active = Atomics.load(progress, 0);
      const now = performance.now();
      if (active !== previous) {
        previous = active;
        lastProgress = now;
      }
      if (active !== 0n && now - lastProgress > caseBoundMs) {
        const index = Number(active - 1n);
        const label = targets
          ? `${targets[index % targets.length]}, iteration ${Math.floor(index / targets.length)}`
          : `input ${index}`;
        reject(new Error(`Seed ${SEED}, ${label} exceeded ${caseBoundMs} ms.`));
      } else if (!targets && now - launched > STARTUP_BOUND_MS) {
        reject(new Error("Fuzz worker did not start within 15 seconds."));
      }
    }, 10);
  }).finally(async () => {
    clearInterval(watchdog);
    await worker.terminate();
  });
}

const sharedProgress = () => new BigInt64Array(new SharedArrayBuffer(BigInt64Array.BYTES_PER_ELEMENT));

test("the fuzz watchdog detects and terminates a synchronous loop", async () => {
  const progress = sharedProgress();
  const worker = new Worker(
    `
      const { parentPort, workerData } = require("node:worker_threads");
      parentPort.postMessage(["synchronous loop"]);
      Atomics.store(workerData, 0, 1n);
      for (;;) Atomics.load(workerData, 0);
    `,
    { eval: true, workerData: progress },
  );
  const exit = new Promise<number>((resolve) => worker.once("exit", resolve));
  await expect(watchWorker(worker, progress, 50)).rejects.toThrow(
    `Seed ${SEED}, synchronous loop, iteration 0 exceeded 50 ms.`,
  );
  expect(await exit).not.toBe(0);
});

test(
  "seeded fuzz of CSR policy and DER decoders",
  async () => {
    if (!Number.isSafeInteger(SEED) || SEED < 0 || SEED > 0xffffffff)
      throw new Error("ARK_CSR_FUZZ_SEED must be an unsigned 32-bit integer.");
    if (!Number.isSafeInteger(ITERATIONS) || ITERATIONS < 1)
      throw new Error("ARK_CSR_FUZZ_ITERATIONS must be a positive integer.");

    const progress = sharedProgress();
    const worker = new Worker(new URL("./csr-fuzz-worker.ts", import.meta.url), {
      workerData: { progress, seed: SEED, iterations: ITERATIONS, caseBoundMs: CASE_BOUND_MS },
    });
    const { result, targets } = await watchWorker(worker, progress, CASE_BOUND_MS);
    console.log(
      `PKI fuzz seed ${SEED}: ${ITERATIONS} iterations across ${targets.length} entry points, ` +
        `${result.csrAccepted} CSRs accepted, ` +
        `slowest input ${result.slowestMs.toFixed(2)} ms (bound ${CASE_BOUND_MS} ms).\n` +
        `CSR mutations exercised: ${result.csrMutations.join(", ")}.`,
    );
  },
  { timeout: Math.max(120_000, ITERATIONS * 10) },
);

const algorithm = x509.ecdsaWithSha256();
const wrongAlgorithm = x509.set(x509.oid(x509.OID.ecdsaWithSha256));
const name = x509.sequence();
const timestamp = x509.time(new Date("2026-01-01T00:00:00Z"));
const signature = x509.bitString(Buffer.from([1]));
const validity = (notAfter?: Buffer) => x509.sequence(timestamp, ...(notAfter ? [notAfter] : []));
const certificate = (dates: Buffer, serial = x509.integer(1), ...optional: Buffer[]) =>
  x509.sequence(serial, algorithm, name, dates, name, x509.sequence(), ...optional);
const crl = (...entries: Buffer[]) => x509.sequence(algorithm, name, timestamp, ...entries);
const signed = (body: Buffer, bits = signature) => x509.sequence(body, algorithm, bits);
const crlExtensions = x509.explicit(
  0,
  x509.sequence(x509.extension(x509.OID.crlNumber, false, x509.integer(1))),
);
const v2Crl = (...fields: Buffer[]) => x509.sequence(x509.integer(1), algorithm, name, timestamp, ...fields);
const revokedEntry = (serial: Buffer, date: Buffer) => x509.sequence(x509.sequence(serial, date));
const negativeSerial = x509.tlv(0x02, Buffer.from([0xff]));
const nonMinimalSerial = x509.tlv(0x02, Buffer.from([0, 1]));
const impossibleDate = x509.tlv(0x17, Buffer.from("260230000000Z"));
const overrun = Buffer.from([0x30, 0x7f]);
const time = (content: Buffer | string) => x509.decodeTime(x509.decode(x509.tlv(0x17, Buffer.from(content))));

test.each<[string, () => unknown, RegExp]>([
  ["negative reader offset", () => x509.readNode(name, -1), /Invalid DER offset/],
  ["fractional reader offset", () => x509.readNode(name, 0.5), /Invalid DER offset/],
  ["missing constructed value", () => x509.children(undefined), /constructed DER/],
  ["empty serial number", () => x509.serialHex(x509.decode(x509.tlv(0x02))), /Empty serial number/],
  [
    "negative serial number",
    () => x509.serialHex(x509.decode(x509.tlv(0x02, Buffer.from([0xff])))),
    /Negative serial number/,
  ],
  [
    "non-minimal serial number",
    () => x509.serialHex(x509.decode(x509.tlv(0x02, Buffer.from([0, 1])))),
    /Non-minimal serial number/,
  ],
  [
    "oversized serial number",
    () => x509.serialHex(x509.decode(x509.integerFromBytes(Buffer.alloc(21, 1)))),
    /Oversized serial number/,
  ],
  ["impossible time", () => time("260230000000Z"), /Invalid DER time/],
  [
    "high bit in time",
    () => time(Buffer.from([0xb2, ...Buffer.from("60101000000Z")])),
    /UTCTime or GeneralizedTime/,
  ],
  [
    "missing certificate validity date",
    () => x509.parseCertificate(signed(certificate(validity()))),
    /certificate Validity/,
  ],
  [
    "negative certificate serial",
    () => x509.parseCertificate(signed(certificate(validity(timestamp), negativeSerial))),
    /Negative serial number/,
  ],
  [
    "non-minimal revoked certificate serial",
    () => x509.parseCrl(signed(crl(revokedEntry(nonMinimalSerial, timestamp)))),
    /Non-minimal serial number/,
  ],
  [
    "impossible certificate validity date",
    () => x509.parseCertificate(signed(certificate(validity(impossibleDate)))),
    /Invalid DER time/,
  ],
  [
    "impossible CRL revocation date",
    () => x509.parseCrl(signed(crl(revokedEntry(x509.integer(1), impossibleDate)))),
    /Invalid DER time/,
  ],
  [
    "certificate field that extends beyond its enclosing DER",
    () => x509.parseCertificate(signed(certificate(validity(timestamp), x509.integer(1), overrun))),
    /past the end/,
  ],
  [
    "CRL entry field that extends beyond its enclosing DER",
    () => x509.parseCrl(signed(crl(x509.sequence(overrun)))),
    /past the end/,
  ],
  [
    "duplicate CRL extensions wrappers",
    () => x509.parseCrl(signed(v2Crl(crlExtensions, crlExtensions))),
    /Unexpected TBSCertList field/,
  ],
  [
    "multiple values inside a CRL extensions wrapper",
    () => x509.parseCrl(signed(v2Crl(x509.tlv(0xa0, x509.decode(crlExtensions).content, name)))),
    /Malformed extensions wrapper/,
  ],
  [
    "extra certificate field",
    () => x509.parseCertificate(x509.sequence(certificate(validity(timestamp)), algorithm, signature, name)),
    /Malformed Certificate/,
  ],
  [
    "certificate signature algorithm with the wrong tag",
    () => x509.parseCertificate(x509.sequence(certificate(validity(timestamp)), wrongAlgorithm, signature)),
    /signature AlgorithmIdentifier/,
  ],
  [
    "missing CRL thisUpdate",
    () => x509.parseCrl(signed(x509.sequence(algorithm, name))),
    /UTCTime or GeneralizedTime/,
  ],
  [
    "missing CRL entry revocation date",
    () => x509.parseCrl(signed(crl(x509.sequence(x509.sequence(x509.integer(1)))))),
    /UTCTime or GeneralizedTime/,
  ],
  [
    "extra CRL field",
    () => x509.parseCrl(x509.sequence(crl(), algorithm, signature, name)),
    /Malformed CertificateList/,
  ],
  [
    "CRL signature algorithm with the wrong tag",
    () => x509.parseCrl(x509.sequence(crl(), wrongAlgorithm, signature)),
    /signature AlgorithmIdentifier/,
  ],
  [
    "malformed CRL signature bit string",
    () => x509.parseCrl(signed(crl(), x509.tlv(0x03, Buffer.from([8, 0])))),
    /Malformed signature BIT STRING/,
  ],
])("DER domain error for %s", (_name, parse, message) => {
  expect(parse).toThrow(x509.DerError);
  expect(parse).toThrow(message);
});

test("DER time preserves an early GeneralizedTime calendar year", () => {
  const early = x509.tlv(0x18, Buffer.from("00960229000000Z"));
  const expected = "0096-02-29T00:00:00.000Z";
  expect(x509.decodeTime(x509.decode(early)).toISOString()).toBe(expected);
  const cert = x509.parseCertificate(signed(certificate(x509.sequence(early, timestamp))));
  expect(cert.notBefore.toISOString()).toBe(expected);
  const list = x509.parseCrl(signed(x509.sequence(algorithm, name, early)));
  expect(list.thisUpdate.toISOString()).toBe(expected);
});
