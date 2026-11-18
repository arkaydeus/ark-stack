import { expect, test } from "bun:test";
import { createPrivateKey } from "node:crypto";

import { buildCsr, extensionRequest, rawTlv, toCsrPem } from "./csr-test-kit.ts";
import { testOpenSsl } from "./test-openssl.ts";
import * as x509 from "./x509.ts";

process.env.DATABASE_URL ??= "postgres://unused:unused@127.0.0.1:9/unused";
const { CsrError, validateCsr } = await import("./pki.ts");

type CorpusCase = { name: string; der: Buffer } & (
  | { ark: "accept"; openssl: "accept" }
  | { ark: RegExp; openssl: "reject" }
  | { ark: RegExp; openssl: "accept"; strictness: string }
);

test(
  "CSR parser and client policy agree with OpenSSL except for listed strictness differences",
  () => {
    const executable = testOpenSsl();
    function openssl(args: string[], stdin?: Buffer) {
      const result = Bun.spawnSync([executable, ...args], {
        stdin: stdin ?? "ignore",
        stderr: "pipe",
        timeout: 15_000,
        killSignal: "SIGKILL",
        env: { ...process.env, LC_ALL: "C" },
      });
      if (result.signalCode) throw new Error(`OpenSSL ${args[0]} terminated with ${result.signalCode}.`);
      return { ...result, diagnostics: result.stderr.toString() };
    }
    function generate(args: string[], stdin?: Buffer) {
      const result = openssl(args, stdin);
      // Key generation output is private test material. Only print diagnostics on failure.
      expect(result.exitCode, result.diagnostics).toBe(0);
      return result.stdout;
    }
    const ecKey = (curve: string) =>
      generate(["genpkey", "-algorithm", "EC", "-pkeyopt", `ec_paramgen_curve:${curve}`]);
    const rsaKey = (bits: number) =>
      generate(["genpkey", "-algorithm", "RSA", "-pkeyopt", `rsa_keygen_bits:${bits}`]);
    function request(key: Buffer, ...options: string[]) {
      return generate(
        [
          "req",
          "-new",
          "-key",
          "/dev/stdin",
          "-config",
          "/dev/null",
          "-subj",
          "/CN=csr differential",
          "-outform",
          "DER",
          ...options,
        ],
        key,
      );
    }

    const p256 = ecKey("P-256");
    const p384 = ecKey("P-384");
    const rsa3072 = rsaKey(3072);
    const corpus: CorpusCase[] = [];
    const accept = (name: string, der: Buffer) =>
      corpus.push({ name, der, ark: "accept", openssl: "accept" });
    const reject = (name: string, der: Buffer, ark: RegExp) =>
      corpus.push({ name, der, ark, openssl: "reject" });
    const stricter = (name: string, der: Buffer, ark: RegExp, strictness: string) =>
      corpus.push({ name, der, ark, openssl: "accept", strictness });

    // Each allowed key shape with each digest the CA supports for it.
    for (const { name, key } of [
      { name: "P-256", key: p256 },
      { name: "P-384", key: p384 },
      { name: "RSA-3072", key: rsa3072 },
    ]) {
      for (const digest of ["sha256", "sha384", "sha512"])
        accept(`${name} / ${digest}`, request(key, `-${digest}`));
    }
    accept(
      "all supported requested extensions",
      request(
        p256,
        "-sha256",
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-addext",
        "keyUsage=critical,digitalSignature,keyAgreement,keyEncipherment",
        "-addext",
        "extendedKeyUsage=clientAuth",
        "-addext",
        "subjectKeyIdentifier=hash",
      ),
    );
    const [rsaInfo, , rsaSignature] = x509.children(x509.decode(request(rsa3072, "-sha256")));
    accept(
      "RSA signature algorithm with omitted NULL parameters",
      x509.sequence(rsaInfo!.raw, x509.sequence(x509.oid(x509.OID.sha256WithRsa)), rsaSignature!.raw),
    );

    const base = request(p256, "-sha256");
    const [info, , signature] = x509.children(x509.decode(base));
    const corrupted = Buffer.from(base);
    corrupted[corrupted.length - 1] = corrupted[corrupted.length - 1]! ^ 1;
    reject("corrupt self-signature", corrupted, /does not verify/);
    reject(
      "EC public key with RSA signature algorithm",
      x509.sequence(
        info!.raw,
        x509.sequence(x509.oid(x509.OID.sha256WithRsa), x509.tlv(0x05)),
        signature!.raw,
      ),
      /not accepted for its key/,
    );
    reject("truncated DER", base.subarray(0, -1), /past the end/);

    // These explicit exceptions compare OpenSSL's PKCS#10 verification with Ark's tighter
    // encoding and certificate-issuance policy. Each rejection must give the named reason.
    stricter(
      "SHA-224 signature",
      request(p256, "-sha224"),
      /not accepted for its key/,
      "The CA accepts SHA-256, SHA-384 and SHA-512.",
    );
    stricter(
      "RSA-PSS signature",
      request(rsa3072, "-sha256", "-sigopt", "rsa_padding_mode:pss"),
      /not accepted for its key/,
      "The CA accepts PKCS#1 v1.5 RSA signatures.",
    );
    stricter(
      "RSA-2048",
      request(rsaKey(2048), "-sha256"),
      /at least 3072 bits/,
      "RSA client keys have a 3072-bit minimum.",
    );
    stricter(
      "P-521",
      request(ecKey("P-521"), "-sha512"),
      /curve are not accepted/,
      "The allowed curves are P-256 and P-384.",
    );
    stricter(
      "Ed25519",
      request(generate(["genpkey", "-algorithm", "ED25519"])),
      /ed25519/,
      "The client key profile allows ECDSA and RSA.",
    );
    stricter(
      "subjectAltName request",
      request(p256, "-addext", "subjectAltName=DNS:client.example"),
      /which client certificates do not carry/,
      "Client identity is assigned by Ark.",
    );
    stricter(
      "unknown critical extension",
      request(p256, "-addext", "1.3.6.1.4.1.55555.1=critical,DER:05:00"),
      /which client certificates do not carry/,
      "Requested extensions must be on the client allowlist.",
    );
    stricter(
      "client and server EKUs",
      request(p256, "-addext", "extendedKeyUsage=clientAuth,serverAuth"),
      /other than clientAuth/,
      "Client authentication is the only allowed extended key usage.",
    );
    stricter(
      "CA request",
      request(p256, "-addext", "basicConstraints=critical,CA:TRUE"),
      /cannot be CAs/,
      "Client requests cannot ask for CA privileges.",
    );

    const body = x509.decode(base).content;
    const length = base.subarray(1, base.length - body.length);
    const lengthBytes = length[0]! < 0x80 ? [...length] : [...length.subarray(1)];
    stricter(
      "non-minimal outer length",
      rawTlv(0x30, [0x81 + lengthBytes.length, 0, ...lengthBytes], body),
      /Non-minimal DER length/,
      "The request must use canonical DER lengths.",
    );
    stricter(
      "trailing DER",
      Buffer.concat([base, x509.tlv(0x05)]),
      /Trailing data/,
      "The input must contain exactly one DER request.",
    );

    const p256Key = createPrivateKey(p256);
    const withSubject = (value: Buffer) =>
      buildCsr({
        key: p256Key,
        subject: x509.sequence(x509.set(x509.sequence(x509.oid(x509.OID.commonName), value))),
      }).der;
    accept("UTF-8 subject", withSubject(x509.utf8String("client café")));
    accept("BMPString subject", withSubject(x509.tlv(0x1e, Buffer.from([0x00, 0xe9]))));
    accept("UniversalString subject", withSubject(x509.tlv(0x1c, Buffer.from([0x00, 0x01, 0xf6, 0x00]))));
    for (const [name, value] of [
      ["truncated UTF-8", x509.tlv(0x0c, Buffer.from([0xc3]))],
      ["partial BMPString code unit", x509.tlv(0x1e, Buffer.from([0x00]))],
      ["isolated BMPString surrogate", x509.tlv(0x1e, Buffer.from([0xd8, 0x00]))],
      ["partial UniversalString code point", x509.tlv(0x1c, Buffer.from([0x00, 0x00, 0x00]))],
      ["out-of-range UniversalString code point", x509.tlv(0x1c, Buffer.from([0x00, 0x11, 0x00, 0x00]))],
    ] as const) {
      reject(name, withSubject(value), /Malformed CSR subject string/);
    }
    stricter(
      "non-ASCII IA5String",
      withSubject(x509.tlv(0x16, Buffer.from([0xe9]))),
      /Malformed CSR subject string/,
      "IA5String is restricted to ASCII.",
    );
    stricter(
      "invalid PrintableString character",
      withSubject(x509.tlv(0x13, Buffer.from("@"))),
      /Invalid PrintableString character/,
      "PrintableString has a restricted alphabet.",
    );

    // OpenSSL verifies the signature over these extension bytes without applying their schema or
    // Ark's certificate profile. Each malformed request is otherwise correctly signed.
    for (const item of [
      {
        name: "unknown KeyUsage bit after digitalSignature",
        extension: "2.5.29.15=DER:03:03:06:80:40",
        error: /Unknown KeyUsage bits/,
        strictness: "KeyUsage has nine defined bits.",
      },
      {
        name: "non-minimal KeyUsage",
        extension: "2.5.29.15=DER:03:02:00:80",
        error: /Non-minimal KeyUsage/,
        strictness: "DER omits trailing zero bits in a named bit list.",
      },
      {
        name: "empty KeyUsage",
        extension: "2.5.29.15=DER:03:01:00",
        error: /Non-minimal KeyUsage/,
        strictness: "KeyUsage requires at least one bit to be set.",
      },
      {
        name: "explicit default cA flag",
        extension: "2.5.29.19=DER:30:03:01:01:00",
        error: /default BasicConstraints cA flag/,
        strictness: "DER omits a field encoded with its default value.",
      },
      {
        name: "path length without a CA request",
        extension: "2.5.29.19=DER:30:03:02:01:00",
        error: /pathLenConstraint requires cA/,
        strictness: "Only a CA can specify a path length constraint.",
      },
      {
        name: "subject key identifier with trailing bytes",
        extension: "2.5.29.14=DER:04:01:42:00",
        error: /Trailing data/,
        strictness: "Even ignored extension values must contain a single valid DER value.",
      },
    ]) {
      stricter(item.name, request(p256, "-addext", item.extension), item.error, item.strictness);
    }
    const defaultCritical = x509.sequence(
      x509.oid(x509.OID.keyUsage),
      x509.tlv(0x01, Buffer.from([0])),
      x509.octetString(x509.keyUsageValue(["digitalSignature"])),
    );
    stricter(
      "explicit default critical flag",
      buildCsr({ key: p256Key, attributes: [extensionRequest([defaultCritical])] }).der,
      /default Extension critical flag/,
      "DER omits the default false critical flag.",
    );

    for (const item of corpus) {
      const result = openssl(["req", "-inform", "DER", "-verify", "-noout"], item.der);
      // OpenSSL before 3.3 can exit zero when a decoded request fails verification.
      const diagnostics = `${result.stdout.toString()}\n${result.diagnostics}`;
      const verified =
        result.exitCode === 0 && /^Certificate request self-signature verify OK\r?$/m.test(diagnostics);
      const label = `${item.name}${"strictness" in item ? ` (${item.strictness})` : ""}`;
      expect(verified, `${label}\n${diagnostics}`).toBe(item.openssl === "accept");

      let error: unknown;
      try {
        validateCsr(toCsrPem(item.der));
      } catch (caught) {
        error = caught;
      }
      if (!verified)
        expect(error, `${label}: Ark accepted a request rejected by OpenSSL`).toBeInstanceOf(CsrError);
      if (item.ark === "accept") {
        expect(error, label).toBeUndefined();
      } else {
        expect(error, label).toBeInstanceOf(CsrError);
        expect((error as Error).message, label).toMatch(item.ark);
      }
    }
  },
  { timeout: 60_000 },
);
