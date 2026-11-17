import { testOpenSsl } from "./test-openssl.ts";
// Private CA module tests (docs/design/front-door.md §3.10.1, ticket FD-13).
//
// OpenSSL is the independent check: every chain is verified with `openssl verify -x509_strict`,
// which applies the same strict profile as Python 3.13's default `VERIFY_X509_STRICT` (AKI
// required, critical CA basicConstraints, keyCertSign on CAs). No Python dependency is added.
// Only public material (certificates, CRLs, CSRs) is written to the temporary directory; CSR test
// keys are thrown away to /dev/null as OpenSSL creates them.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createPrivateKey, createPublicKey, X509Certificate } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createId, privilegedRequestHash, parseEnvFile } from "@ark-stack/shared";

import type { ClientCertificateSummary, IssueClientCertificateInput } from "./pki.ts";
import type { ParsedCertificate, Node } from "./x509.ts";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const pki = await import("./pki.ts");
const x509 = await import("./x509.ts");
const { assertSecretRevealable } = await import("../access.ts");
const { db, sql } = await import("../db.ts");
const { clientCertificates, privateCas, secrets, projects, user, session, platformAccess, stepUpGrants } =
  await import("../schema.ts");
const { decryptSecret } = await import("@ark-stack/shared");
const { eq, inArray } = await import("drizzle-orm");

const DAY = 86_400_000;
let dir = "";
const createdCas: string[] = [];

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ark-pki-test-"));
});

afterAll(async () => {
  if (createdCas.length) {
    const caRows = await db.select().from(privateCas).where(inArray(privateCas.id, createdCas));
    const certRows = await db
      .select()
      .from(clientCertificates)
      .where(inArray(clientCertificates.caId, createdCas));
    const secretIds = [
      ...caRows.map((row) => row.keySecretId),
      ...certRows.flatMap((row) => (row.keySecretId ? [row.keySecretId] : [])),
    ];
    await db.delete(clientCertificates).where(inArray(clientCertificates.caId, createdCas));
    await db.delete(privateCas).where(inArray(privateCas.id, createdCas));
    if (secretIds.length) await db.delete(secrets).where(inArray(secrets.id, secretIds));
  }
  if (dir) await rm(dir, { recursive: true, force: true });
});

const opensslBin = testOpenSsl();

function openssl(args: string[], stdin?: string) {
  const result = Bun.spawnSync([opensslBin, ...args], {
    stdin: stdin === undefined ? "ignore" : Buffer.from(stdin),
  });
  return { code: result.exitCode, stdout: result.stdout.toString(), stderr: result.stderr.toString() };
}

let fileCounter = 0;
async function file(name: string, contents: string) {
  const path = join(dir, `${(fileCounter += 1)}-${name}`);
  await Bun.write(path, contents);
  return path;
}

async function newCa(
  name = "storefront/production",
  purpose: (typeof pki.CA_PURPOSES)[number] = "db-client",
  now?: Date,
) {
  const ca = await pki.createPrivateCa({ purpose, name, now });
  createdCas.push(ca.id);
  return ca;
}

/** Most tests deliberately bind generated keys to the existing owner-only platform resource. */
function issue(input: IssueClientCertificateInput) {
  return pki.issueClientCertificate({
    keyOwner: { resourceType: "platform", resourceId: "platform" },
    ...input,
  });
}

/** An OpenSSL-made CSR. The key goes to /dev/null: only the request is kept. */
function csr(keySpec: string[], extensions: string[] = []) {
  const result = openssl([
    "req",
    "-new",
    ...keySpec,
    "-nodes",
    "-keyout",
    "/dev/null",
    "-subj",
    "/CN=chosen-by-the-client",
    ...extensions.flatMap((item) => ["-addext", item]),
    "-out",
    "-",
  ]);
  expect(result.code, result.stderr).toBe(0);
  return result.stdout;
}
const P256 = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"];

function extensionOf(cert: ParsedCertificate, id: string) {
  const found = cert.extensions.find((item) => item.id === id);
  expect(found, id).toBeDefined();
  return found!;
}

function parsePem(pem: string) {
  return x509.parseCertificate(x509.fromPem(pem, ["CERTIFICATE"]));
}

describe("chain verification with OpenSSL", () => {
  test("an issued certificate verifies strictly against its CA and fails against another CA", async () => {
    const ca = await newCa();
    const other = await newCa(); // same purpose and name: only the key and serialNumber differ
    const { certificate } = await issue({
      caId: ca.id,
      subjectCn: "appdb_storefront_production",
    });
    const caPath = await file("ca.pem", ca.certPem);
    const otherPath = await file("other.pem", other.certPem);
    const leafPath = await file("leaf.pem", certificate.certPem!);

    const strict = ["verify", "-x509_strict", "-purpose", "sslclient"];
    const good = openssl([...strict, "-CAfile", caPath, leafPath]);
    expect(good.code, good.stdout + good.stderr).toBe(0);
    expect(good.stdout).toContain(": OK");

    const wrong = openssl([...strict, "-CAfile", otherPath, leafPath]);
    expect(wrong.code).not.toBe(0);
    expect(wrong.stdout + wrong.stderr).toMatch(
      /unable to get local issuer certificate|certificate signature failure/,
    );

    // A PgBouncer-style bundle with several generation CAs picks the issuer by AKI.
    const bundle = await file("bundle.pem", other.certPem + ca.certPem);
    expect(openssl([...strict, "-CAfile", bundle, leafPath]).code).toBe(0);

    // The CA itself passes the strict profile as a trust anchor and as a chain element.
    expect(openssl(["verify", "-x509_strict", "-CAfile", caPath, caPath]).code).toBe(0);
    expect(openssl(["verify", "-x509_strict", "-partial_chain", "-trusted", caPath, leafPath]).code).toBe(0);
  });
});

describe("strict name encoding", () => {
  test("PrintableString rejects invalid ASCII and non-ASCII characters", () => {
    expect(x509.printableString("AZaz09 '()+,-./:=?")[0]).toBe(0x13);
    for (const value of ["pca_id", "@", "é", "\u0000", "\n"])
      expect(() => x509.printableString(value)).toThrow(x509.DerError);
  });

  test("CA and leaf names use valid PrintableStrings and parse and verify in Go", async () => {
    const ca = await newCa("go-parser");
    const { certificate } = await issue({ caId: ca.id, subjectCn: "strict-client" });
    const caParsed = parsePem(ca.certPem);
    const leafParsed = parsePem(certificate.certPem!);
    expect(leafParsed.issuerDer).toEqual(caParsed.subjectDer);
    function checkStrings(node: Node) {
      if (node.tag === 0x13) expect(node.content.toString("ascii")).toMatch(/^[A-Za-z0-9 '()+,./:=?-]*$/);
      if (node.tag & 0x20) for (const child of x509.children(node)) checkStrings(child);
    }
    for (const der of [caParsed.subjectDer, caParsed.issuerDer, leafParsed.subjectDer, leafParsed.issuerDer])
      checkStrings(x509.decode(der));
    const caPath = await file("go-ca.pem", ca.certPem);
    const leafPath = await file("go-leaf.pem", certificate.certPem!);
    const child = Bun.spawn(
      ["go", "run", join(import.meta.dir, "testdata/parse-certificates.go"), caPath, leafPath],
      {
        env: { ...process.env, GO111MODULE: "off" },
        stdout: "pipe",
        stderr: "pipe",
      },
    );
    const [code, out, err] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    expect(code, out + err).toBe(0);
    expect(out).toContain("CA and leaf parsed; client chain verified");
  }, 60_000);

  for (const purpose of pki.CA_PURPOSES) {
    test(`${purpose} enforces the full common name boundary before persistence`, async () => {
      const max = 64 - `Ark ${purpose} CA `.length;
      const ca = await newCa("a".repeat(max), purpose);
      expect(new X509Certificate(ca.certPem).subject.split("\n")[0]).toBe(
        `CN=Ark ${purpose} CA ${"a".repeat(max)}`,
      );
      for (const length of [max + 1, 48]) {
        const name = "a".repeat(length);
        await expect(pki.createPrivateCa({ purpose, name })).rejects.toThrow(pki.PkiPolicyError);
        expect((await pki.listPrivateCas({ purpose })).filter((row) => row.name === name)).toHaveLength(0);
      }
    });
  }
});

describe("certificate profiles", () => {
  test("the CA is ECDSA P-256 with CA:TRUE pathlen:0, keyCertSign+cRLSign, SKI and AKI, for 5 years", async () => {
    const ca = await newCa("profile-ca", "tcp-client");
    const parsed = parsePem(ca.certPem);
    expect(parsed.version).toBe(3);
    expect(parsed.signatureAlgorithm).toBe(x509.OID.ecdsaWithSha256);

    const basic = extensionOf(parsed, x509.OID.basicConstraints);
    expect(basic.critical).toBe(true);
    expect(x509.decodeBasicConstraints(basic.value)).toEqual({ ca: true, pathLength: 0 });
    const usage = extensionOf(parsed, x509.OID.keyUsage);
    expect(usage.critical).toBe(true);
    expect(x509.decodeKeyUsage(usage.value).toSorted()).toEqual(["cRLSign", "keyCertSign"]);
    const ski = x509.decodeSubjectKeyIdentifier(extensionOf(parsed, x509.OID.subjectKeyIdentifier).value);
    expect(ski).toEqual(x509.keyIdentifier(parsed.spki));
    expect(
      x509.decodeAuthorityKeyIdentifier(extensionOf(parsed, x509.OID.authorityKeyIdentifier).value),
    ).toEqual(ski);
    expect(parsed.notAfter.getUTCFullYear() - parsed.notBefore.getUTCFullYear()).toBe(5);
    expect(parsed.notAfter.getTime()).toBe(ca.notAfter.getTime());

    const node = new X509Certificate(ca.certPem);
    expect(node.ca).toBe(true);
    expect(node.subject).toContain(`CN=Ark tcp-client CA profile-ca`);
    expect(node.subject).toContain(ca.id.replaceAll("_", "-"));
    expect(node.fingerprint256.replaceAll(":", "").toLowerCase()).toBe(ca.fingerprintSha256);

    // OpenSSL's own parser agrees.
    const text = openssl(["x509", "-noout", "-text"], ca.certPem).stdout;
    expect(text).toContain("CA:TRUE, pathlen:0");
    expect(text).toMatch(/X509v3 Basic Constraints: critical/);
    expect(text).toMatch(/X509v3 Key Usage: critical\s+Certificate Sign, CRL Sign/);
    expect(text).toContain("X509v3 Subject Key Identifier");
    expect(text).toContain("X509v3 Authority Key Identifier");
    expect(text).toContain("prime256v1");
  });

  test("a client certificate has EKU clientAuth, SKI, AKI = CA SKI, and exactly 90 days", async () => {
    const ca = await newCa("profile-leaf", "db-client", new Date("2026-11-16T00:00:00Z"));
    const now = new Date("2026-11-16T12:00:00.750Z");
    const { certificate, caCertPem } = await issue({
      caId: ca.id,
      subjectCn: "appdb_storefront_preview",
      now,
    });
    expect(caCertPem).toBe(ca.certPem);
    const parsed = parsePem(certificate.certPem!);
    const caParsed = parsePem(ca.certPem);

    expect(parsed.version).toBe(3);
    expect(parsed.notBefore.toISOString()).toBe("2026-11-16T12:00:00.000Z");
    expect(parsed.notAfter.getTime() - parsed.notBefore.getTime()).toBe(90 * DAY);
    expect(parsed.issuerDer).toEqual(caParsed.subjectDer);

    const eku = extensionOf(parsed, x509.OID.extendedKeyUsage);
    expect(x509.decodeExtendedKeyUsage(eku.value)).toEqual([x509.OID.clientAuth]);
    const usage = extensionOf(parsed, x509.OID.keyUsage);
    expect(usage.critical).toBe(true);
    expect(x509.decodeKeyUsage(usage.value)).toEqual(["digitalSignature"]);
    const basic = extensionOf(parsed, x509.OID.basicConstraints);
    expect(basic.critical).toBe(true);
    expect(x509.decodeBasicConstraints(basic.value).ca).toBe(false);
    expect(x509.decodeSubjectKeyIdentifier(extensionOf(parsed, x509.OID.subjectKeyIdentifier).value)).toEqual(
      x509.keyIdentifier(parsed.spki),
    );
    expect(
      x509.decodeAuthorityKeyIdentifier(extensionOf(parsed, x509.OID.authorityKeyIdentifier).value),
    ).toEqual(x509.decodeSubjectKeyIdentifier(extensionOf(caParsed, x509.OID.subjectKeyIdentifier).value));
    expect(parsed.extensions.map((item) => item.id).toSorted()).toEqual(
      [
        x509.OID.authorityKeyIdentifier,
        x509.OID.basicConstraints,
        x509.OID.extendedKeyUsage,
        x509.OID.keyUsage,
        x509.OID.subjectKeyIdentifier,
      ].toSorted(),
    );
    // Random 128-bit serial.
    expect(certificate.serial).toMatch(/^[0-9A-F]{1,32}$/);

    const node = new X509Certificate(certificate.certPem!);
    expect(node.ca).toBe(false);
    expect(node.subject).toBe("CN=appdb_storefront_preview");
    expect(node.checkIssued(new X509Certificate(ca.certPem))).toBe(true);
    expect(node.verify(new X509Certificate(ca.certPem).publicKey)).toBe(true);

    const text = openssl(["x509", "-noout", "-text"], certificate.certPem!).stdout;
    expect(text).toMatch(/X509v3 Extended Key Usage:\s+TLS Web Client Authentication\n/);
    expect(text).toMatch(/X509v3 Key Usage: critical\s+Digital Signature\n/);
    expect(text).toContain("X509v3 Subject Key Identifier");
    expect(text).toContain("X509v3 Authority Key Identifier");
  });

  test("a CA that expires within 90 days refuses to issue", async () => {
    const ca = await newCa("nearly-expired", "db-client", new Date(Date.now() - (5 * 365 - 30) * DAY));
    await expect(issue({ caId: ca.id, subjectCn: "late" })).rejects.toThrow(
      /expires before a 90-day certificate/,
    );
  });

  test("names, purposes and subject CNs outside the policy are refused", async () => {
    await expect(pki.createPrivateCa({ purpose: "db-client", name: "bad\nname" })).rejects.toThrow(
      pki.PkiPolicyError,
    );
    await expect(pki.createPrivateCa({ purpose: "server" as never, name: "x" })).rejects.toThrow(
      pki.PkiPolicyError,
    );
    const ca = await newCa("cn-policy");
    for (const subjectCn of ["", "a".repeat(65), "x,O=Evil", "role\u0000"]) {
      await expect(issue({ caId: ca.id, subjectCn })).rejects.toThrow(pki.PkiPolicyError);
    }
    expect(await pki.listClientCertificates(ca.id)).toHaveLength(0);
  });
});

describe("issuance", () => {
  test("a generated key is sealed as a once secret and matches the certificate", async () => {
    const ca = await newCa("generated");
    const { certificate } = await issue({
      caId: ca.id,
      subjectCn: "appdb_generated",
      keyOwner: { resourceType: "platform", resourceId: "platform" },
    });
    expect(certificate.keySecretId).toBeTruthy();
    const [secret] = await db.select().from(secrets).where(eq(secrets.id, certificate.keySecretId!));
    expect(secret).toMatchObject({
      kind: pki.CLIENT_KEY_SECRET_KIND,
      once: true,
      sensitivity: "credential",
      resourceType: "platform",
      resourceId: "platform",
      keyId: process.env.ARK_ROOT_KEY_ID ?? "k1",
      revealedAt: null,
    });
    const key = createPrivateKey(decryptSecret(process.env.ARK_ROOT_KEY!, secret!));
    expect(key.asymmetricKeyDetails?.namedCurve).toBe("prime256v1");
    const certKey = new X509Certificate(certificate.certPem!).publicKey;
    expect(createPublicKey(key).export({ type: "spki", format: "der" })).toEqual(
      certKey.export({ type: "spki", format: "der" }),
    );
  });

  test("a CSR is signed without storing a key, and Ark sets the subject", async () => {
    const ca = await newCa("csr");
    const request = csr(P256, [
      "basicConstraints=critical,CA:FALSE",
      "keyUsage=critical,digitalSignature",
      "extendedKeyUsage=clientAuth",
    ]);
    const { certificate } = await issue({
      caId: ca.id,
      subjectCn: "appdb_csr",
      csrPem: request,
    });
    expect(certificate.keySecretId).toBeNull();
    const csrKey = openssl(["req", "-pubkey", "-noout"], request).stdout;
    const certKey = openssl(["x509", "-pubkey", "-noout"], certificate.certPem!).stdout;
    expect(certKey).toBe(csrKey);
    expect(new X509Certificate(certificate.certPem!).subject).toBe("CN=appdb_csr");
    // Requested extensions are never copied: the issued profile is fixed.
    expect(parsePem(certificate.certPem!).extensions).toHaveLength(5);
    const caPath = await file("csr-ca.pem", ca.certPem);
    const leafPath = await file("csr-leaf.pem", certificate.certPem!);
    expect(
      openssl(["verify", "-x509_strict", "-purpose", "sslclient", "-CAfile", caPath, leafPath]).code,
    ).toBe(0);
  });

  test("P-384 and RSA-3072 CSRs are accepted", async () => {
    const ca = await newCa("csr-shapes");
    for (const keySpec of [
      ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"],
      ["-newkey", "rsa:3072"],
    ]) {
      const { certificate } = await issue({
        caId: ca.id,
        subjectCn: "shape",
        csrPem: csr(keySpec),
      });
      expect(certificate.status).toBe("issued");
    }
  });

  test("CSRs whose key, extensions or signature violate policy are rejected", async () => {
    const ca = await newCa("csr-policy");
    const valid = csr(P256);
    const der = x509.fromPem(valid, ["CERTIFICATE REQUEST"]);
    const tampered = Buffer.from(der);
    tampered[tampered.length - 5] = (tampered[tampered.length - 5] ?? 0) ^ 0x01; // inside the signature
    const cases: Array<[string, string, RegExp]> = [
      ["RSA-2048 key", csr(["-newkey", "rsa:2048"]), /at least 3072 bits/],
      ["Ed25519 key", csr(["-newkey", "ed25519"]), /type ed25519 are not accepted/],
      ["P-521 key", csr(["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-521"]), /curve are not accepted/],
      ["CA request", csr(P256, ["basicConstraints=critical,CA:TRUE"]), /requests a CA certificate/],
      ["serverAuth EKU", csr(P256, ["extendedKeyUsage=serverAuth"]), /other than clientAuth/],
      ["mixed EKU", csr(P256, ["extendedKeyUsage=clientAuth,serverAuth"]), /other than clientAuth/],
      ["keyCertSign usage", csr(P256, ["keyUsage=digitalSignature,keyCertSign"]), /keyCertSign/],
      ["subjectAltName", csr(P256, ["subjectAltName=DNS:db.example.com"]), /extension 2\.5\.29\.17/],
      ["bad signature", x509.toPem("CERTIFICATE REQUEST", tampered), /signature does not verify|malformed/],
      ["not a CSR", ca.certPem, /Expected a PEM/],
      [
        "garbage",
        "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
        /malformed/,
      ],
    ];
    for (const [label, pem, message] of cases) {
      let error: unknown;
      try {
        await issue({ caId: ca.id, subjectCn: "rejected", csrPem: pem });
      } catch (caught) {
        error = caught;
      }
      expect(error, label).toBeInstanceOf(pki.PkiPolicyError);
      expect((error as Error).message, label).toMatch(message);
    }
    expect(await pki.listClientCertificates(ca.id)).toHaveLength(0);
  });

  test("retired and revoked CAs cannot issue", async () => {
    const ca = await newCa("retire-me");
    expect((await pki.setPrivateCaStatus(ca.id, "retired")).status).toBe("retired");
    await expect(issue({ caId: ca.id, subjectCn: "x" })).rejects.toThrow(/retired/);
    expect((await pki.setPrivateCaStatus(ca.id, "revoked")).status).toBe("revoked");
    await expect(issue({ caId: ca.id, subjectCn: "x" })).rejects.toThrow(/revoked/);
    // Revocation is final.
    expect((await pki.setPrivateCaStatus(ca.id, "retired")).status).toBe("revoked");
  });
});

describe("key delivery", () => {
  test("generated issuance requires a supported existing owner; CSR issuance needs none", async () => {
    const ca = await newCa("owner-policy");
    for (const keyOwner of [
      undefined,
      { resourceType: "client_certificate", resourceId: "ccert_missing" },
      { resourceType: "constructor", resourceId: "x" },
      { resourceType: "platform", resourceId: "wrong" },
      { resourceType: "database", resourceId: "db_missing" },
      { resourceType: "project", resourceId: "" },
    ]) {
      await expect(
        pki.issueClientCertificate({ caId: ca.id, subjectCn: "missing-owner", keyOwner: keyOwner as never }),
      ).rejects.toThrow(pki.PkiPolicyError);
    }
    expect(await pki.listClientCertificates(ca.id)).toHaveLength(0);
    const result = await pki.issueClientCertificate({
      caId: ca.id,
      subjectCn: "csr-no-owner",
      csrPem: csr(P256),
    });
    expect(result.certificate.keySecretId).toBeNull();
  });

  test("authenticated resource owner reveals once; a foreign operator cannot reveal or consume the grant", async () => {
    const { app } = await import("../app.ts");
    const { auth } = await import("../auth.ts");
    const projectId = createId("prj");
    const users: string[] = [];
    await db.insert(projects).values({ id: projectId, name: "PKI delivery", slug: projectId });
    const origin = process.env.BETTER_AUTH_URL ?? "http://127.0.0.1:3000";
    async function actor(projectIds: string[]) {
      const email = `${createId("usr")}@example.test`;
      const response = await auth.handler(
        new Request(`${origin}/api/auth/sign-up/email`, {
          method: "POST",
          // Keep this fixture outside other tests' per-IP signup rate-limit bucket. Better Auth reads
          // the client address only from X-Ark-Client-Ip, which the app sets (client-ip.ts).
          headers: {
            "content-type": "application/json",
            origin,
            "x-ark-client-ip": `192.0.2.${50 + users.length}`,
          },
          body: JSON.stringify({ name: "PKI delivery", email, password: "PKI-Delivery-Test-Password-123!" }),
        }),
      );
      expect(response.status).toBe(200);
      const body = await response.json();
      const id = body.user.id as string;
      users.push(id);
      const [stored] = await db.select().from(session).where(eq(session.token, body.token));
      expect(stored).toBeDefined();
      await db
        .update(user)
        .set({ twoFactorEnabled: true, mfaEnrolledAt: new Date(stored!.createdAt.getTime() - 60_000) })
        .where(eq(user.id, id));
      await db.insert(platformAccess).values({ userId: id, role: "operator", projectIds, domainIds: [] });
      return {
        id,
        sessionId: stored!.id,
        cookie: response.headers
          .getSetCookie()
          .map((value) => value.split(";")[0])
          .join("; "),
      };
    }
    try {
      const allowed = await actor([projectId]);
      const forbidden = await actor([]);
      const ca = await newCa("reveal");
      const { certificate } = await pki.issueClientCertificate({
        caId: ca.id,
        subjectCn: "reveal",
        keyOwner: { resourceType: "project", resourceId: projectId },
      });
      const secretId = certificate.keySecretId!;
      async function grant(who: typeof allowed) {
        const id = createId("sup");
        await db.insert(stepUpGrants).values({
          id,
          userId: who.id,
          sessionId: who.sessionId,
          action: "secret.reveal",
          planHash: privilegedRequestHash("secret.reveal", { secretId }),
          expiresAt: new Date(Date.now() + 60_000),
        });
        return id;
      }
      const reveal = (who: typeof allowed) =>
        app.request(`${origin}/api/secrets/${secretId}/reveal`, {
          method: "POST",
          headers: { origin, cookie: who.cookie, "content-type": "application/json" },
          body: "{}",
        });
      const deniedGrant = await grant(forbidden);
      expect((await reveal(forbidden)).status).toBe(403);
      const [denied] = await db.select().from(stepUpGrants).where(eq(stepUpGrants.id, deniedGrant));
      expect(denied!.consumedAt).toBeNull();
      const [sealed] = await db.select().from(secrets).where(eq(secrets.id, secretId));
      expect(sealed!.revealedAt).toBeNull();
      await grant(allowed);
      const first = await reveal(allowed);
      expect(first.status, await first.clone().text()).toBe(200);
      expect(first.headers.get("cache-control")).toBe("no-store");
      const key = createPrivateKey((await first.json()).value);
      expect(createPublicKey(key).export({ type: "spki", format: "der" })).toEqual(
        new X509Certificate(certificate.certPem!).publicKey.export({ type: "spki", format: "der" }),
      );
      await grant(allowed);
      expect((await reveal(allowed)).status).toBe(409);
    } finally {
      if (users.length) await db.delete(user).where(inArray(user.id, users));
      await db.delete(projects).where(eq(projects.id, projectId));
    }
  });
});

describe("persistence", () => {
  test("rows are written and read through the module with serial, fingerprint, validity and revocation", async () => {
    const ca = await newCa("persisted", "http-client");
    expect(await pki.getPrivateCa(ca.id)).toEqual(ca);
    expect((await pki.listPrivateCas({ purpose: "http-client" })).map((item) => item.id)).toContain(ca.id);
    expect((await pki.listPrivateCas({ status: "retired" })).map((item) => item.id)).not.toContain(ca.id);

    const { certificate } = await issue({
      caId: ca.id,
      subjectCn: "persisted",
      rolloverState: "pending",
    });
    const [row] = await db.select().from(clientCertificates).where(eq(clientCertificates.id, certificate.id));
    expect(row).toMatchObject({
      caId: ca.id,
      status: "issued",
      rolloverState: "pending",
      certPem: certificate.certPem,
    });
    const read = await pki.getClientCertificate(certificate.id);
    expect(read).toEqual(certificate);

    // Cross-check every stored attribute against OpenSSL's reading of the stored PEM.
    const meta = openssl(
      ["x509", "-noout", "-serial", "-fingerprint", "-sha256", "-startdate", "-enddate"],
      read!.certPem!,
    ).stdout;
    expect(meta).toContain(`serial=${read!.serial}`);
    expect(/sha256 Fingerprint=([0-9A-F:]+)/i.exec(meta)?.[1]?.replaceAll(":", "").toLowerCase()).toBe(
      read!.fingerprintSha256,
    );
    expect(new Date(/notBefore=(.+)/.exec(meta)![1]!).getTime()).toBe(read!.notBefore.getTime());
    expect(new Date(/notAfter=(.+)/.exec(meta)![1]!).getTime()).toBe(read!.notAfter.getTime());
    const caMeta = openssl(["x509", "-noout", "-serial", "-enddate"], ca.certPem).stdout;
    expect(caMeta).toContain(`serial=${ca.serial}`);
    expect(new Date(/notAfter=(.+)/.exec(caMeta)![1]!).getTime()).toBe(ca.notAfter.getTime());

    const revokedAt = new Date("2026-11-20T08:00:00Z");
    const revoked = await pki.revokeClientCertificate({
      id: certificate.id,
      reason: "keyCompromise",
      now: revokedAt,
    });
    expect(revoked).toMatchObject({ status: "revoked", revokedReason: "keyCompromise", keySecretId: null });
    expect(revoked.revokedAt?.getTime()).toBe(revokedAt.getTime());
    // The unrevealed generated key is destroyed with the certificate.
    expect(await db.select().from(secrets).where(eq(secrets.id, certificate.keySecretId!))).toHaveLength(0);
    // Idempotent: a second revocation keeps the first record.
    const again = await pki.revokeClientCertificate({ id: certificate.id, reason: "superseded" });
    expect(again).toEqual(revoked);
    expect(await pki.listClientCertificates(ca.id)).toEqual([revoked]);
  });
});

describe("missing identifiers", () => {
  test("lookups return null and mutations reject missing CA and certificate IDs", async () => {
    const caId = createId("pca");
    const id = createId("ccert");
    expect(await pki.getPrivateCa(caId)).toBeNull();
    expect(await pki.getClientCertificate(id)).toBeNull();
    for (const mutate of [
      () => issue({ caId, subjectCn: "missing" }),
      () => pki.generateCaCrl({ caId }),
      () => pki.setPrivateCaStatus(caId, "retired"),
      () => pki.revokeClientCertificate({ id }),
    ])
      await expect(mutate()).rejects.toThrow(pki.PkiPolicyError);
  });
});

/** Wait for an observed PostgreSQL lock dependency instead of assuming task scheduling. */
async function waitForBlockedBy(pid: number, count = 1) {
  for (let attempt = 0; attempt < 200; attempt++) {
    const [row] =
      await sql`SELECT count(*)::int AS n FROM pg_stat_activity WHERE ${pid}::int = ANY(pg_blocking_pids(pid))`;
    if (row!.n >= count) return;
    await Bun.sleep(10);
  }
  throw new Error("Expected PKI operations to wait on the held row lock.");
}

describe("transaction concurrency and rollback", () => {
  test("retirement holds issuance until commit, then issuance refuses without writing a key", async () => {
    const ca = await newCa("retirement-race");
    let pending: ReturnType<typeof issue> | undefined;
    await sql.begin(async (tx) => {
      const [connection] = await tx`SELECT pg_backend_pid() AS pid`;
      await tx`UPDATE private_cas SET status = 'retired' WHERE id = ${ca.id}`;
      pending = issue({ caId: ca.id, subjectCn: "racing" });
      // Observe rejection below, after releasing the lock.
      void pending.catch(() => {});
      await waitForBlockedBy(connection!.pid);
    });
    await expect(pending!).rejects.toThrow(/retired/);
    expect(await pki.listClientCertificates(ca.id)).toHaveLength(0);
  });

  test("issuance holding a shared CA lock completes before queued retirement", async () => {
    const ca = await newCa("issuance-race");
    const reservation = await sql.reserve();
    let locked = false;
    let issuing: ReturnType<typeof issue> | undefined;
    let retiring: ReturnType<typeof pki.setPrivateCaStatus> | undefined;
    try {
      await reservation`BEGIN`;
      locked = true;
      const [connection] = await reservation`SELECT pg_backend_pid() AS pid`;
      // Compatible with issuance's SHARE, incompatible with retirement's UPDATE.
      await reservation`SELECT id FROM private_cas WHERE id = ${ca.id} FOR SHARE`;
      // Pause issuance after its CA lock, at its client-key INSERT.
      await reservation`LOCK TABLE secrets IN SHARE MODE`;
      issuing = issue({ caId: ca.id, subjectCn: "before-retirement" });
      void issuing.catch(() => {});
      await waitForBlockedBy(connection!.pid);
      retiring = pki.setPrivateCaStatus(ca.id, "retired");
      void retiring.catch(() => {});
      await waitForBlockedBy(connection!.pid, 2);
      await reservation`COMMIT`;
      locked = false;
      const result = await issuing;
      expect(result.certificate.status).toBe("issued");
      expect((await retiring).status).toBe("retired");
      await expect(issue({ caId: ca.id, subjectCn: "too-late" })).rejects.toThrow(/retired/);
      expect(await pki.listClientCertificates(ca.id)).toHaveLength(1);
    } finally {
      if (locked) await reservation`ROLLBACK`;
      reservation.release();
      await Promise.allSettled([issuing, retiring].filter(Boolean));
    }
  });

  test("concurrent duplicate revocations keep the first result and remove the key once", async () => {
    const ca = await newCa("duplicate-revocations");
    const { certificate } = await issue({ caId: ca.id, subjectCn: "duplicate" });
    const now = new Date("2026-11-20T00:00:00Z");
    let pending: ReturnType<typeof pki.revokeClientCertificate>[] = [];
    await sql.begin(async (tx) => {
      const [connection] = await tx`SELECT pg_backend_pid() AS pid`;
      await tx`SELECT id FROM client_certificates WHERE id = ${certificate.id} FOR UPDATE`;
      pending = ["keyCompromise", "superseded", "unspecified"].map((reason) =>
        pki.revokeClientCertificate({
          id: certificate.id,
          reason: reason as import("./pki.ts").CrlReason,
          now,
        }),
      );
      await waitForBlockedBy(connection!.pid);
    });
    const results = await Promise.all(pending);
    for (const result of results) expect(result).toEqual(results[0]!);
    expect(results[0]!.revokedAt).toEqual(now);
    expect(await db.select().from(secrets).where(eq(secrets.id, certificate.keySecretId!))).toHaveLength(0);
  });

  test("parallel CRLs receive consecutive numbers and concurrent revocations reach the final CRL", async () => {
    const ca = await newCa("parallel-crls");
    const certs = await Promise.all(
      ["one", "two", "three"].map((subjectCn) => issue({ caId: ca.id, subjectCn })),
    );
    const now = new Date("2026-11-21T00:00:00Z");
    const initial = await pki.generateCaCrl({ caId: ca.id, now });
    let pending: ReturnType<typeof pki.generateCaCrl>[] = [];
    await sql.begin(async (tx) => {
      const [connection] = await tx`SELECT pg_backend_pid() AS pid`;
      await tx`SELECT id FROM private_cas WHERE id = ${ca.id} FOR UPDATE`;
      pending = Array.from({ length: 3 }, () => pki.generateCaCrl({ caId: ca.id, now }));
      await waitForBlockedBy(connection!.pid);
    });
    const [crls] = await Promise.all([
      Promise.all(pending),
      Promise.all(certs.map(({ certificate }) => pki.revokeClientCertificate({ id: certificate.id, now }))),
    ]);
    const numbers = crls.map((crl) => BigInt(crl.crlNumber)).toSorted((a, b) => (a < b ? -1 : 1));
    expect(numbers).toEqual([1n, 2n, 3n].map((offset) => BigInt(initial.crlNumber) + offset));
    const final = await pki.generateCaCrl({ caId: ca.id, now });
    expect(BigInt(final.crlNumber)).toBe(numbers[2]! + 1n);
    expect(final.revokedSerials.toSorted()).toEqual(
      certs.map(({ certificate }) => certificate.serial).toSorted(),
    );
    expect((await pki.getPrivateCa(ca.id))!.crlPem).toBe(final.crlPem);
  });

  test("a failed certificate INSERT rolls back its already-inserted generated secret", async () => {
    const ca = await newCa("rollback");
    const before = await db
      .select({ id: secrets.id })
      .from(secrets)
      .where(eq(secrets.kind, pki.CLIENT_KEY_SECRET_KIND));
    // This CHECK is evaluated by PostgreSQL at the final INSERT, after the key INSERT.
    await expect(
      issue({ caId: ca.id, subjectCn: "rollback", rolloverState: "invalid" as never }),
    ).rejects.toThrow(/client_certificates/);
    expect(await pki.listClientCertificates(ca.id)).toHaveLength(0);
    const after = await db
      .select({ id: secrets.id })
      .from(secrets)
      .where(eq(secrets.kind, pki.CLIENT_KEY_SECRET_KIND));
    expect(after.map((row) => row.id).toSorted()).toEqual(before.map((row) => row.id).toSorted());
  });
});

describe("CRL", () => {
  test("invalid runtime reasons are rejected and legacy unknown reasons cannot poison CRLs", async () => {
    const ca = await newCa("reason-policy");
    const { certificate } = await issue({ caId: ca.id, subjectCn: "bad-reason" });
    for (const reason of ["constructor", "toString", "__proto__", "unknown"]) {
      await expect(
        pki.revokeClientCertificate({ id: certificate.id, reason: reason as never }),
      ).rejects.toThrow(pki.PkiPolicyError);
      expect((await pki.getClientCertificate(certificate.id))!.status).toBe("issued");
    }
    await pki.revokeClientCertificate({ id: certificate.id });
    for (const reason of ["constructor", "toString", "__proto__", "unknown"]) {
      await db
        .update(clientCertificates)
        .set({ revokedReason: reason })
        .where(eq(clientCertificates.id, certificate.id));
      const crl = await pki.generateCaCrl({ caId: ca.id });
      const parsed = x509.parseCrl(x509.fromPem(crl.crlPem, ["X509 CRL"]));
      expect(parsed.revoked).toMatchObject([{ serial: certificate.serial, reasonCode: null }]);
      const caPath = await file("reason-ca.pem", ca.certPem);
      const crlPath = await file("reason-crl.pem", crl.crlPem);
      expect(openssl(["crl", "-in", crlPath, "-CAfile", caPath, "-noout"]).code).toBe(0);
    }
  });

  test("the CRL lists revoked serials, is signed by the CA, and carries the configured nextUpdate", async () => {
    const issuedAt = new Date("2026-11-16T00:00:00Z");
    const revokedAt = new Date(issuedAt.getTime() + 4 * DAY);
    const now = new Date(issuedAt.getTime() + 5 * DAY);
    const ca = await newCa("crl", "db-client", issuedAt);
    const other = await newCa("crl-other", "db-client", issuedAt);
    const issued: ClientCertificateSummary[] = [];
    for (const name of ["keep", "lost", "retired"]) {
      issued.push((await issue({ caId: ca.id, subjectCn: name, now: issuedAt })).certificate);
    }
    await pki.revokeClientCertificate({ id: issued[1]!.id, reason: "keyCompromise", now: revokedAt });
    await pki.revokeClientCertificate({ id: issued[2]!.id, now: revokedAt });

    const crl = await pki.generateCaCrl({ caId: ca.id, nextUpdateDays: 7, now });
    expect(crl.revokedSerials.toSorted()).toEqual([issued[1]!.serial, issued[2]!.serial].toSorted());
    expect(crl.nextUpdate.getTime() - crl.thisUpdate.getTime()).toBe(7 * DAY);

    const parsed = x509.parseCrl(x509.fromPem(crl.crlPem, ["X509 CRL"]));
    expect(parsed.revoked.map((entry) => entry.serial).toSorted()).toEqual(crl.revokedSerials.toSorted());
    expect(parsed.revoked.find((entry) => entry.serial === issued[1]!.serial)?.reasonCode).toBe(1);
    expect(parsed.revoked.find((entry) => entry.serial === issued[2]!.serial)?.reasonCode).toBeNull();
    expect(parsed.thisUpdate.toISOString()).toBe(now.toISOString());
    expect(parsed.nextUpdate?.toISOString()).toBe("2026-11-28T00:00:00.000Z");
    expect(parsed.issuerDer).toEqual(parsePem(ca.certPem).subjectDer);

    // Stored on the CA row.
    const stored = await pki.getPrivateCa(ca.id);
    expect(stored?.crlPem).toBe(crl.crlPem);
    expect(stored?.crlNextUpdate?.toISOString()).toBe("2026-11-28T00:00:00.000Z");

    // OpenSSL: the signature verifies with this CA only, and nextUpdate is what was configured.
    const caPath = await file("crl-ca.pem", ca.certPem);
    const otherPath = await file("crl-other.pem", other.certPem);
    const crlPath = await file("crl.pem", crl.crlPem);
    const signed = openssl(["crl", "-in", crlPath, "-CAfile", caPath, "-noout"]);
    expect(signed.code, signed.stderr).toBe(0);
    expect(signed.stdout + signed.stderr).toContain("verify OK");
    expect(openssl(["crl", "-in", crlPath, "-CAfile", otherPath, "-noout"]).code).not.toBe(0);
    const nextUpdate = openssl(["crl", "-in", crlPath, "-noout", "-nextupdate"]).stdout;
    expect(new Date(nextUpdate.replace(/^nextUpdate=/, "").trim()).toISOString()).toBe(
      "2026-11-28T00:00:00.000Z",
    );
    const text = openssl(["crl", "-in", crlPath, "-noout", "-text"]).stdout;
    for (const serial of crl.revokedSerials) expect(text).toContain(`Serial Number: ${serial}`);
    expect(text).not.toContain(`Serial Number: ${issued[0]!.serial}`);

    // Strict chain plus CRL check: revoked leaves fail, the kept one passes.
    const crlCheck = [
      "verify",
      "-x509_strict",
      "-crl_check",
      "-CRLfile",
      crlPath,
      "-CAfile",
      caPath,
      "-attime",
    ];
    const at = String(Math.floor((now.getTime() + DAY) / 1000));
    for (const [index, certificate] of issued.entries()) {
      const leaf = await file(`crl-leaf-${index}.pem`, certificate.certPem!);
      const result = openssl([...crlCheck, at, leaf]);
      if (index === 0) expect(result.code, result.stdout + result.stderr).toBe(0);
      else expect(result.stdout + result.stderr).toContain("certificate revoked");
    }

    // Default nextUpdate is 14 days, and the CRL number always increases.
    const second = await pki.generateCaCrl({ caId: ca.id, now });
    expect(second.nextUpdate.getTime() - second.thisUpdate.getTime()).toBe(
      pki.DEFAULT_CRL_NEXT_UPDATE_DAYS * DAY,
    );
    expect(BigInt(second.crlNumber)).toBeGreaterThan(BigInt(crl.crlNumber));
    expect(x509.parseCrl(x509.fromPem(second.crlPem, ["X509 CRL"])).crlNumber).toBe(BigInt(second.crlNumber));
  });

  test("an empty CRL is valid and well-formed", async () => {
    const ca = await newCa("crl-empty");
    const crl = await pki.generateCaCrl({ caId: ca.id });
    expect(crl.revokedSerials).toEqual([]);
    const caPath = await file("empty-ca.pem", ca.certPem);
    const crlPath = await file("empty.pem", crl.crlPem);
    expect(openssl(["crl", "-in", crlPath, "-CAfile", caPath, "-noout"]).code).toBe(0);
  });
});

describe("CA key confinement", () => {
  test("the CA key exists only as a sealed root secret and never appears in responses, logs or plaintext columns", async () => {
    // Capture everything this flow writes to the console or the process streams.
    const logged: string[] = [];
    const methods = ["log", "info", "warn", "error", "debug", "trace"] as const;
    const originals = methods.map((method) => console[method]);
    const writes = [process.stdout.write, process.stderr.write];
    for (const method of methods)
      console[method] = (...args: unknown[]) => void logged.push(args.map(String).join(" "));
    for (const stream of [process.stdout, process.stderr]) {
      const original = stream.write.bind(stream);
      stream.write = ((chunk: unknown, ...rest: unknown[]) => {
        logged.push(String(chunk));
        return (original as (...args: unknown[]) => boolean)(chunk, ...rest);
      }) as typeof stream.write;
    }
    const responses: unknown[] = [];
    let caId = "";
    try {
      const ca = await newCa("confined");
      caId = ca.id;
      responses.push(ca, await pki.getPrivateCa(ca.id), await pki.listPrivateCas());
      const issued = await issue({ caId: ca.id, subjectCn: "confined" });
      responses.push(issued, await issue({ caId: ca.id, subjectCn: "confined-csr", csrPem: csr(P256) }));
      responses.push(await pki.revokeClientCertificate({ id: issued.certificate.id }));
      responses.push(await pki.generateCaCrl({ caId: ca.id }));
      responses.push(await pki.listClientCertificates(ca.id));
      try {
        await issue({ caId: ca.id, subjectCn: "x", csrPem: "nonsense" });
      } catch (error) {
        responses.push(String(error));
      }
    } finally {
      methods.forEach((method, index) => (console[method] = originals[index]!));
      process.stdout.write = writes[0]!;
      process.stderr.write = writes[1]!;
    }

    // The key is sealed: AES-256-GCM (12-byte IV, 16-byte tag) under the configured key ID.
    const [row] = await db.select().from(privateCas).where(eq(privateCas.id, caId));
    const [secret] = await db.select().from(secrets).where(eq(secrets.id, row!.keySecretId));
    expect(secret).toMatchObject({
      kind: pki.CA_KEY_SECRET_KIND,
      sensitivity: "root",
      once: false,
      resourceType: "private_ca",
      resourceId: caId,
      keyId: process.env.ARK_ROOT_KEY_ID ?? "k1",
    });
    expect(Buffer.from(secret!.iv, "base64")).toHaveLength(12);
    expect(Buffer.from(secret!.authTag, "base64")).toHaveLength(16);
    const keyPem = decryptSecret(process.env.ARK_ROOT_KEY!, secret!);
    expect(keyPem).toContain("BEGIN PRIVATE KEY");
    const key = createPrivateKey(keyPem);
    expect(createPublicKey(key).export({ type: "spki", format: "der" })).toEqual(
      new X509Certificate(row!.certPem).publicKey.export({ type: "spki", format: "der" }),
    );
    // A wrong root key cannot open it.
    expect(() => decryptSecret("another-root-key-0123456789abcdef0123", secret!)).toThrow();
    // The generic one-time reveal endpoint refuses root secrets.
    expect(() => assertSecretRevealable(secret!)).toThrow(/cannot be revealed/);

    // Needles: the whole PKCS#8 body, the base64 window of it that holds the private scalar, and
    // the scalar itself in hex, base64 and base64url. (The PKCS#8 tail is the public point, which
    // the certificate rightly carries, so it is not a needle.)
    const body = keyPem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
    const d = key.export({ format: "jwk" }).d!;
    const scalar = Buffer.from(d, "base64url");
    const pkcs8 = key.export({ type: "pkcs8", format: "der" });
    const at = pkcs8.indexOf(scalar);
    expect(at).toBeGreaterThan(0);
    const window = pkcs8.subarray(at - (at % 3), at - (at % 3) + 36).toString("base64");
    expect(body).toContain(window);
    const needles = [body, window, d, scalar.toString("hex"), scalar.toString("base64"), secret!.id];

    const responseText = JSON.stringify(responses);
    expect(responseText).not.toContain("PRIVATE KEY");
    for (const needle of needles) expect(responseText).not.toContain(needle);
    const logText = logged.join("\n");
    for (const needle of needles.slice(0, -1)) expect(logText).not.toContain(needle);

    // No plaintext column in any table of the platform schema holds the key.
    const tables = await sql<{ tablename: string }[]>`
      SELECT tablename FROM pg_tables WHERE schemaname = current_schema()
    `;
    for (const { tablename } of tables) {
      for (const needle of needles.slice(0, -1)) {
        const [hit] = await sql.unsafe(
          `SELECT count(*)::int AS n FROM "${tablename.replaceAll('"', '""')}" t WHERE strpos(row_to_json(t)::text, $1) > 0`,
          [needle],
        );
        expect({ table: tablename, hits: hit?.n }).toEqual({ table: tablename, hits: 0 });
      }
    }
  });
});
