import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createHash } from "node:crypto";

import { legoArgs, renewalDue } from "@ark-stack/shared";

const exec = promisify(execFile);

export const challenges = new Map<
  string,
  { hostname: string; keyAuthorization: string; expiresAt: number }
>();

export function putChallenge(hostname: string, token: string, keyAuthorization: string) {
  challenges.set(token, { hostname, keyAuthorization, expiresAt: Date.now() + 15 * 60 * 1000 });
}

export function getChallenge(token: string) {
  const row = challenges.get(token);
  if (!row || row.expiresAt < Date.now()) {
    challenges.delete(token);
    return null;
  }
  return row;
}

export async function issueCertificateFiles(hostname: string) {
  const root = join(process.env.ARK_CERT_DIR ?? join(process.cwd(), "tmp", "certs"), hostname);
  await mkdir(root, { recursive: true });
  const keyPath = join(root, "privkey.pem");
  const certPath = join(root, "fullchain.pem");
  const legoBin = process.env.ARK_LEGO_BIN;
  const email = process.env.ARK_ACME_EMAIL;
  if (legoBin && email) {
    const args = legoArgs({
      email,
      hostname,
      webroot: process.env.ARK_ACME_WEBROOT ?? join(root, "webroot"),
      path: join(root, "lego"),
      staging: process.env.ARK_ACME_STAGING !== "0",
    });
    await exec(legoBin, args, { timeout: 120_000 });
    return {
      issuer: process.env.ARK_ACME_STAGING !== "0" ? "letsencrypt-staging" : "letsencrypt",
      keyPath,
      certPath,
    };
  }
  await exec(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:P-256",
      "-days",
      "30",
      "-nodes",
      "-subj",
      `/CN=${hostname}`,
      "-addext",
      `subjectAltName=DNS:${hostname}`,
      "-keyout",
      keyPath,
      "-out",
      certPath,
    ],
    { timeout: 15_000 },
  );
  const pem = await Bun.file(certPath).text();
  const fingerprint = createHash("sha256").update(pem).digest("hex");
  return {
    issuer: "local-openssl",
    keyPath,
    certPath,
    fingerprint,
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    renew: renewalDue(new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)),
  };
}
