import { access, chmod, copyFile, mkdir, readFile, rename } from "node:fs/promises";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

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

function parseOpenSslDate(value: string) {
  const parsed = new Date(value.trim());
  if (Number.isNaN(parsed.getTime())) throw new Error(`Could not parse certificate expiry: ${value}`);
  return parsed;
}

export async function readCertificateMeta(certPath: string) {
  const { stdout: enddate } = await exec("openssl", ["x509", "-in", certPath, "-noout", "-enddate"], {
    timeout: 10_000,
  });
  const { stdout: fingerprint } = await exec(
    "openssl",
    ["x509", "-in", certPath, "-noout", "-fingerprint", "-sha256"],
    { timeout: 10_000 },
  );
  const expiresAt = parseOpenSslDate(enddate.replace(/^notAfter=/i, "").trim());
  const digest = fingerprint.split("=")[1]?.trim().replace(/:/g, "").toLowerCase();
  if (!digest) throw new Error("Could not read certificate fingerprint.");
  return { expiresAt, fingerprint: digest, renew: renewalDue(expiresAt) };
}

async function firstExisting(paths: string[]) {
  for (const path of paths) {
    try {
      await access(path);
      return path;
    } catch {
      continue;
    }
  }
  return null;
}

const certificateRoot = (hostname: string) =>
  join(process.env.ARK_CERT_DIR ?? join(process.cwd(), "tmp", "certs"), hostname);

export async function acmeAccountUri(hostname: string) {
  const email = process.env.ARK_ACME_EMAIL;
  if (!process.env.ARK_LEGO_BIN || !email) return null;
  const staging = process.env.ARK_ACME_STAGING !== "0";
  try {
    const host = staging
      ? "acme-staging-v02.api.letsencrypt.org"
      : new URL(process.env.LEGO_SERVER || "https://acme-v02.api.letsencrypt.org/directory").host;
    const account = join(certificateRoot(hostname), "lego", "accounts", host.replaceAll(":", "_"), email);
    // lego v4 keeps one account per storage path, ACME server and email.
    await access(join(account, "keys", email + ".key"));
    const saved = JSON.parse(await readFile(join(account, "account.json"), "utf8")) as {
      registration?: { uri?: string; body?: { status?: string } };
    };
    const uri = saved.registration?.uri;
    return saved.registration?.body?.status === "valid" && uri && new URL(uri).protocol === "https:"
      ? uri
      : null;
  } catch {
    return null;
  }
}

export async function issueCertificateFiles(hostname: string, action: "run" | "renew" = "run") {
  const root = certificateRoot(hostname);
  await mkdir(root, { recursive: true });
  const keyPath = join(root, "privkey.pem");
  const certPath = join(root, "fullchain.pem");
  const legoBin = process.env.ARK_LEGO_BIN;
  const email = process.env.ARK_ACME_EMAIL;
  if (legoBin && email) {
    const legoPath = join(root, "lego");
    const args = legoArgs({
      email,
      hostname,
      webroot: process.env.ARK_ACME_WEBROOT ?? join(root, "webroot"),
      path: legoPath,
      staging: process.env.ARK_ACME_STAGING !== "0",
      action,
    });
    await exec(legoBin, args, { timeout: 120_000 });
    const issuedCert = await firstExisting([
      join(legoPath, "certificates", `${hostname}.crt`),
      join(legoPath, "certificates", `${hostname}.issuer.crt`),
      certPath,
    ]);
    const issuedKey = await firstExisting([join(legoPath, "certificates", `${hostname}.key`), keyPath]);
    if (!issuedCert || !issuedKey) throw new Error("lego did not write a certificate and key.");
    if (issuedCert !== certPath) {
      await copyFile(issuedCert, `${certPath}.next`);
      await chmod(`${certPath}.next`, 0o644);
      await rename(`${certPath}.next`, certPath);
    }
    if (issuedKey !== keyPath) {
      await copyFile(issuedKey, `${keyPath}.next`);
      await chmod(`${keyPath}.next`, 0o600);
      await rename(`${keyPath}.next`, keyPath);
    }
    const { stdout: certKey } = await exec("openssl", ["x509", "-in", certPath, "-pubkey", "-noout"]);
    const { stdout: privateKey } = await exec("openssl", ["pkey", "-in", keyPath, "-pubout"]);
    if (certKey.trim() !== privateKey.trim())
      throw new Error("Issued certificate does not match its private key.");
    const { stdout: names } = await exec("openssl", [
      "x509",
      "-in",
      certPath,
      "-noout",
      "-ext",
      "subjectAltName",
    ]);
    if (!names.includes(`DNS:${hostname}`)) throw new Error(`Issued certificate does not cover ${hostname}.`);
    const meta = await readCertificateMeta(certPath);
    return {
      issuer: process.env.ARK_ACME_STAGING !== "0" ? "letsencrypt-staging" : "letsencrypt",
      keyPath,
      certPath,
      ...meta,
    };
  }
  if (process.env.ARK_CERTIFICATE_MODE !== "development") {
    throw new Error(
      "Public certificate issuance is not configured. Set ARK_LEGO_BIN and ARK_ACME_EMAIL; self-signed fallback is development-only.",
    );
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
  const meta = await readCertificateMeta(certPath);
  return {
    issuer: "local-openssl",
    keyPath,
    certPath,
    ...meta,
  };
}
