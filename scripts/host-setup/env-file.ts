// Edits of the installed `.env` by the guided setup: only the named keys change, every other line
// (and every secret) is kept, and the file stays mode 0600.
import { chmodSync, existsSync, readFileSync, renameSync, statSync, writeFileSync, chownSync } from "node:fs";

import { parseEnvFile } from "@ark-stack/shared";

import type { Answers } from "./answers.ts";

export const TUNNEL_ORIGIN = "http://localhost:3000";

export function readEnv(path: string) {
  return existsSync(path) ? readFileSync(path, "utf8") : "";
}

/** Replaces each `KEY=` line in place (dropping duplicates) and appends keys that are absent. */
export function setEnvValues(text: string, values: Record<string, string>) {
  for (const [key, value] of Object.entries(values)) {
    if (!/^[A-Z][A-Z0-9_]*$/.test(key) || /[\r\n]/.test(value)) {
      throw new Error(`Refusing to write ${key} to .env: invalid key or value.`);
    }
  }
  const seen = new Set<string>();
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  const out: string[] = [];
  for (const line of lines) {
    const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)=/.exec(line);
    const key = match?.[1];
    if (key && key in values) {
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(`${key}=${values[key]}`);
    } else out.push(line);
  }
  for (const [key, value] of Object.entries(values)) if (!seen.has(key)) out.push(`${key}=${value}`);
  return `${out.join("\n")}\n`;
}

/** Atomic write that keeps the file's owner and forces mode 0600. */
export function writeEnv(path: string, text: string) {
  const before = existsSync(path) ? statSync(path) : undefined;
  const temporary = `${path}.${process.pid}.setup.tmp`;
  writeFileSync(temporary, text, { mode: 0o600 });
  chmodSync(temporary, 0o600);
  if (before && process.getuid?.() === 0) chownSync(temporary, before.uid, before.gid);
  renameSync(temporary, path);
  chmodSync(path, 0o600);
}

/** The admin-origin, ACME, DNS and reboot settings the answers imply, given the current `.env`. */
export function desiredConfiguration(answers: Answers, current: string, previousAdminOrigin?: string) {
  const values = parseEnvFile(current);
  const adminOrigin = `https://${answers.adminHost}`;
  const existing = (values.BETTER_AUTH_TRUSTED_ORIGINS ?? "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean)
    .filter((origin) => origin !== previousAdminOrigin || origin === adminOrigin);
  const origins = [...new Set([adminOrigin, TUNNEL_ORIGIN, ...existing])];
  const desired: Record<string, string> = {
    BETTER_AUTH_URL: adminOrigin,
    BETTER_AUTH_TRUSTED_ORIGINS: origins.join(","),
    ARK_ACME_EMAIL: answers.acmeEmail,
    ARK_ACME_STAGING: answers.acmeEmail && answers.trustedCertificates ? "0" : "1",
    ARK_HOST_REBOOT_TIME: answers.rebootTime,
  };
  if (answers.dnsApiToken) desired.DNS_API_TOKEN = answers.dnsApiToken;
  const changed = Object.entries(desired).some(([key, value]) => values[key] !== value);
  return { desired, changed, adminOrigin };
}
