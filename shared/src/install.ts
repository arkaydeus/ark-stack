import { randomBytes } from "node:crypto";

import { parseSniPorts } from "./edge-l4.ts";

export const installEnvKeys = [
  "BETTER_AUTH_SECRET",
  "ARK_ROOT_KEY",
  "ARK_SETUP_TOKEN",
  "ARK_INTERNAL_TOKEN",
  "ARK_DATABASE_WORKER_TOKEN",
  "ARK_DOMAIN_WORKER_TOKEN",
  "ARK_MAIL_WORKER_TOKEN",
  "ARK_BACKUP_WORKER_TOKEN",
  "ARK_AGENT_TOKEN",
  "ARK_MAINTENANCE_TOKEN",
  "ARK_MFA_RECOVERY_TOKEN",
  "ARK_METRICS_TOKEN",
  "ARK_OFFHOST_HEARTBEAT_TOKEN",
  "ARK_EDGE_GATE_TOKEN",
  "ARK_EDGE_WATCHDOG_TOKEN",
  "ARK_PLATFORM_PG_EXECUTOR_TOKEN",
  "ARK_APP_PG_EXECUTOR_TOKEN",
  "ARK_PLATFORM_PG_REPO_CIPHER_PASS",
  "ARK_APP_PG_REPO_CIPHER_PASS",
  "ARK_CONTROL_DB_PASSWORD",
  "ARK_APP_DB_PASSWORD",
  "ARK_API_DB_PASSWORD",
  "STALWART_ADMIN_PASSWORD",
] as const;

export const placeholderSecretValues = new Set([
  "change-me-to-at-least-32-characters-long",
  "dev-setup-token",
  "dev-internal-token",
  "dev-database-worker-token",
  "dev-domain-worker-token",
  "dev-mail-worker-token",
  "dev-backup-worker-token",
  "dev-agent-token",
  "dev-maintenance-token",
  "dev-mfa-recovery-token",
  "dev-metrics-token",
  "dev-offhost-heartbeat-token",
  "dev-edge-gate-token",
  "dev-edge-watchdog-token",
]);

const insecureDefaultPaths: Record<string, string[]> = {
  ARK_PGBOUNCER_DIR: ["./infra/database", "infra/database"],
};

export function generateInstallSecrets() {
  const controlPassword = randomBytes(32).toString("base64url");
  const appPassword = randomBytes(32).toString("base64url");
  const apiPassword = randomBytes(32).toString("base64url");
  return {
    BETTER_AUTH_SECRET: randomBytes(32).toString("base64url"),
    ARK_ROOT_KEY: randomBytes(32).toString("base64url"),
    ARK_ROOT_KEY_ID: "k1",
    ARK_SETUP_TOKEN: randomBytes(24).toString("base64url"),
    ARK_INTERNAL_TOKEN: randomBytes(24).toString("base64url"),
    ARK_DATABASE_WORKER_TOKEN: randomBytes(24).toString("base64url"),
    ARK_DOMAIN_WORKER_TOKEN: randomBytes(24).toString("base64url"),
    ARK_MAIL_WORKER_TOKEN: randomBytes(24).toString("base64url"),
    ARK_BACKUP_WORKER_TOKEN: randomBytes(24).toString("base64url"),
    ARK_AGENT_TOKEN: randomBytes(24).toString("base64url"),
    ARK_MAINTENANCE_TOKEN: randomBytes(24).toString("base64url"),
    ARK_MFA_RECOVERY_TOKEN: randomBytes(24).toString("base64url"),
    ARK_METRICS_TOKEN: randomBytes(24).toString("base64url"),
    ARK_OFFHOST_HEARTBEAT_TOKEN: randomBytes(24).toString("base64url"),
    // Shared by `edge` and `api` to authenticate gate calls (docs/design/front-door.md §3.9, FD-11).
    ARK_EDGE_GATE_TOKEN: randomBytes(32).toString("base64url"),
    // The edge watchdog's read-only lease credential (docs/design/front-door.md §3.2, FD-06).
    ARK_EDGE_WATCHDOG_TOKEN: randomBytes(32).toString("base64url"),
    // pgBackRest executors inside the PostgreSQL containers (docs/design/front-door.md §3.18.1, FD-21):
    // per-cluster tokens shared only with the backup worker, and the repo2 cipher passes. Copy the
    // cipher passes off-host with the restic repository password: an off-VPS restore needs both.
    ARK_PLATFORM_PG_EXECUTOR_TOKEN: randomBytes(32).toString("base64url"),
    ARK_APP_PG_EXECUTOR_TOKEN: randomBytes(32).toString("base64url"),
    ARK_PLATFORM_PG_REPO_CIPHER_PASS: randomBytes(48).toString("base64url"),
    ARK_APP_PG_REPO_CIPHER_PASS: randomBytes(48).toString("base64url"),
    ARK_CONTROL_DB_PASSWORD: controlPassword,
    ARK_APP_DB_PASSWORD: appPassword,
    ARK_API_DB_PASSWORD: apiPassword,
    // PgBouncer console administrator (FD-16): only the database worker receives it; PgBouncer's
    // userlist stores a SCRAM verifier.
    ARK_PGBOUNCER_ADMIN_PASSWORD: randomBytes(32).toString("base64url"),
    STALWART_ADMIN_ADDRESS: "admin",
    STALWART_ADMIN_PASSWORD: randomBytes(32).toString("base64url"),
    DATABASE_URL: `postgres://ark_runtime:${apiPassword}@127.0.0.1:5433/ark_platform`,
    DATABASE_APP_URL: `postgres://ark_cluster_admin:${appPassword}@127.0.0.1:5434/postgres`,
    BETTER_AUTH_URL: "http://127.0.0.1:3000",
    BETTER_AUTH_TRUSTED_ORIGINS: "http://127.0.0.1:3000,http://127.0.0.1:5173",
    ARK_LISTEN_PORT: "3000",
    ARK_EMBEDDED_WORKERS: "1",
    ARK_CERT_DIR: "./tmp/certs",
    ARK_COMPOSE_DIR: "./tmp/compose",
    ARK_MAIL_STATE_DIR: "./tmp/mail-state",
    ARK_PGBOUNCER_DIR: "./tmp/pgbouncer",
    ARK_DB_INGRESS_METRICS_DIR: "./tmp/db-ingress",
    ARK_EDGE_DIR: "./infra/platform",
  };
}

export function parseEnvFile(source: string) {
  const values: Record<string, string> = {};
  for (const line of source.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    values[trimmed.slice(0, eq)] = trimmed.slice(eq + 1);
  }
  return values;
}

export function isPlaceholderValue(key: string, value: string) {
  const trimmed = value.trim();
  if (!trimmed) return true;
  if (placeholderSecretValues.has(trimmed)) return true;
  if (trimmed.startsWith("change-me")) return true;
  if (insecureDefaultPaths[key]?.includes(trimmed)) return true;
  return false;
}

export function isInstallSecretKey(key: string) {
  return (installEnvKeys as readonly string[]).includes(key);
}

export function mergeInstallEnv(
  existing: string,
  generated: Record<string, string>,
  options: { template?: boolean } = {},
) {
  const current = parseEnvFile(existing);
  const next = { ...generated };
  for (const [key, value] of Object.entries(current)) {
    const secret = isInstallSecretKey(key);
    if (options.template && secret) continue;
    if (secret && isPlaceholderValue(key, value)) continue;
    if (isPlaceholderValue(key, value) && key in generated) continue;
    next[key] = value;
  }
  return Object.entries(next)
    .map(([key, value]) => `${key}=${value}`)
    .join("\n")
    .concat("\n");
}

// Tailscale auth keys are `tskey-<kind>-<id>-<secret>`; anything else, or anything that could
// break out of its `.env` line, is refused rather than written.
const tailscaleAuthKey = /^tskey-[A-Za-z0-9-]+$/;

export type EdgeAuthKeyResult = {
  env: string;
  /** `kept`: `.env` already had a key. `set`: the supplied key was written. `missing`: neither. */
  status: "kept" | "set" | "missing";
};

/**
 * Adds the edge node's one-off auth key (`TS_EDGE_AUTHKEY`) to an installed `.env`. An existing
 * non-empty value always wins; the supplied key is only used to fill an absent or empty entry.
 */
export function applyEdgeAuthKey(env: string, supplied?: string): EdgeAuthKeyResult {
  const current = parseEnvFile(env).TS_EDGE_AUTHKEY?.trim() ?? "";
  if (current) return { env, status: "kept" };
  const key = supplied?.trim() ?? "";
  if (!key) return { env, status: "missing" };
  if (!tailscaleAuthKey.test(key)) {
    throw new Error("TS_EDGE_AUTHKEY must be a Tailscale auth key (tskey-…); it was not written.");
  }
  const lines = env.split("\n");
  const index = lines.findIndex((line) => /^\s*TS_EDGE_AUTHKEY=/.test(line));
  if (index >= 0) {
    lines[index] = `TS_EDGE_AUTHKEY=${key}`;
    return { env: lines.join("\n"), status: "set" };
  }
  const base = env === "" || env.endsWith("\n") ? env : `${env}\n`;
  return { env: `${base}TS_EDGE_AUTHKEY=${key}\n`, status: "set" };
}

const externalServiceSecrets = new Set<string>([
  "ARK_PLATFORM_PG_EXECUTOR_TOKEN",
  "ARK_APP_PG_EXECUTOR_TOKEN",
  "ARK_PLATFORM_PG_REPO_CIPHER_PASS",
  "ARK_APP_PG_REPO_CIPHER_PASS",
  "ARK_CONTROL_DB_PASSWORD",
  "ARK_APP_DB_PASSWORD",
  "ARK_API_DB_PASSWORD",
  "STALWART_ADMIN_PASSWORD",
]);

export function assertNoPlaceholderSecrets(
  env: Record<string, string | undefined> = process.env,
  { embeddedWorkers = true } = {},
) {
  for (const key of installEnvKeys) {
    const value = env[key] ?? "";
    // Without the optional edge tokens the API does not trust proxy addresses or serve watchdog leases.
    if (!value && (key === "ARK_EDGE_GATE_TOKEN" || key === "ARK_EDGE_WATCHDOG_TOKEN")) continue;
    // Compose projects the effective credentials into DATABASE_URL and keeps other services' secrets
    // out of the API container. If a host supplies any of them anyway, still validate the value.
    if (!value && !embeddedWorkers && externalServiceSecrets.has(key)) continue;
    if (!value || isPlaceholderValue(key, value)) {
      throw new Error(
        `${key} still has a published example placeholder. Refuse to start until it is replaced.`,
      );
    }
  }
}

export const hostLossChecklist = [
  "Restore ARK_ROOT_KEY and ARK_ROOT_KEY_ID from off-host storage before any database restore.",
  "Bring up a clean host and unique Compose project names. Do not reuse the failed Tailscale node identity.",
  "Restore the platform database, then application clusters, then mail/volume snapshots.",
  "Disable reconciliation, outbound SES, and public ingress until ownership and credentials are verified.",
  "Re-enroll Tailscale, verify private login, then enable public routes last.",
];

/**
 * Install-time selection of the shared SNI ports (docs/design/front-door.md §3.8.2, FD-14). The
 * selection comes from `supplied` (the installer's environment) or else the existing `.env`, is
 * validated against the supported set, and is written as `ARK_EDGE_SNI_PORTS` plus one
 * `ARK_EDGE_SNI_PORT_<n>=<n>:<n>` publish entry per enabled port, which the edge-ts `ports` list
 * interpolates. Entries for ports no longer enabled are removed, so the published set and the set the
 * API and domain worker accept can never diverge.
 */
export function applyEdgeSniPorts(env: string, supplied?: string) {
  const current = parseEnvFile(env).ARK_EDGE_SNI_PORTS ?? "";
  const ports = parseSniPorts(supplied ?? current);
  const lines = env.split("\n").filter((line) => !/^\s*ARK_EDGE_SNI_PORTS?(?:_\d+)?=/.test(line));
  while (lines.length && lines.at(-1) === "") lines.pop();
  lines.push(`ARK_EDGE_SNI_PORTS=${ports.join(",")}`);
  for (const port of ports) lines.push(`ARK_EDGE_SNI_PORT_${port}=${port}:${port}`);
  return { env: `${lines.join("\n")}\n`, ports };
}
