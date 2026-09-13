import { randomBytes } from "node:crypto";

export const installEnvKeys = [
  "BETTER_AUTH_SECRET",
  "ARK_ROOT_KEY",
  "ARK_SETUP_TOKEN",
  "ARK_INTERNAL_TOKEN",
  "ARK_AGENT_TOKEN",
  "ARK_MAINTENANCE_TOKEN",
] as const;

export function generateInstallSecrets() {
  return {
    BETTER_AUTH_SECRET: randomBytes(32).toString("base64url"),
    ARK_ROOT_KEY: randomBytes(32).toString("base64url"),
    ARK_ROOT_KEY_ID: "k1",
    ARK_SETUP_TOKEN: randomBytes(24).toString("base64url"),
    ARK_INTERNAL_TOKEN: randomBytes(24).toString("base64url"),
    ARK_AGENT_TOKEN: randomBytes(24).toString("base64url"),
    ARK_MAINTENANCE_TOKEN: randomBytes(24).toString("base64url"),
    DATABASE_URL: "postgres://ark:ark@127.0.0.1:5433/ark_platform",
    DATABASE_APP_URL: "postgres://ark_app:ark_app@127.0.0.1:5434/postgres",
    BETTER_AUTH_URL: "http://127.0.0.1:3000",
    BETTER_AUTH_TRUSTED_ORIGINS: "http://127.0.0.1:3000,http://127.0.0.1:5173",
    ARK_LISTEN_PORT: "3000",
    ARK_EMBEDDED_WORKERS: "1",
    ARK_CERT_DIR: "./tmp/certs",
    ARK_COMPOSE_DIR: "./tmp/compose",
    ARK_MAIL_STATE_DIR: "./tmp/mail-state",
    ARK_PGBOUNCER_DIR: "./infra/database",
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

export function mergeInstallEnv(existing: string, generated: Record<string, string>) {
  const current = parseEnvFile(existing);
  const next = { ...generated, ...current };
  return Object.entries(next)
    .map(([key, value]) => `${key}=${value}`)
    .join("\n")
    .concat("\n");
}

export const hostLossChecklist = [
  "Restore ARK_ROOT_KEY and ARK_ROOT_KEY_ID from off-host storage before any database restore.",
  "Bring up a clean host and unique Compose project names. Do not reuse the failed Tailscale node identity.",
  "Restore the platform database, then application clusters, then mail/volume snapshots.",
  "Disable reconciliation, outbound SES, and public ingress until ownership and credentials are verified.",
  "Re-enroll Tailscale, verify private login, then enable public routes last.",
];
