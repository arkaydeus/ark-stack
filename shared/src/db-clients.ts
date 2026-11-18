// Database clients for external apps such as Vercel deployments (docs/design/front-door.md
// §3.10.3, §3.12, ticket FD-17).
//
// Each client is one app environment ("storefront" / "preview") of one public database. It gets
// its own login role `<db>_<client>_<env>`, created `IN ROLE <db>_runtime` or `<db>_readonly`
// so it inherits the least-privilege grants of shared/src/provision-sql.ts, and a 90-day client
// certificate from its own CA generation. Preview environments default to read-only (R5).
//
// Everything here is pure: naming, role SQL, request validation, and the Vercel guide that the
// one-time reveal fills with real values (and the guide endpoint fills with placeholders).

import { z } from "zod";

import { ValidationError } from "./errors.ts";
import { quoteIdent } from "./hostnames.ts";
import { literal } from "./provision-sql.ts";
import { regionProfiles, type PlatformRegion, type VercelRegionCode } from "./region.ts";

export const DB_CLIENT_ROLE_KINDS = ["runtime", "readonly"] as const;
export type DbClientRoleKind = (typeof DB_CLIENT_ROLE_KINDS)[number];

/** Server connection limits per role kind (§3.10.2 example: production 20, preview 5). */
export const DB_CLIENT_CONNECTION_LIMITS: Record<DbClientRoleKind, number> = { runtime: 20, readonly: 5 };

/** CSR submissions are PEM text of at most 16 KiB (the API and pki.validateCsr both enforce it). */
export const DB_CLIENT_CSR_MAX_BYTES = 16 * 1024;

/** Client and environment names: lowercase letters and digits, no separators. */
const CLIENT_NAME = /^[a-z][a-z0-9]{0,23}$/;
const ENVIRONMENT = /^[a-z][a-z0-9]{0,15}$/;
/**
 * Environment names that would make `<db>_<client>_<env>` look like another database's group or
 * privileged role (db `a_b` has `a_b_runtime`; client `b` of db `a` in `runtime` would collide).
 */
const RESERVED_ENVIRONMENTS = new Set([
  "owner",
  "migration",
  "runtime",
  "readonly",
  "backup",
  "monitor",
  "admin",
]);
const PRIVILEGED_SUFFIX = /_(owner|migration|backup|monitor)$/;

/** R5: production writes through `runtime`; every other environment defaults to `readonly`. */
export function defaultClientRoleKind(environment: string): DbClientRoleKind {
  return environment === "production" ? "runtime" : "readonly";
}

/**
 * The client's login role, `<db>_<client>_<env>`. Client and environment names carry no
 * underscores, so the last two segments always identify the client and the name cannot collide
 * with another database's roles.
 */
export function clientRoleName(database: string, name: string, environment: string) {
  if (!/^[a-z][a-z0-9_]{0,40}$/.test(database)) throw new ValidationError("Invalid database name.");
  if (!CLIENT_NAME.test(name))
    throw new ValidationError("Client names are 1-24 lowercase letters or digits, starting with a letter.");
  if (!ENVIRONMENT.test(environment))
    throw new ValidationError("Environments are 1-16 lowercase letters or digits, starting with a letter.");
  if (RESERVED_ENVIRONMENTS.has(environment))
    throw new ValidationError(`"${environment}" is reserved and cannot be a client environment.`);
  const role = `${database}_${name}_${environment}`;
  if (role.length > 63)
    throw new ValidationError(
      `The login role ${role} is longer than PostgreSQL's 63-character limit; use a shorter client or environment name.`,
    );
  if (PRIVILEGED_SUFFIX.test(role)) throw new ValidationError("The client role would look privileged.");
  return role;
}

/** `<db>_runtime` or `<db>_readonly`: the group whose grants the client inherits. */
export const clientGroupRole = (database: string, kind: DbClientRoleKind) => `${database}_${kind}`;

/** `POST /api/databases/:id/clients`. `csrPem` selects advanced issuance (the key never reaches Ark). */
export const databaseClientInput = z
  .object({
    name: z.string().regex(CLIENT_NAME, "Client names are 1-24 lowercase letters or digits."),
    environment: z.string().regex(ENVIRONMENT, "Environments are 1-16 lowercase letters or digits."),
    roleKind: z.enum(DB_CLIENT_ROLE_KINDS).optional(),
    csrPem: z
      .string()
      .min(1)
      .max(DB_CLIENT_CSR_MAX_BYTES, `CSRs are PEM text of at most ${DB_CLIENT_CSR_MAX_BYTES / 1024} KiB.`)
      .refine((value) => Buffer.byteLength(value, "utf8") <= DB_CLIENT_CSR_MAX_BYTES, {
        message: `CSRs are PEM text of at most ${DB_CLIENT_CSR_MAX_BYTES / 1024} KiB.`,
      })
      .refine((value) => /^\s*-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----/.test(value), {
        message: "Submit the CSR as PEM (-----BEGIN CERTIFICATE REQUEST-----).",
      })
      .optional(),
  })
  .strict();
export type DatabaseClientInput = z.infer<typeof databaseClientInput>;

/**
 * Create the client's login role, or bring an existing Ark-owned one to the planned state (a
 * retried issue). `INHERIT` + `IN ROLE` gives it the group's CONNECT and table grants; it can
 * never create roles, databases or bypass row security.
 */
export function clientRoleSql(input: {
  role: string;
  group: string;
  password: string;
  connectionLimit: number;
  exists: boolean;
}) {
  const role = quoteIdent(input.role);
  const group = quoteIdent(input.group);
  if (!Number.isSafeInteger(input.connectionLimit) || input.connectionLimit < 1)
    throw new ValidationError("Invalid connection limit.");
  const attributes = `LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT ${input.connectionLimit} PASSWORD ${literal(input.password)}`;
  return input.exists
    ? [`ALTER ROLE ${role} WITH ${attributes}`, `GRANT ${group} TO ${role}`]
    : [`CREATE ROLE ${role} WITH ${attributes} IN ROLE ${group}`];
}

/** Revocation: a new random password the client never sees, and no further logins. */
export function revokedClientRoleSql(role: string, password: string) {
  return [`ALTER ROLE ${quoteIdent(role)} WITH NOLOGIN PASSWORD ${literal(password)}`];
}

// ---- Vercel guide (§3.12) ----------------------------------------------------------------------

/** Env var names never change; rollover replaces only the values (§3.12). */
export const VERCEL_ENV_NAMES = {
  host: "ARK_DB_HOST",
  database: "ARK_DB_NAME",
  user: "ARK_DB_USER",
  password: "ARK_DB_PASSWORD",
  cert: "ARK_DB_CLIENT_CERT_B64",
  key: "ARK_DB_CLIENT_KEY_B64",
} as const;

/**
 * §3.12's node-postgres module, verbatim: a module-scope `Pool` with the client certificate and
 * key from base64 env vars, TLS 1.3 and a verified server certificate, released by
 * `attachDatabasePool` before the function suspends.
 */
export const NODE_POSTGRES_SNIPPET = `// lib/db.ts — module scope, so one pool is reused per function instance
import { Pool } from "pg";
import { attachDatabasePool } from "@vercel/functions";

const pem = (name: string) => Buffer.from(process.env[name] ?? "", "base64").toString("utf8");

export const pool = new Pool({
  host: process.env.ARK_DB_HOST, // hostname, not IP: node-postgres then sets SNI itself
  port: 5432,
  database: process.env.ARK_DB_NAME,
  user: process.env.ARK_DB_USER,
  password: process.env.ARK_DB_PASSWORD,
  ssl: {
    rejectUnauthorized: true, // server cert is public Let's Encrypt; no custom CA needed
    minVersion: "TLSv1.3",
    cert: pem("ARK_DB_CLIENT_CERT_B64"),
    key: pem("ARK_DB_CLIENT_KEY_B64"),
  },
  max: 5,
  idleTimeoutMillis: 5_000,
  connectionTimeoutMillis: 5_000,
});
attachDatabasePool(pool);
`;

export type DatabaseClientGuideInput = {
  host: string;
  database: string;
  role: string;
  environment: string;
  roleKind: DbClientRoleKind;
  region: PlatformRegion;
  /** Real values for the one-time reveal. Omit them for the placeholder guide. */
  secrets?: { password: string; certPem: string; keyPem: string | null };
};

const base64 = (value: string) => Buffer.from(value, "utf8").toString("base64");

export type VercelEnvVar = { name: string; value: string; sensitive: boolean };

/**
 * The §3.12 guide for one client: env vars (base64 certificate and key), the `vercel env add`
 * commands, the node-postgres module and `vercel.json` with the platform region's Vercel region.
 * With `secrets` the values are real (one-time reveal); without, they are placeholders.
 */
export function databaseClientGuide(input: DatabaseClientGuideInput) {
  // production and preview are Vercel's built-in targets; any other name is a custom environment.
  const target = input.environment;
  const vercelRegion: VercelRegionCode = regionProfiles[input.region].vercelRegion;
  const secrets = input.secrets;
  const env: VercelEnvVar[] = [
    { name: VERCEL_ENV_NAMES.host, value: input.host, sensitive: false },
    { name: VERCEL_ENV_NAMES.database, value: input.database, sensitive: false },
    { name: VERCEL_ENV_NAMES.user, value: input.role, sensitive: false },
    {
      name: VERCEL_ENV_NAMES.password,
      value: secrets ? secrets.password : "<password from the one-time reveal>",
      sensitive: true,
    },
    {
      name: VERCEL_ENV_NAMES.cert,
      value: secrets ? base64(secrets.certPem) : "<base64 of client.crt>",
      sensitive: true,
    },
    {
      name: VERCEL_ENV_NAMES.key,
      value: secrets?.keyPem
        ? base64(secrets.keyPem)
        : secrets
          ? "<base64 of the key you generated with your CSR>"
          : "<base64 of client.key>",
      sensitive: true,
    },
  ];
  const userNote = input.roleKind === "readonly" ? `${input.role}, read-only` : input.role;
  const commands = [
    `vercel env add ${VERCEL_ENV_NAMES.host} ${target}          # ${input.host}`,
    `vercel env add ${VERCEL_ENV_NAMES.database} ${target}          # ${input.database}`,
    `vercel env add ${VERCEL_ENV_NAMES.user} ${target}          # ${userNote}`,
    `vercel env add ${VERCEL_ENV_NAMES.password} ${target} --sensitive`,
    `base64 -i client.crt | tr -d '\\n' | vercel env add ${VERCEL_ENV_NAMES.cert} ${target} --sensitive`,
    `base64 -i client.key | tr -d '\\n' | vercel env add ${VERCEL_ENV_NAMES.key} ${target} --sensitive`,
  ].join("\n");
  const vercelJson = { regions: [vercelRegion] };
  return {
    target,
    env,
    commands: `${commands}\n`,
    nodePostgres: NODE_POSTGRES_SNIPPET,
    vercelJson,
    vercelJsonSnippet: JSON.stringify(vercelJson),
    vercelRegion,
    notes: [
      "Do not put sslmode, sslcert, sslkey or sslrootcert in a connection string: node-postgres then replaces the ssl object.",
      "The server certificate is publicly trusted; no custom CA is needed. TLS 1.3 is required.",
      `Pin the function region to ${vercelRegion} (vercel.json) so it stays next to the database.`,
      "The client certificate is valid for 90 days. Check the --sensitive flag spelling against your Vercel CLI version.",
      ...(input.roleKind === "readonly"
        ? ["This client is read-only: INSERT, UPDATE and DELETE are refused with permission denied."]
        : []),
    ],
  };
}

// ---- Automatic rollover (§3.10.4, FD-28) -------------------------------------------------------

const DAY_MS = 86_400_000;

/** Issue the successor this many days before the current certificate's not_after (T−30). */
export const ROLLOVER_LEAD_DAYS = 30;
/** The rollover-pending alert becomes a warning at T−14 and critical at T−7. */
export const ROLLOVER_WARNING_DAYS = 14;
export const ROLLOVER_CRITICAL_DAYS = 7;
/** Every session of a retiring generation's role is closed by not_after plus this deadline. */
export const RETIREMENT_DEADLINE_MS = 5_000;

/** Dedup key prefixes of the rollover alerts (server/src/modules/alerts.ts). */
export const ROLLOVER_ALERT_PREFIX = "db-client-rollover:";
export const RETIREMENT_ALERT_PREFIX = "db-client-retire:";

/** True once a certificate is within the rollover lead time (T−30 days) of its not_after. */
export function rolloverDue(notAfter: Date, now: Date, leadDays = ROLLOVER_LEAD_DAYS) {
  return notAfter.getTime() - now.getTime() <= leadDays * DAY_MS;
}

export type RolloverAlertLevel = "info" | "warning" | "critical";

/**
 * The rollover-pending alert for a certificate whose successor is not delivered yet: `info`
 * (pending) from T−30, `warning` from T−14 and `critical` from T−7 (and after expiry). Null
 * before T−30.
 */
export function rolloverAlertLevel(notAfter: Date, now: Date): RolloverAlertLevel | null {
  const left = notAfter.getTime() - now.getTime();
  if (left <= ROLLOVER_CRITICAL_DAYS * DAY_MS) return "critical";
  if (left <= ROLLOVER_WARNING_DAYS * DAY_MS) return "warning";
  if (left <= ROLLOVER_LEAD_DAYS * DAY_MS) return "info";
  return null;
}

/** Whole days (rounded down) until `notAfter`; negative once it has passed. */
export function daysUntil(notAfter: Date, now: Date) {
  return Math.floor((notAfter.getTime() - now.getTime()) / DAY_MS);
}

export function rolloverAlertTitle(input: { role: string; notAfter: Date; now: Date; needsCsr?: boolean }) {
  const days = daysUntil(input.notAfter, input.now);
  const when =
    input.notAfter.getTime() <= input.now.getTime()
      ? `expired ${input.notAfter.toISOString()} before its successor was delivered`
      : `expires in ${days} day(s) (${input.notAfter.toISOString()})`;
  const action = input.needsCsr
    ? "submit a CSR to the early-rollover endpoint, deliver the successor and confirm"
    : "reveal the successor, deliver it and confirm";
  return `Database client ${input.role}: certificate rollover pending; the current certificate ${when}. ${action}.`;
}

/**
 * The client-level rollover status derived from its certificate chain:
 * `none` (no successor in flight) → `pending` (successor issued, not delivered) → `delivered`
 * (successor promoted; the predecessor stays trusted until its not_after) → `retired` (the
 * predecessor's generation was removed and its role drained). A new cycle starts at `none`
 * again only after the predecessor retired; a fresh client with one certificate is `none`.
 */
export type ClientRolloverStatus = "none" | "pending" | "delivered" | "retired";

export function clientRolloverStatus(
  certificates: Array<{ id: string; status: string; rolloverState: string; supersededBy: string | null }>,
): ClientRolloverStatus {
  const pending = certificates.find((item) => item.status === "issued" && item.rolloverState === "pending");
  if (pending) return "pending";
  const superseded = certificates.some(
    (item) => item.status === "issued" && item.rolloverState === "superseded",
  );
  if (superseded) return "delivered";
  if (certificates.some((item) => item.rolloverState === "retired")) return "retired";
  return "none";
}

/** `POST /api/databases/:id/clients/:clientId/rollover` (owner, step-up). */
export const earlyRolloverInput = z
  .object({
    csrPem: z
      .string()
      .min(1)
      .max(DB_CLIENT_CSR_MAX_BYTES, `CSRs are PEM text of at most ${DB_CLIENT_CSR_MAX_BYTES / 1024} KiB.`)
      .refine((value) => Buffer.byteLength(value, "utf8") <= DB_CLIENT_CSR_MAX_BYTES, {
        message: `CSRs are PEM text of at most ${DB_CLIENT_CSR_MAX_BYTES / 1024} KiB.`,
      })
      .refine((value) => /^\s*-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----/.test(value), {
        message: "Submit the CSR as PEM (-----BEGIN CERTIFICATE REQUEST-----).",
      })
      .optional(),
  })
  .strict();

/** `POST /api/databases/:id/clients/:clientId/rollover/confirm` (owner, MFA). */
export const rolloverConfirmInput = z.object({ certificateId: z.string().min(1).max(64) }).strict();

/**
 * §3.12's manual rollover step for one client: only the certificate and key values change (the
 * env var names, role and password stay), then redeploy and confirm. With `secrets` the env
 * values are real (the successor's one-time reveal).
 */
export function databaseClientRolloverGuide(input: {
  environment: string;
  secrets?: { certPem: string; keyPem: string | null };
  vercelScope?: { projectId: string; target: "production" | "preview"; gitBranch: string | null };
}) {
  const target = input.vercelScope?.target ?? input.environment;
  const branch = target === "preview" ? input.vercelScope?.gitBranch : null;
  const project = input.vercelScope?.projectId;
  const branchArg = branch ? "'" + branch.replaceAll("'", "'\\''") + "'" : "";
  const envScope = branch ? `--environment preview --git-branch=${branchArg}` : target;
  const secrets = input.secrets;
  const env: VercelEnvVar[] = [
    {
      name: VERCEL_ENV_NAMES.cert,
      value: secrets ? base64(secrets.certPem) : "<base64 of client-next.crt>",
      sensitive: true,
    },
    {
      name: VERCEL_ENV_NAMES.key,
      value: secrets?.keyPem
        ? base64(secrets.keyPem)
        : secrets
          ? "<base64 of the key you generated with your rollover CSR>"
          : "<base64 of client-next.key>",
      sensitive: true,
    },
  ];
  const commands = [
    "# Reveal the new bundle once in Ark (step-up), then:",
    ...(project ? [`# Link this checkout to Vercel project ${project} before updating the variables.`] : []),
    `base64 -i client-next.crt | tr -d '\\n' | vercel env add ${VERCEL_ENV_NAMES.cert} ${envScope} --sensitive --force`,
    `base64 -i client-next.key | tr -d '\\n' | vercel env add ${VERCEL_ENV_NAMES.key} ${envScope} --sensitive --force`,
    branch
      ? `# Redeploy Preview branch ${JSON.stringify(branch)} using its deploy hook or the Vercel dashboard.`
      : `vercel deploy${target === "production" ? " --prod" : ""}        # or redeploy from the dashboard`,
    "# Check database access, then confirm in Ark: POST the reveal's confirm.path with its confirm.body (MFA).",
  ].join("\n");
  return {
    target,
    env,
    commands: `${commands}\n`,
    notes: [
      "The old certificate admits new connections until its expiry, and its role's sessions are closed by expiry + 5 s; redeploy any time before then.",
      "Clients must reconnect and refresh their pools after the redeploy. Check the --force and --sensitive flag spellings against your Vercel CLI version.",
      ...(branch ? ["Branch-specific commands require Vercel CLI 64.7.0 or later."] : []),
    ],
  };
}
