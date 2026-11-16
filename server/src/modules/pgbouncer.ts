// Public PgBouncer: plan, write and reload (docs/design/front-door.md §3.10.2, §3.14, FD-16).
//
// This module has no database import, so it can be unit-tested and bundled into the runtime
// smoke test's database-worker stand-in. The coordinator loads rows and calls `planPgbouncer`,
// writes the rendered files atomically, and reloads PgBouncer through the admin console on the
// unix socket shared only with the database worker. There is no Docker CLI or socket here.

import { generateKeyPairSync, randomBytes } from "node:crypto";
import { connect as netConnect, isIP } from "node:net";
import { chmod, mkdir, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { connect as tlsConnect } from "node:tls";

import {
  PGBOUNCER_ADMIN_USER,
  PGBOUNCER_DEFAULTS,
  PGBOUNCER_FILES,
  PGBOUNCER_PORT,
  PGBOUNCER_SOCKET_DIR,
  pgbouncerConfig,
  pgbouncerHba,
  pgbouncerUserlist,
  renderClientCaBundle,
  scramSha256Verifier,
  selectClientCaBundle,
  type BundleCa,
  type BundleCertificate,
  type PgbouncerSettings,
} from "@ark-stack/shared";
import postgres from "postgres";

import * as x509 from "./x509.ts";

// ---- Deny-all CA ---------------------------------------------------------------------------------

/**
 * A fresh self-signed CA whose private key is discarded before this function returns. With no
 * admitted client the bundle holds only this certificate, so `verify-full` can be satisfied by
 * nobody. Leaving `client_tls_ca_file` empty or unset is never an option: PgBouncer's TLS layer
 * would then fall back to the system trust store.
 */
export function denyAllCaPem(now = new Date()) {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = x509.spkiDer(privateKey);
  const keyId = x509.keyIdentifier(spki);
  const notBefore = new Date(Math.floor(now.getTime() / 1000) * 1000);
  const notAfter = new Date(notBefore);
  notAfter.setUTCFullYear(notAfter.getUTCFullYear() + 10);
  const subject = x509.name([
    { type: "CN", value: "Ark db-client CA deny-all" },
    { type: "serialNumber", value: randomBytes(8).toString("hex") },
  ]);
  const serial = randomBytes(16);
  serial[0] = (serial[0]! & 0x7f) | 0x01;
  const tbs = x509.sequence(
    x509.explicit(0, x509.integer(2)),
    x509.integerFromBytes(serial),
    x509.ecdsaWithSha256(),
    subject,
    x509.sequence(x509.time(notBefore), x509.time(notAfter)),
    subject,
    spki,
    x509.explicit(
      3,
      x509.sequence(
        x509.extension(x509.OID.basicConstraints, true, x509.basicConstraintsValue(true, 0)),
        x509.extension(x509.OID.keyUsage, true, x509.keyUsageValue(["keyCertSign", "cRLSign"])),
        x509.extension(x509.OID.subjectKeyIdentifier, false, x509.subjectKeyIdentifierValue(keyId)),
        x509.extension(x509.OID.authorityKeyIdentifier, false, x509.authorityKeyIdentifierValue(keyId)),
      ),
    ),
  );
  return x509.toPem("CERTIFICATE", x509.signStructure(tbs, privateKey));
}

// ---- Plan ----------------------------------------------------------------------------------------

export type PlanDatabase = { id: string; name: string; exposure: string };
export type PlanClient = {
  id: string;
  databaseId: string;
  environment: string;
  status: string;
  caId: string;
  role: { name: string; connectionLimit: number; password: string | null };
};

/**
 * Decide what PgBouncer serves. Only active clients of public databases with a stored role
 * password and at least one trusted certificate generation are admitted; only databases with an
 * admitted client are mapped. With nobody admitted the plan is closed: no mappings, no users,
 * a deny-all CA bundle, and `routed: false` so the public listener stays shut.
 */
export function planPgbouncer(input: {
  databases: PlanDatabase[];
  clients: PlanClient[];
  certificates: BundleCertificate[];
  cas: BundleCa[];
  now: Date;
  host: string;
  settings?: Partial<PgbouncerSettings>;
  denyAllCa?: () => string;
}) {
  const settings = { ...PGBOUNCER_DEFAULTS, ...input.settings };
  const publicDatabases = new Map(
    input.databases.filter((item) => item.exposure === "public").map((item) => [item.id, item]),
  );
  // Revoked clients still feed the selection so their CAs are excluded; active clients that
  // cannot connect anyway (private database, no password) are left out of the trust set.
  const candidates = input.clients.filter(
    (client) =>
      client.status !== "active" || (publicDatabases.has(client.databaseId) && Boolean(client.role.password)),
  );
  const selection = selectClientCaBundle({
    clients: candidates,
    certificates: input.certificates,
    cas: input.cas,
    now: input.now,
  });
  const admitted = new Set(selection.admittedClientIds);
  const clients = candidates
    .filter((client) => admitted.has(client.id))
    .toSorted((a, b) => a.role.name.localeCompare(b.role.name));
  const mapped = new Set(clients.map((client) => client.databaseId));
  const mappings = [...publicDatabases.values()]
    .filter((database) => mapped.has(database.id))
    .toSorted((a, b) => a.name.localeCompare(b.name))
    .map((database) => ({ database: database.name, host: input.host }));
  const users = clients.map((client) => ({
    name: client.role.name,
    maxUserConnections: client.role.connectionLimit,
    maxUserClientConnections:
      client.environment === "production"
        ? settings.maxUserClientConnections
        : settings.previewMaxUserClientConnections,
  }));
  const routed = selection.generations.length > 0 && mappings.length > 0;
  return {
    routed,
    mappings: routed ? mappings : [],
    users: routed ? users : [],
    credentials: routed
      ? clients.map((client) => ({ name: client.role.name, password: client.role.password! }))
      : [],
    caBundle: routed
      ? renderClientCaBundle(selection.generations)
      : renderClientCaBundle([{ certPem: (input.denyAllCa ?? denyAllCaPem)() }]),
    generations: routed ? selection.generations.map(({ certPem: _pem, ...rest }) => rest) : [],
    excluded: selection.excluded,
    admittedClientIds: routed ? clients.map((client) => client.id) : [],
    settings,
  };
}

/** Render the four files PgBouncer reads. The admin password itself is never written. */
export function renderPgbouncerFiles(input: {
  plan: ReturnType<typeof planPgbouncer>;
  adminPassword?: string;
  certificateDir?: string;
}) {
  return {
    [PGBOUNCER_FILES.config]: pgbouncerConfig({
      mappings: input.plan.mappings,
      users: input.plan.users,
      certificateDir: input.certificateDir,
      settings: input.plan.settings,
    }),
    [PGBOUNCER_FILES.hba]: pgbouncerHba(),
    [PGBOUNCER_FILES.userlist]: pgbouncerUserlist(input.plan.credentials, {
      adminVerifier: input.adminPassword ? scramSha256Verifier(input.adminPassword) : undefined,
    }),
    [PGBOUNCER_FILES.caBundle]: input.plan.caBundle,
  };
}

/**
 * Replace each file atomically (`<name>.next`, then rename) with mode 0600. The CA bundle,
 * userlist and HBA land before the INI that references them.
 */
export async function writePgbouncerFiles(dir: string, files: Record<string, string>) {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const order = [
    PGBOUNCER_FILES.caBundle,
    PGBOUNCER_FILES.hba,
    PGBOUNCER_FILES.userlist,
    PGBOUNCER_FILES.config,
  ];
  const names = [
    ...order.filter((name) => name in files),
    ...Object.keys(files).filter((name) => !order.includes(name as never)),
  ];
  for (const name of names) {
    const target = join(dir, name);
    await writeFile(`${target}.next`, files[name]!, { mode: 0o600 });
    await chmod(`${target}.next`, 0o600);
    await rename(`${target}.next`, target);
  }
  return { dir, files: names };
}

// ---- Admin console over the unix socket ----------------------------------------------------------

export type AdminSocketOptions = {
  socketDir?: string;
  port?: number;
  password: string;
  connectTimeoutSeconds?: number;
};

const ADMIN_COMMAND = /^(RELOAD|SHOW [A-Z_]+)$/;

/** Run one console command as the administrator over the shared socket (simple protocol). */
export async function pgbouncerAdminCommand(command: string, options: AdminSocketOptions) {
  if (!ADMIN_COMMAND.test(command)) throw new Error(`Refusing PgBouncer console command: ${command}`);
  if (!options.password) throw new Error("The PgBouncer administrator password is not configured.");
  const sql = postgres({
    path: join(options.socketDir ?? PGBOUNCER_SOCKET_DIR, `.s.PGSQL.${options.port ?? PGBOUNCER_PORT}`),
    database: "pgbouncer",
    username: PGBOUNCER_ADMIN_USER,
    password: options.password,
    max: 1,
    prepare: false,
    fetch_types: false,
    connect_timeout: options.connectTimeoutSeconds ?? 10,
    onnotice: () => undefined,
    connection: { application_name: "ark-database-worker" },
  });
  try {
    return await sql.unsafe(command).simple();
  } finally {
    await sql.end({ timeout: 2 }).catch(() => undefined);
  }
}

export async function reloadPgbouncerAdmin(options: AdminSocketOptions) {
  await pgbouncerAdminCommand("RELOAD", options);
}

// ---- Served certificate --------------------------------------------------------------------------

export function normalizeFingerprint(value: string) {
  return value.replace(/[:\s]/g, "").toLowerCase();
}

/**
 * The SHA-256 fingerprint of the leaf certificate PgBouncer serves: a PostgreSQL SSLRequest,
 * then a TLS 1.3 handshake without a client certificate. PgBouncer rejects the client after the
 * handshake (verify-full), which is expected; the server certificate is already known by then.
 */
export function servedCertificateFingerprint(input: {
  host: string;
  port?: number;
  servername?: string;
  timeoutMs?: number;
}) {
  return new Promise<string>((resolve, reject) => {
    let settled = false;
    const socket = netConnect({ host: input.host, port: input.port ?? PGBOUNCER_PORT });
    const finish = (error: Error | null, value?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve(value!);
    };
    const timer = setTimeout(
      () => finish(new Error("Timed out reading the served PgBouncer certificate.")),
      input.timeoutMs ?? 10_000,
    );
    socket.once("error", (error) => finish(error));
    socket.once("connect", () => socket.write(Buffer.from([0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f])));
    socket.once("data", (chunk) => {
      if (chunk[0] !== 0x53) return finish(new Error("PgBouncer did not accept the TLS request."));
      const servername = input.servername ?? (isIP(input.host) ? undefined : input.host);
      const secure = tlsConnect({
        socket,
        servername,
        rejectUnauthorized: false,
        minVersion: "TLSv1.3",
      });
      secure.once("secureConnect", () => {
        const fingerprint = secure.getPeerCertificate()?.fingerprint256;
        secure.destroy();
        if (!fingerprint) finish(new Error("PgBouncer served no certificate."));
        else finish(null, normalizeFingerprint(fingerprint));
      });
      secure.once("error", (error) => finish(error));
    });
  });
}

// ---- Reload with retries -------------------------------------------------------------------------

export class PgbouncerReloadError extends Error {
  readonly attempts: number;
  readonly failures: string[];
  constructor(attempts: number, failures: string[]) {
    super(`PgBouncer reload failed after ${attempts} attempt(s): ${failures.at(-1) ?? "unknown error"}`);
    this.name = "PgbouncerReloadError";
    this.attempts = attempts;
    this.failures = failures;
  }
}

/**
 * RELOAD, then (for a certificate change) confirm that the served fingerprint is the expected
 * one. Failures are retried with a linear backoff; after the last attempt this throws, so a
 * caller can never record success for a reload that did not take effect.
 */
export async function reloadAndVerify(input: {
  reload: () => Promise<unknown>;
  servedFingerprint?: () => Promise<string>;
  expectedFingerprint?: string;
  attempts?: number;
  delayMs?: number;
  sleep?: (ms: number) => Promise<void>;
}) {
  const attempts = Math.max(1, input.attempts ?? 3);
  const sleep = input.sleep ?? ((ms: number) => new Promise<void>((done) => setTimeout(done, ms)));
  const expected = input.expectedFingerprint ? normalizeFingerprint(input.expectedFingerprint) : undefined;
  if (expected && !input.servedFingerprint) throw new Error("A served-fingerprint probe is required.");
  const failures: string[] = [];
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      await input.reload();
      let fingerprint: string | undefined;
      if (expected) {
        fingerprint = normalizeFingerprint(await input.servedFingerprint!());
        if (fingerprint !== expected) {
          throw new Error(`served certificate ${fingerprint} is not the renewed ${expected}`);
        }
      }
      return { attempts: attempt, fingerprint, failures };
    } catch (error) {
      failures.push(`attempt ${attempt}: ${error instanceof Error ? error.message : String(error)}`);
      if (attempt < attempts) await sleep((input.delayMs ?? 2_000) * attempt);
    }
  }
  throw new PgbouncerReloadError(attempts, failures);
}
