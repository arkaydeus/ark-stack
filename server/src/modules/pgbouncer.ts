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

// RELOAD and SHOW for FD-16; KILL_CLIENT for FD-17 revocation; DISABLE/ENABLE (admission fence)
// and SET client_login_timeout (pre-auth drain) for FD-28. SHUTDOWN is never accepted here: only
// the retirement watchdog may stop PgBouncer, through shutdownPgbouncerAdmin.
const ADMIN_COMMAND =
  /^(RELOAD|SHOW [A-Z_]+|KILL_CLIENT [1-9][0-9]{0,18}|(?:DISABLE|ENABLE) [a-z_][a-z0-9_]{0,62}|SET client_login_timeout = [1-9][0-9]{0,5})$/;

/** Run one console command as the administrator over the shared socket (simple protocol). */
export async function pgbouncerAdminCommand(command: string, options: AdminSocketOptions) {
  if (!ADMIN_COMMAND.test(command)) throw new Error(`Refusing PgBouncer console command: ${command}`);
  return consoleCommand(command, options);
}

/**
 * The FD-28 watchdog's last resort when a retirement misses its deadline: stop PgBouncer. The
 * container restarts with the reduced files already on disk and no client sessions at all.
 */
export async function shutdownPgbouncerAdmin(options: AdminSocketOptions) {
  // PgBouncer exits while answering, so a dropped connection is the expected outcome.
  await consoleCommand("SHUTDOWN", options).catch((error: unknown) => {
    if (!/closed|terminat|ECONNRESET|EPIPE|CONNECTION_ENDED|CONNECTION_CLOSED/i.test(String(error)))
      throw error;
  });
}

async function consoleCommand(command: string, options: AdminSocketOptions) {
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

const ROLE_NAME = /^[a-z_][a-z0-9_]{0,62}$/;

/** The console client IDs (SHOW CLIENTS `id`) of every connection authenticated as `role`. */
export async function roleClientIds(role: string, options: AdminSocketOptions) {
  if (!ROLE_NAME.test(role)) throw new Error(`Invalid PgBouncer role: ${role}`);
  const rows = await pgbouncerAdminCommand("SHOW CLIENTS", options);
  return [...rows]
    .filter((row) => String(row.user) === role)
    .map((row) => String(row.id))
    .filter((id) => /^[1-9][0-9]{0,18}$/.test(id));
}

/**
 * Close every PgBouncer client session of one login role (§3.10.4 step 4). A RELOAD with a
 * smaller CA bundle only affects new handshakes, and an authenticated session survives it, so
 * revocation must kill them. `KILL_CLIENT` also closes the server connections those clients
 * hold. Repeats until no session of the role remains, then reports what it closed; other roles'
 * sessions are never touched.
 */
export async function killRoleClients(
  role: string,
  options: AdminSocketOptions & { attempts?: number; delayMs?: number },
) {
  if (role === PGBOUNCER_ADMIN_USER) throw new Error("Refusing to kill the console administrator.");
  const attempts = Math.max(1, options.attempts ?? 3);
  const killed = new Set<string>();
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const ids = await roleClientIds(role, options);
    if (!ids.length) return { killed: killed.size, attempts: attempt, remaining: 0 };
    for (const id of ids) {
      // A client may disconnect between SHOW CLIENTS and KILL_CLIENT; that is not a failure.
      await pgbouncerAdminCommand(`KILL_CLIENT ${id}`, options).catch(() => undefined);
      killed.add(id);
    }
    await new Promise((done) => setTimeout(done, options.delayMs ?? 100));
  }
  const remaining = (await roleClientIds(role, options)).length;
  if (remaining) throw new Error(`${remaining} PgBouncer session(s) of ${role} survived KILL_CLIENT.`);
  return { killed: killed.size, attempts, remaining };
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

// ---- Generation retirement (§3.10.4 step 4, FD-28) ------------------------------------------------

export type AdminCommand = (command: string) => Promise<ReadonlyArray<Record<string, unknown>>>;

/** A console runner over the shared socket, for retireGeneration and the watchdog. */
export function socketAdmin(options: AdminSocketOptions): AdminCommand {
  return async (command) => [...(await pgbouncerAdminCommand(command, options))];
}

/** PgBouncer prints `connect_time` as `YYYY-MM-DD HH:MM:SS UTC` (second resolution). */
function connectTime(value: unknown) {
  if (value instanceof Date) return value.getTime();
  const match = /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(?:\.\d+)? (?:UTC|GMT|\+00(?::?00)?)$/.exec(
    String(value ?? ""),
  );
  return match ? Date.parse(`${match[1]}T${match[2]}Z`) : null;
}

export type RetirementTimeline = {
  startedAt: number;
  fencedAt: number;
  reloadedAt: number;
  drainedAt: number;
  reopenedAt: number;
  killedRoleClients: number;
  preAuthWaited: number;
  iterations: number;
  deadline: number;
  withinDeadline: boolean;
  reopenSkipped?: string;
};

export class RetirementError extends Error {
  readonly timeline: Partial<RetirementTimeline>;
  constructor(message: string, timeline: Partial<RetirementTimeline>) {
    super(message);
    this.name = "RetirementError";
    this.timeline = timeline;
  }
}

/**
 * Retire one certificate generation of one login role (§3.10.4 step 4) and close every session
 * of that role by `deadline` (the certificate's not_after + 5 s):
 *
 * 1. `DISABLE <database>` fences admission: PgBouncer refuses any client that finishes login
 *    while disabled (`finish_client_login`), including one whose TLS handshake with the old
 *    certificate completed before the reload. Other roles' established sessions are untouched;
 *    new connections to this database briefly fail and retry.
 * 2. `apply()` writes the reduced CA bundle and runs RELOAD, so new handshakes need a trusted
 *    generation.
 * 3. `SET client_login_timeout = 1`, then `KILL_CLIENT` every client of the role until none is
 *    left. `SHOW CLIENTS` and `KILL_CLIENT` cannot see pre-auth clients (PgBouncer keeps them on
 *    its login list), so the shortened login timeout makes the janitor close every pre-auth
 *    socket that connected before the reload; `SHOW SOCKETS` (`cl_login`) proves they are gone.
 * 4. Restore `client_login_timeout`, verify the role has no client, then `ENABLE <database>`.
 *
 * Throws a RetirementError (with the partial timeline) if the role still has sessions, or
 * pre-reload logins remain, at the deadline. The fence is left in place on failure: the caller
 * retries, alerts, and the watchdog escalates.
 */
export async function retireGeneration(input: {
  database: string;
  role: string;
  deadline: Date;
  admin: AdminCommand;
  /**
   * Write the reduced bundle and RELOAD. Report `databaseMapped: false` when the database left
   * [databases] with this reload (its last admitted client is gone), so ENABLE is best-effort.
   */
  apply: () => Promise<{ databaseMapped?: boolean } | void>;
  /** The configured client_login_timeout (seconds) to restore. */
  loginTimeoutSeconds?: number;
  clock?: () => number;
  sleep?: (ms: number) => Promise<void>;
  pollMs?: number;
}) {
  if (input.role === PGBOUNCER_ADMIN_USER) throw new Error("Refusing to drain the console administrator.");
  if (!ROLE_NAME.test(input.role)) throw new Error(`Invalid PgBouncer role: ${input.role}`);
  if (!ROLE_NAME.test(input.database)) throw new Error(`Invalid PgBouncer database: ${input.database}`);
  const clock = input.clock ?? Date.now;
  const sleep = input.sleep ?? ((ms: number) => new Promise<void>((done) => setTimeout(done, ms)));
  const pollMs = input.pollMs ?? 50;
  const deadline = input.deadline.getTime();
  const timeline: Partial<RetirementTimeline> = { startedAt: clock(), deadline, iterations: 0 };
  const fail = (message: string) => new RetirementError(message, { ...timeline, withinDeadline: false });

  await input.admin(`DISABLE ${input.database}`);
  timeline.fencedAt = clock();
  const applied = await input.apply();
  timeline.reloadedAt = clock();
  // RELOAD re-reads client_login_timeout from the INI, so shorten it only after the reload.
  await input.admin("SET client_login_timeout = 1");
  const reloadedSecond = Math.floor(timeline.reloadedAt / 1000) * 1000;
  let killed = 0;
  let preAuthWaited = 0;
  for (;;) {
    timeline.iterations = (timeline.iterations ?? 0) + 1;
    const clients = await input.admin("SHOW CLIENTS");
    const roleIds = clients
      .filter((row) => String(row.user) === input.role)
      .map((row) => String(row.id))
      .filter((id) => /^[1-9][0-9]{0,18}$/.test(id));
    for (const id of roleIds) {
      // A client may disconnect between SHOW CLIENTS and KILL_CLIENT; that is not a failure.
      await input.admin(`KILL_CLIENT ${id}`).catch(() => undefined);
      killed++;
    }
    // Pre-auth sockets that may hold a handshake from before the reload. Connect times have
    // second resolution, so a login in the reload's second counts as old; unknown times too.
    const logins = (await input.admin("SHOW SOCKETS")).filter((row) => String(row.state) === "cl_login");
    const old = logins.filter((row) => {
      const at = connectTime(row.connect_time);
      return at === null || at <= reloadedSecond;
    });
    preAuthWaited = Math.max(preAuthWaited, old.length);
    if (!roleIds.length && !old.length) {
      const remaining = (await input.admin("SHOW CLIENTS")).filter((row) => String(row.user) === input.role);
      if (!remaining.length) break;
    }
    if (clock() > deadline)
      throw fail(
        `Retirement of ${input.role} missed its deadline: ${roleIds.length} session(s) and ${old.length} pre-auth login(s) remain.`,
      );
    await sleep(pollMs);
  }
  timeline.drainedAt = clock();
  timeline.killedRoleClients = killed;
  timeline.preAuthWaited = preAuthWaited;
  await input.admin(
    `SET client_login_timeout = ${Math.max(1, Math.floor(input.loginTimeoutSeconds ?? PGBOUNCER_DEFAULTS.clientLoginTimeout))}`,
  );
  if (applied && applied.databaseMapped === false) {
    // The database left [databases] with this reload; there is nothing to re-enable.
    timeline.reopenSkipped = "database no longer mapped";
    await input.admin(`ENABLE ${input.database}`).catch(() => undefined);
  } else {
    await input.admin(`ENABLE ${input.database}`);
  }
  timeline.reopenedAt = clock();
  const result = {
    ...(timeline as RetirementTimeline),
    withinDeadline: timeline.drainedAt <= deadline,
  };
  if (!result.withinDeadline)
    throw new RetirementError(`Retirement of ${input.role} drained after its deadline.`, result);
  return result;
}

/**
 * Expiry is not a drain: TLS expiry only stops new handshakes. Given the role's sessions observed
 * after the deadline, refuse to call the retirement complete (the "expiry without drain" case).
 */
export function assertDrainedByDeadline(input: {
  role: string;
  deadline: Date;
  observedAt: Date;
  sessions: number;
}) {
  if (input.observedAt.getTime() < input.deadline.getTime())
    throw new Error("The drain deadline has not passed yet; nothing to assert.");
  if (input.sessions > 0)
    throw new Error(
      `${input.sessions} session(s) of ${input.role} are still open after the retirement deadline ${input.deadline.toISOString()}.`,
    );
  return true;
}
