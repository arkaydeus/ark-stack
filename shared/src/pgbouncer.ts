// Public PgBouncer configuration (docs/design/front-door.md §3.10.2, ticket FD-16).
//
// Every network client must present a certificate from one of Ark's private database-client CAs
// (`client_tls_sslmode = verify-full`, TLS 1.3 only) and then authenticate with SCRAM as its own
// login role. The console administrator is admitted only over the unix socket shared with the
// database worker; the ordered `pg_hba.conf` rules reject it on every network transport.
//
// The renderers here are pure. The database worker writes their output atomically and reloads
// PgBouncer through the admin socket (server/src/modules/pgbouncer.ts).

import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";

/** Console administrator. Never a Postgres role, never in `[users]`, never admitted over TCP. */
export const PGBOUNCER_ADMIN_USER = "ark_pgbouncer_admin";
/** In-container state directory (config, HBA, userlist and CA bundle), read-only in PgBouncer. */
export const PGBOUNCER_STATE_DIR = "/var/lib/ark/pgbouncer";
/** In-container admin socket directory, shared only by pgbouncer-public and database-worker. */
export const PGBOUNCER_SOCKET_DIR = "/var/run/pgbouncer";
export const PGBOUNCER_PORT = 5432;
export const PGBOUNCER_FILES = {
  config: "pgbouncer.ini",
  hba: "pg_hba.conf",
  userlist: "userlist.txt",
  caBundle: "client-ca-bundle.pem",
} as const;
/** A retiring generation stays trusted until its certificate's not_after plus this grace (§3.10.4). */
export const RETIREMENT_GRACE_MS = 5_000;

/** §3.10.2 defaults. All are settable per platform through `settings`. */
export const PGBOUNCER_DEFAULTS = {
  poolMode: "transaction" as "transaction" | "session",
  maxPreparedStatements: 200,
  maxClientConn: 2000,
  defaultPoolSize: 10,
  clientLoginTimeout: 10,
  queryWaitTimeout: 30,
  idleTransactionTimeout: 60,
  clientIdleTimeout: 900,
  serverIdleTimeout: 60,
  serverLifetime: 3600,
  poolSize: 10,
  maxDbConnections: 30,
  maxDbClientConnections: 500,
  maxUserClientConnections: 300,
  previewMaxUserClientConnections: 100,
};
export type PgbouncerSettings = typeof PGBOUNCER_DEFAULTS;

export type PgbouncerDatabase = {
  database: string;
  host: string;
  poolSize?: number;
  maxDbConnections?: number;
  maxDbClientConnections?: number;
};

export type PgbouncerUser = {
  name: string;
  poolMode?: "transaction" | "session";
  /** Server connections for this role: its Postgres CONNECTION LIMIT. */
  maxUserConnections: number;
  maxUserClientConnections: number;
};

const IDENTIFIER = /^[a-z_][a-z0-9_]{0,62}$/;
const HOST = /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;
const PRIVILEGED_ROLE = /_(owner|migration|backup|monitor)$/;

function identifier(value: string, what: string) {
  if (!IDENTIFIER.test(value)) throw new Error(`Invalid PgBouncer ${what}: ${JSON.stringify(value)}`);
  return value;
}

function count(value: number, what: string) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Invalid PgBouncer ${what}: ${value}`);
  return value;
}

function path(value: string, what: string) {
  // INI values cannot carry trailing comments, quotes or line breaks.
  if (!/^\/[A-Za-z0-9._/-]+$/.test(value)) throw new Error(`Invalid PgBouncer ${what}: ${value}`);
  return value;
}

/**
 * Render the complete §3.10.2 `pgbouncer.ini`. Comments are standalone lines only: PgBouncer
 * does not allow trailing comments in values.
 */
export function pgbouncerConfig(input: {
  mappings: PgbouncerDatabase[];
  users?: PgbouncerUser[];
  listenPort?: number;
  certificateDir?: string;
  stateDir?: string;
  socketDir?: string;
  settings?: Partial<PgbouncerSettings>;
}) {
  const s = { ...PGBOUNCER_DEFAULTS, ...input.settings };
  const stateDir = path(input.stateDir ?? PGBOUNCER_STATE_DIR, "state directory");
  const socketDir = path(input.socketDir ?? PGBOUNCER_SOCKET_DIR, "socket directory");
  const certificateDir = path(input.certificateDir ?? "/var/lib/ark/certs/database", "certificate directory");
  const databases = input.mappings.map((item) => {
    if (!HOST.test(item.host)) throw new Error(`Invalid PgBouncer database host: ${item.host}`);
    const name = identifier(item.database, "database name");
    return `${name} = host=${item.host} dbname=${name} pool_size=${count(item.poolSize ?? s.poolSize, "pool_size")} max_db_connections=${count(item.maxDbConnections ?? s.maxDbConnections, "max_db_connections")} max_db_client_connections=${count(item.maxDbClientConnections ?? s.maxDbClientConnections, "max_db_client_connections")}`;
  });
  const users = (input.users ?? []).map((user) => {
    const name = identifier(user.name, "user name");
    if (name === PGBOUNCER_ADMIN_USER || PRIVILEGED_ROLE.test(name)) {
      throw new Error(`${name} must never be admitted as a public PgBouncer user.`);
    }
    return `${name} = pool_mode=${user.poolMode ?? s.poolMode} max_user_connections=${count(user.maxUserConnections, "max_user_connections")} max_user_client_connections=${count(user.maxUserClientConnections, "max_user_client_connections")}`;
  });
  return `[databases]
; per admitted public database
${databases.map((line) => `${line}\n`).join("")}
[users]
; per active database client login role; max_user_connections from its connection limit
${users.map((line) => `${line}\n`).join("")}
[pgbouncer]
listen_addr = 0.0.0.0
listen_port = ${count(input.listenPort ?? PGBOUNCER_PORT, "listen_port")}
; shared only with database-worker
unix_socket_dir = ${socketDir}
auth_type = hba
auth_hba_file = ${stateDir}/${PGBOUNCER_FILES.hba}
auth_file = ${stateDir}/${PGBOUNCER_FILES.userlist}
; transport restriction is enforced in pg_hba.conf below, not by admin_users
admin_users = ${PGBOUNCER_ADMIN_USER}
pool_mode = ${s.poolMode}
max_prepared_statements = ${count(s.maxPreparedStatements, "max_prepared_statements")}
ignore_startup_parameters = extra_float_digits

client_tls_sslmode = verify-full
client_tls_ca_file = ${stateDir}/${PGBOUNCER_FILES.caBundle}
client_tls_cert_file = ${certificateDir}/fullchain.pem
client_tls_key_file = ${certificateDir}/privkey.pem
client_tls_protocols = tlsv1.3
; internal database-management bridge, unchanged
server_tls_sslmode = disable

max_client_conn = ${count(s.maxClientConn, "max_client_conn")}
default_pool_size = ${count(s.defaultPoolSize, "default_pool_size")}
client_login_timeout = ${count(s.clientLoginTimeout, "client_login_timeout")}
query_wait_timeout = ${count(s.queryWaitTimeout, "query_wait_timeout")}
idle_transaction_timeout = ${count(s.idleTransactionTimeout, "idle_transaction_timeout")}
client_idle_timeout = ${count(s.clientIdleTimeout, "client_idle_timeout")}
server_idle_timeout = ${count(s.serverIdleTimeout, "server_idle_timeout")}
server_lifetime = ${count(s.serverLifetime, "server_lifetime")}
`;
}

/**
 * The complete, ordered §3.10.2 `pg_hba.conf`. First match wins: the admin identity is accepted
 * only on the local socket for the console database, and rejected on every host transport even
 * with a valid application certificate. Applications use TLS (with the global verify-full client
 * certificate check) plus SCRAM; everything else is rejected.
 */
export function pgbouncerHba() {
  return `local   pgbouncer  ${PGBOUNCER_ADMIN_USER}                     scram-sha-256
local   all        all                                     reject
host    all        ${PGBOUNCER_ADMIN_USER}  0.0.0.0/0           reject
host    all        ${PGBOUNCER_ADMIN_USER}  ::/0                reject
hostssl all        all                  0.0.0.0/0           scram-sha-256
hostssl all        all                  ::/0                scram-sha-256
host    all        all                  0.0.0.0/0           reject
host    all        all                  ::/0                reject
`;
}

function quoted(value: string) {
  if (/[\r\n\0]/.test(value)) throw new Error("PgBouncer userlist values cannot contain line breaks.");
  return `"${value.replaceAll('"', '""')}"`;
}

/**
 * `userlist.txt`: one line per admitted login role, plus the console administrator's SCRAM
 * verifier. Privileged roles and anything named like the administrator are never admitted.
 */
export function pgbouncerUserlist(
  users: Array<{ name: string; password: string }>,
  options: { adminVerifier?: string } = {},
) {
  const lines = users
    .filter((user) => !PRIVILEGED_ROLE.test(user.name) && user.name !== PGBOUNCER_ADMIN_USER)
    .map((user) => `${quoted(user.name)} ${quoted(user.password)}`);
  if (options.adminVerifier) {
    if (!options.adminVerifier.startsWith("SCRAM-SHA-256$")) {
      throw new Error("The PgBouncer administrator must be stored as a SCRAM-SHA-256 verifier.");
    }
    lines.push(`${quoted(PGBOUNCER_ADMIN_USER)} ${quoted(options.adminVerifier)}`);
  }
  return lines.join("\n");
}

/**
 * A PostgreSQL-format SCRAM-SHA-256 verifier. The administrator's plaintext password never
 * reaches PgBouncer's files; only the database worker holds it.
 */
export function scramSha256Verifier(password: string, options: { salt?: Buffer; iterations?: number } = {}) {
  const salt = options.salt ?? randomBytes(16);
  const iterations = options.iterations ?? 4096;
  const salted = pbkdf2Sync(password.normalize("NFKC"), salt, iterations, 32, "sha256");
  const clientKey = createHmac("sha256", salted).update("Client Key").digest();
  const storedKey = createHash("sha256").update(clientKey).digest();
  const serverKey = createHmac("sha256", salted).update("Server Key").digest();
  return `SCRAM-SHA-256$${iterations}:${salt.toString("base64")}$${storedKey.toString("base64")}:${serverKey.toString("base64")}`;
}

/** True when `verifier` is a SCRAM-SHA-256 verifier for `password`. */
export function scramVerifierMatches(password: string, verifier: string) {
  const match = /^SCRAM-SHA-256\$(\d+):([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$/.exec(
    verifier,
  );
  if (!match) return false;
  const expected = scramSha256Verifier(password, {
    iterations: Number(match[1]),
    salt: Buffer.from(match[2]!, "base64"),
  });
  return expected === verifier;
}

// ---- Client CA bundle (§3.10.3, §3.10.4) -------------------------------------------------------

export type BundleClient = { id: string; status: string; caId: string };
export type BundleCertificate = {
  id: string;
  caId: string;
  status: string;
  rolloverState: string;
  supersededBy: string | null;
  notAfter: Date;
};
export type BundleCa = { id: string; purpose: string; status: string; certPem: string; notAfter: Date };
export type BundleRole = "current" | "pending" | "retiring";
export type BundleGeneration = { caId: string; clientIds: string[]; role: BundleRole; certPem: string };
export type BundleExclusion = { caId: string; reason: string };

const ROLE_RANK: Record<BundleRole, number> = { current: 0, pending: 1, retiring: 2 };

function certificateRole(state: string): BundleRole | null {
  if (state === "current" || state === "delivered") return "current";
  if (state === "pending") return "pending";
  if (state === "superseded") return "retiring";
  return null;
}

/** Every certificate linked to a client through its CA pointer and the superseded_by chain. */
function linkedCertificates(client: BundleClient, certificates: BundleCertificate[]) {
  const byId = new Map(certificates.map((item) => [item.id, item]));
  const predecessors = new Map<string, BundleCertificate[]>();
  for (const item of certificates) {
    if (!item.supersededBy) continue;
    predecessors.set(item.supersededBy, [...(predecessors.get(item.supersededBy) ?? []), item]);
  }
  const seen = new Map<string, BundleCertificate>();
  const queue = certificates.filter((item) => item.caId === client.caId);
  while (queue.length) {
    const item = queue.pop()!;
    if (seen.has(item.id)) continue;
    seen.set(item.id, item);
    const successor = item.supersededBy ? byId.get(item.supersededBy) : undefined;
    if (successor) queue.push(successor);
    queue.push(...(predecessors.get(item.id) ?? []));
  }
  return [...seen.values()];
}

/**
 * Select the generation CAs PgBouncer trusts: for each **active** client, the current, linked
 * pending and retiring generations, found through its certificates rather than only the
 * `database_clients.ca_id` pointer. A generation is trusted only while it has an issued,
 * unrevoked certificate before its retirement deadline (`not_after + 5 s`), and its CA is an
 * unrevoked, unexpired `db-client` CA. A CA linked to any revoked client is never trusted, even
 * when an active client shares it (fail closed). An empty result means nobody is admitted.
 */
export function selectClientCaBundle(input: {
  clients: BundleClient[];
  certificates: BundleCertificate[];
  cas: BundleCa[];
  now: Date;
  retirementGraceMs?: number;
}) {
  const grace = input.retirementGraceMs ?? RETIREMENT_GRACE_MS;
  const now = input.now.getTime();
  const cas = new Map(input.cas.map((item) => [item.id, item]));
  const excluded = new Map<string, string>();
  const revokedCas = new Set<string>();
  for (const client of input.clients.filter((item) => item.status !== "active")) {
    revokedCas.add(client.caId);
    for (const item of linkedCertificates(client, input.certificates)) revokedCas.add(item.caId);
  }
  const generations = new Map<string, BundleGeneration>();
  const admitted = new Set<string>();
  for (const client of input.clients.filter((item) => item.status === "active")) {
    const roles = new Map<string, BundleRole>();
    for (const item of linkedCertificates(client, input.certificates)) {
      const role = certificateRole(item.rolloverState);
      if (item.status !== "issued") {
        excluded.set(item.caId, excluded.get(item.caId) ?? `certificate ${item.status}`);
        continue;
      }
      if (item.notAfter.getTime() + grace <= now) {
        excluded.set(item.caId, excluded.get(item.caId) ?? "past retirement deadline");
        continue;
      }
      if (!role) continue;
      const held = roles.get(item.caId);
      if (!held || ROLE_RANK[role] < ROLE_RANK[held]) roles.set(item.caId, role);
    }
    for (const [caId, role] of roles) {
      const ca = cas.get(caId);
      const reason = !ca
        ? "CA missing"
        : ca.purpose !== "db-client"
          ? `CA purpose ${ca.purpose}`
          : ca.status === "revoked"
            ? "CA revoked"
            : ca.notAfter.getTime() <= now
              ? "CA expired"
              : revokedCas.has(caId)
                ? "CA linked to a revoked client"
                : null;
      if (reason) {
        excluded.set(caId, reason);
        continue;
      }
      excluded.delete(caId);
      admitted.add(client.id);
      const held = generations.get(caId);
      if (held) {
        if (!held.clientIds.includes(client.id)) held.clientIds.push(client.id);
        if (ROLE_RANK[role] < ROLE_RANK[held.role]) held.role = role;
      } else {
        generations.set(caId, { caId, clientIds: [client.id], role, certPem: ca!.certPem });
      }
    }
  }
  for (const caId of generations.keys()) excluded.delete(caId);
  const ordered = [...generations.values()].toSorted(
    (a, b) =>
      a.clientIds[0]!.localeCompare(b.clientIds[0]!) ||
      ROLE_RANK[a.role] - ROLE_RANK[b.role] ||
      a.caId.localeCompare(b.caId),
  );
  return {
    generations: ordered,
    admittedClientIds: [...admitted].toSorted(),
    excluded: [...excluded].map(([caId, reason]) => ({ caId, reason })) as BundleExclusion[],
  };
}

/** Concatenate the trusted generation CAs. Refuses an empty bundle: it must never mean "anyone". */
export function renderClientCaBundle(generations: Array<{ certPem: string }>) {
  const pems = generations.map((item) => item.certPem.trim()).filter(Boolean);
  if (!pems.length) throw new Error("Refusing to render an empty PgBouncer client CA bundle.");
  for (const pem of pems) {
    if (!/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----$/.test(pem)) {
      throw new Error("The PgBouncer client CA bundle accepts PEM certificates only.");
    }
  }
  return `${pems.join("\n")}\n`;
}

export function authQuerySql() {
  return `
CREATE SCHEMA IF NOT EXISTS pgbouncer;
REVOKE ALL ON SCHEMA pgbouncer FROM PUBLIC;
CREATE OR REPLACE FUNCTION pgbouncer.user_lookup(IN i_username text, OUT uname text, OUT phash text)
RETURNS record
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pgbouncer, pg_temp
AS $$
BEGIN
  SELECT usename, passwd INTO uname, phash FROM pg_catalog.pg_shadow WHERE usename = i_username;
END;
$$;
REVOKE ALL ON FUNCTION pgbouncer.user_lookup(text) FROM PUBLIC;
`;
}
