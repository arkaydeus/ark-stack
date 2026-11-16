// Starts the real `app-postgres` and `pgbouncer-public` Compose services in a disposable project
// and tests the FD-16 public PgBouncer (docs/design/front-door.md §3.10.2, §3.14, §7 V-8):
//
// - the installer's closed bootstrap (no client admitted: deny-all CA bundle, nothing mapped);
// - the exact INI, HBA, userlist and CA bundle the database worker renders (planPgbouncer), loaded
//   with RELOAD over the admin unix socket by a database-worker stand-in container;
// - the V-8 mTLS matrix, the admin identity's transport restriction, max_user_client_connections,
//   postgres.js prepared statements in transaction mode, and a server certificate swap whose new
//   fingerprint is verified through the published port with `openssl s_client`;
// - a simulated reload failure that retries and never reports success;
// - FD-17 database clients: Ark's §3.12 node-postgres module (real `pg` + `@vercel/functions`)
//   connects with a client's revealed env values, a preview client's role is denied INSERT, UPDATE
//   and DELETE while production's can write, and revoking client B (reduced CA bundle, rotated
//   NOLOGIN password, RELOAD, KILL_CLIENT) closes B's live session and new handshakes with
//   `unknown ca` while client A's sessions, password and new connections are unaffected.
//
// The Compose file's relative bind mounts (`../../tmp/...`) are redirected into a temporary
// directory with `--project-directory`, so the repository's own `tmp/` state is never touched.
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, rename, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer as createTlsServer } from "node:tls";

import {
  DB_CLIENT_CONNECTION_LIMITS,
  NODE_POSTGRES_SNIPPET,
  PGBOUNCER_FILES,
  buildProvisionPlan,
  clientGroupRole,
  clientRoleName,
  clientRoleSql,
  databaseClientGuide,
  defaultClientRoleKind,
  pgbouncerHba,
  renderClientCaBundle,
  revokedClientRoleSql,
  terminateRoleSessionsSql,
} from "@ark-stack/shared";
import { assertTls12Rejected } from "./pgbouncer-smoke-checks.ts";

import { planPgbouncer, renderPgbouncerFiles, writePgbouncerFiles } from "../server/src/modules/pgbouncer.ts";
import { seedPgbouncerBootstrap } from "./pgbouncer-bootstrap.ts";

// The FD-13 CA module issues the client certificates. Its pure functions need no database, but
// the module opens a lazy pool at import; give it an address it never connects to.
process.env.DATABASE_URL ??= "postgres://unused:unused@127.0.0.1:9/unused";
const pki = await import("../server/src/modules/pki.ts");

// macOS's system LibreSSL lacks PostgreSQL STARTTLS. Prefer an installed OpenSSL, and
// fail explicitly rather than treating CLI usage errors as successful security checks.
const openssl = [
  process.env.ARK_OPENSSL_BIN,
  Bun.which("openssl"),
  "/opt/homebrew/opt/openssl@3/bin/openssl",
  "/usr/local/opt/openssl@3/bin/openssl",
]
  .filter((candidate): candidate is string => Boolean(candidate))
  .find((candidate) => {
    const version = Bun.spawnSync([candidate, "version"]);
    return version.exitCode === 0 && /^OpenSSL (?:[3-9]\.|1\.1\.1)/.test(version.stdout.toString());
  });
if (!openssl)
  throw new Error(
    "Install OpenSSL 1.1.1 or newer with PostgreSQL STARTTLS support (or set ARK_OPENSSL_BIN).",
  );

const root = resolve(import.meta.dir, "..");
const composeFile = join(root, "infra", "platform", "docker-compose.yml");
const templates = {
  ini: join(root, "infra", "database", "pgbouncer.ini"),
  hba: join(root, "infra", "database", "pg_hba.conf"),
};
const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const project = `ark-pgbouncer-smoke-${suffix}`;
const work = await mkdtemp(join(tmpdir(), `ark-pgbouncer-${suffix}-`));
// `../../tmp/pgbouncer` in the Compose file resolves against this directory.
const projectDir = join(work, "infra", "platform");
const pgbouncerDir = join(work, "tmp", "pgbouncer");
const certDir = join(work, "tmp", "certs", "database");
const clientDir = join(work, "client");
const probeDir = join(work, "probe");
const serverCa = join(clientDir, "server-ca.pem");
// Ark's containers and the installer's chown use uid/gid 1000 (scripts/install.ts).
const arkUid = "1000:1000";
const hostUid = `${process.getuid?.() ?? 0}:${process.getgid?.() ?? 0}`;
const database = "ark_smoke";
const appRole = "ark_smoke_shop_production";
const limitedRole = "ark_smoke_shop_preview";
const ownerRole = "ark_smoke_owner";
const secret = () => randomBytes(18).toString("base64url");
const appPassword = secret();
const limitedPassword = secret();
const ownerPassword = secret();
const adminPassword = secret();
const clusterPassword = secret();
const limitedClientConnections = 2;

const env: Record<string, string> = { ...(process.env as Record<string, string>) };
// The Compose file interpolates every service, so each installer-generated value needs a
// placeholder even though only two services start.
for (const name of [
  "ARK_AGENT_TOKEN",
  "ARK_API_DB_PASSWORD",
  "ARK_BACKUP_WORKER_TOKEN",
  "ARK_CONTROL_DB_PASSWORD",
  "ARK_DATABASE_WORKER_TOKEN",
  "ARK_DOMAIN_WORKER_TOKEN",
  "ARK_INTERNAL_TOKEN",
  "ARK_MAIL_WORKER_TOKEN",
  "ARK_MAINTENANCE_TOKEN",
  "ARK_METRICS_TOKEN",
  "ARK_MFA_RECOVERY_TOKEN",
  "ARK_OFFHOST_HEARTBEAT_TOKEN",
  "ARK_ROOT_KEY",
  "ARK_SETUP_TOKEN",
  "BETTER_AUTH_SECRET",
  "BETTER_AUTH_TRUSTED_ORIGINS",
  "BETTER_AUTH_URL",
  "STALWART_ADMIN_PASSWORD",
]) {
  env[name] = `smoke-${secret()}`;
}
env.ARK_APP_DB_PASSWORD = clusterPassword;
env.ARK_PGBOUNCER_ADMIN_PASSWORD = adminPassword;
delete env.COMPOSE_FILE;
delete env.COMPOSE_PROJECT_NAME;

let pgbouncerImage = "";
let clientImage = "";
let bunImage = "";
const compose = ["docker", "compose", "-f", composeFile, "--project-directory", projectDir, "-p", project];
const socketVolume = `${project}_ark_pgbouncer_socket`;
const network = `${project}_database-management`;
// Default to the real ingress target. A shared developer host can request an ephemeral
// loopback port with ARK_PGBOUNCER_SMOKE_PORT=0, without changing production Compose.
const requestedPort = process.env.ARK_PGBOUNCER_SMOKE_PORT ?? "15432";
if (!/^\d+$/.test(requestedPort) || Number(requestedPort) > 65535) {
  throw new Error("ARK_PGBOUNCER_SMOKE_PORT must be 0 (ephemeral) or a port from 1 to 65535.");
}
let loopbackPort = requestedPort;
const results: Array<[string, string]> = [];

async function run(
  command: string[],
  options: { allowFailure?: boolean; env?: Record<string, string>; stdin?: string } = {},
) {
  const child = Bun.spawn(command, {
    env: { ...env, ...options.env },
    stdin: options.stdin === undefined ? "ignore" : Buffer.from(options.stdin),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (status !== 0 && !options.allowFailure) {
    throw new Error(`${command.slice(0, 4).join(" ")} … failed (${status}):\n${stderr || stdout}`);
  }
  return { status, stdout: stdout.trim(), stderr: stderr.trim() };
}

function log(line: string) {
  console.log(line);
}

function lastLine(text: string) {
  return text.split("\n").findLast((line) => line.length > 0) ?? "";
}

/** Record one acceptance check for the summary table printed at the end. */
function record(check: string, outcome: string) {
  results.push([check, outcome]);
  log(`✓ ${check}: ${outcome}`);
}

async function service(name: string) {
  const { stdout } = await run([...compose, "ps", "-q", name]);
  if (!stdout) throw new Error(`${name} has no container`);
  return stdout.split("\n")[0]!;
}

async function inspect(container: string, format: string) {
  return (await run(["docker", "inspect", "--format", format, container])).stdout;
}

function settings(text: string) {
  return new Map(
    text
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith(";") && !line.startsWith("#") && !line.startsWith("["))
      .map((line) => {
        const eq = line.indexOf("=");
        return [line.slice(0, eq).trim(), line.slice(eq + 1).trim()] as const;
      }),
  );
}

// Every [pgbouncer] setting in the checked-in template must survive into the generated config,
// so the smoke test exercises the same listener, auth, TLS and pooling settings production uses.
function assertTemplateCoverage(generated: string, source: string) {
  const actual = settings(generated);
  for (const [key, value] of settings(source)) {
    if (actual.get(key) !== value) {
      throw new Error(`Generated pgbouncer.ini drifts from the template: ${key} = ${actual.get(key)}`);
    }
  }
}

async function chownState(owner: string) {
  await run([
    "docker",
    "run",
    "--rm",
    "--user",
    "0:0",
    "--entrypoint",
    "chown",
    "--volume",
    `${join(work, "tmp")}:/smoke`,
    "--volume",
    `${probeDir}:/probe`,
    pgbouncerImage,
    "-R",
    owner,
    "/smoke",
    "/probe",
  ]);
}

/** Write files as the host user, then hand the tree back to uid 1000 as the installer does. */
async function asHost<T>(action: () => Promise<T>) {
  await chownState(hostUid);
  try {
    return await action();
  } finally {
    await chownState(arkUid);
  }
}

async function checkLoopbackPublication(bouncer: string) {
  const published = await run(["docker", "port", bouncer, "5432/tcp"]);
  const binding = /^127\.0\.0\.1:(\d+)$/.exec(published.stdout);
  if (!binding || (requestedPort !== "0" && binding[1] !== requestedPort)) {
    throw new Error(`Expected loopback-only publication, got: ${published.stdout}`);
  }
  loopbackPort = binding[1]!;
}

type Credentials = { cert: string; key: string };

/** psql from the host through the published loopback port, verifying the server certificate. */
async function hostPsql(input: {
  role: string;
  password: string;
  dbname?: string;
  sql: string;
  client?: Credentials;
  sslmode?: string;
  extra?: string;
}) {
  const client = Bun.which("psql");
  if (!client) throw new Error("The loopback smoke test requires a host psql client (postgresql-client).");
  const certificate = input.client ? ` sslcert=${input.client.cert} sslkey=${input.client.key}` : "";
  return run(
    [
      client,
      `host=127.0.0.1 port=${loopbackPort} dbname=${input.dbname ?? database} user=${input.role} sslmode=${input.sslmode ?? "verify-full"} sslrootcert=${serverCa} connect_timeout=10${certificate}${input.extra ? ` ${input.extra}` : ""}`,
      "--no-psqlrc",
      "--tuples-only",
      "--set",
      "ON_ERROR_STOP=1",
      "--command",
      input.sql,
    ],
    {
      allowFailure: true,
      env: { PGPASSWORD: input.password, PGSSLCERT: "/nonexistent", PGSSLKEY: "/nonexistent" },
    },
  );
}

/** psql inside a container that shares only the admin socket volume, as uid 1000. */
async function socketPsql(role: string, password: string, dbname: string, sql: string) {
  return run(
    [
      "docker",
      "run",
      "--rm",
      "--user",
      arkUid,
      "--network",
      "none",
      "--volume",
      `${socketVolume}:/var/run/pgbouncer`,
      "--env",
      `PGPASSWORD=${password}`,
      "--entrypoint",
      "psql",
      pgbouncerImage,
      `host=/var/run/pgbouncer port=5432 dbname=${dbname} user=${role} connect_timeout=10`,
      "--no-psqlrc",
      "--tuples-only",
      "--command",
      sql,
    ],
    { allowFailure: true },
  );
}

/** The database-worker stand-in (scripts/pgbouncer-worker-probe.ts), bundled and containerised. */
async function probe(args: string[], extraEnv: Record<string, string> = {}) {
  const command = [
    "docker",
    "run",
    "--rm",
    "--user",
    arkUid,
    "--read-only",
    "--cap-drop",
    "ALL",
    "--network",
    network,
    "--volume",
    `${socketVolume}:/var/run/pgbouncer`,
    "--volume",
    `${probeDir}:/probe:ro`,
    "--env",
    "ARK_PGBOUNCER_ADMIN_PASSWORD",
    ...Object.keys(extraEnv).flatMap((name) => ["--env", name]),
    bunImage,
    "bun",
    "/probe/pgbouncer-worker-probe.js",
    ...args,
  ];
  const result = await run(command, { allowFailure: true, env: extraEnv });
  const line = result.stdout.split("\n").findLast((item) => item.startsWith("{"));
  if (!line) throw new Error(`Probe printed no result:\n${result.stderr || result.stdout}`);
  return { status: result.status, ...(JSON.parse(line) as Record<string, unknown>) } as {
    status: number;
    ok: boolean;
    attempts?: number;
    fingerprint?: string;
    failures?: string[];
    error?: string;
    rows?: Array<Record<string, unknown>>;
    ids?: string[];
    killed?: number;
    remaining?: number;
    environment: { dockerCli: string | null; dockerSocket: boolean; uid: number };
  };
}

/** The leaf fingerprint served on the published port, read with `openssl s_client`. */
async function opensslFingerprint() {
  const handshake = await run(
    [
      openssl,
      "s_client",
      "-starttls",
      "postgres",
      "-connect",
      `127.0.0.1:${loopbackPort}`,
      "-tls1_3",
      "-showcerts",
    ],
    { allowFailure: true, stdin: "" },
  );
  const leaf = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(handshake.stdout)?.[0];
  if (!leaf) throw new Error(`openssl s_client returned no certificate:\n${handshake.stderr}`);
  const digest = await run([openssl, "x509", "-noout", "-fingerprint", "-sha256"], { stdin: `${leaf}\n` });
  return digest.stdout.split("=")[1]!.trim().replace(/:/g, "").toLowerCase();
}

async function fileFingerprint(path: string) {
  const digest = await run([openssl, "x509", "-in", path, "-noout", "-fingerprint", "-sha256"]);
  return digest.stdout.split("=")[1]!.trim().replace(/:/g, "").toLowerCase();
}

/** A self-signed server certificate for the Compose service name and the loopback address. */
async function serverCertificate(directory: string) {
  await run([
    openssl,
    "req",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-sha256",
    "-nodes",
    "-days",
    "2",
    "-subj",
    "/CN=pgbouncer-public",
    "-addext",
    "subjectAltName=DNS:pgbouncer-public,DNS:localhost,IP:127.0.0.1",
    "-keyout",
    join(directory, "privkey.pem"),
    "-out",
    join(directory, "fullchain.pem"),
  ]);
}

/** A client certificate issued by the FD-13 CA module; the test key lives in the work dir. */
async function issueClient(ca: ReturnType<typeof pki.createCaMaterial>, cn: string, name: string) {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const issued = pki.signClientCertificate({
    ca: { certPem: ca.certPem, privateKey: ca.privateKey },
    subjectCn: cn,
    publicKey: pair.publicKey,
  });
  const cert = join(clientDir, `${name}.crt`);
  const key = join(clientDir, `${name}.key`);
  await Bun.write(cert, issued.certPem);
  await Bun.write(key, pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string);
  await chmod(key, 0o600);
  return {
    cert,
    key,
    certPem: issued.certPem,
    keyPem: pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    notAfter: issued.notAfter,
  };
}

function expectRejected(result: { status: number; stderr: string }, pattern: RegExp, check: string) {
  if (result.status === 0 || !pattern.test(result.stderr)) {
    throw new Error(
      `${check}: expected rejection matching ${pattern}, got (${result.status}) ${result.stderr}`,
    );
  }
  record(check, `rejected — ${lastLine(result.stderr)}`);
}

try {
  await mkdir(projectDir, { recursive: true });
  if (requestedPort !== "15432") {
    const override = join(work, "smoke-ports.yml");
    const binding = `127.0.0.1:${requestedPort === "0" ? "" : requestedPort}:5432`;
    await Bun.write(override, `services:\n  pgbouncer-public:\n    ports: !override ["${binding}"]\n`);
    compose.push("-f", override);
  }
  await mkdir(pgbouncerDir, { recursive: true });
  await mkdir(certDir, { recursive: true });
  await mkdir(clientDir, { recursive: true });
  await mkdir(probeDir, { recursive: true });

  await serverCertificate(certDir);
  await Bun.write(serverCa, await Bun.file(join(certDir, "fullchain.pem")).text());

  // Two client generations admitted (two CAs in one bundle, as in V-8) and one rogue CA.
  const caShop = pki.createCaMaterial({
    id: "pca_smoke_shop",
    purpose: "db-client",
    name: "smoke/production",
  });
  const caPreview = pki.createCaMaterial({
    id: "pca_smoke_preview",
    purpose: "db-client",
    name: "smoke/preview",
  });
  const caRogue = pki.createCaMaterial({ id: "pca_smoke_rogue", purpose: "db-client", name: "rogue" });
  const shop = await issueClient(caShop, appRole, "shop");
  const preview = await issueClient(caPreview, limitedRole, "preview");
  const rogue = await issueClient(caRogue, appRole, "rogue");

  const built = await Bun.build({
    entrypoints: [
      join(import.meta.dir, "pgbouncer-worker-probe.ts"),
      join(import.meta.dir, "pgbouncer-client-probe.ts"),
    ],
    target: "bun",
    outdir: probeDir,
  });
  if (!built.success) throw new Error(`Could not bundle the worker probe:\n${built.logs.join("\n")}`);

  await Bun.write(
    join(probeDir, "client.json"),
    JSON.stringify({
      shop,
      preview,
      appRole,
      limitedRole,
      appPassword,
      limitedPassword,
      database,
      limitedClientConnections,
      serverCa: await Bun.file(serverCa).text(),
    }),
  );
  await chmod(join(probeDir, "client.json"), 0o600);

  // The installer's closed bootstrap: no mapping, no client, and a deny-all CA bundle.
  await seedPgbouncerBootstrap(pgbouncerDir, { adminPassword });
  const bootstrapBundle = await Bun.file(join(pgbouncerDir, PGBOUNCER_FILES.caBundle)).text();
  await chmod(join(certDir, "privkey.pem"), 0o600);

  const resolved = JSON.parse((await run([...compose, "config", "--format", "json"])).stdout) as {
    services: Record<string, { image: string; volumes?: Array<{ source?: string; target: string }> }>;
  };
  const appImage = resolved.services["app-postgres"]!.image;
  pgbouncerImage = resolved.services["pgbouncer-public"]!.image;
  clientImage = appImage;
  const runtimeBase = /^FROM (oven\/bun:[^\s]+@sha256:[a-f0-9]{64}) AS runtime$/m.exec(
    await Bun.file(join(root, "Dockerfile")).text(),
  );
  if (!runtimeBase) throw new Error("Could not read the pinned Bun runtime image from the Dockerfile.");
  bunImage = runtimeBase[1]!;
  for (const name of ["pgbouncer-public", "database-worker"]) {
    const mount = resolved.services[name]!.volumes?.find((item) => item.target === "/var/run/pgbouncer");
    if (mount?.source !== "ark_pgbouncer_socket")
      throw new Error(`${name} does not mount the admin socket volume.`);
  }
  log(`pgbouncer-public image: ${pgbouncerImage}\nworker stand-in image: ${bunImage}`);
  // Match production ownership: the installer chowns these trees to uid 1000 and Ark writes
  // the files with mode 0600. PgBouncer runs with every capability dropped.
  await chownState(arkUid);

  log("Starting app-postgres…");
  await run([...compose, "up", "--detach", "--wait", "--wait-timeout", "120", "app-postgres"]);
  const appContainer = await service("app-postgres");
  await run([
    "docker",
    "exec",
    appContainer,
    "psql",
    "--username",
    "ark_cluster_admin",
    "--dbname",
    "postgres",
    "--set",
    "ON_ERROR_STOP=1",
    "--command",
    `CREATE ROLE ${appRole} LOGIN PASSWORD '${appPassword}'`,
    "--command",
    `CREATE ROLE ${limitedRole} LOGIN PASSWORD '${limitedPassword}'`,
    "--command",
    `CREATE ROLE ${ownerRole} LOGIN PASSWORD '${ownerPassword}'`,
    "--command",
    `CREATE DATABASE ${database} OWNER ${ownerRole}`,
    "--command",
    `REVOKE ALL ON DATABASE ${database} FROM PUBLIC`,
    "--command",
    `GRANT CONNECT ON DATABASE ${database} TO ${appRole}, ${limitedRole}`,
  ]);
  const verifier = await run([
    "docker",
    "exec",
    appContainer,
    "psql",
    "--username",
    "ark_cluster_admin",
    "--dbname",
    "postgres",
    "--tuples-only",
    "--no-align",
    "--command",
    `SELECT left(rolpassword, 14) FROM pg_authid WHERE rolname = '${appRole}'`,
  ]);
  if (verifier.stdout !== "SCRAM-SHA-256$") throw new Error(`Client role is not SCRAM: ${verifier.stdout}`);
  log(`app-postgres (${clientImage}) ready; ${appRole} stores a SCRAM-SHA-256 verifier.`);

  log("Starting pgbouncer-public…");
  await run([...compose, "up", "--detach", "--wait", "--wait-timeout", "120", "pgbouncer-public"]);
  const bouncer = await service("pgbouncer-public");
  log(
    `pgbouncer-public: ${await inspect(bouncer, "status={{.State.Status}} health={{.State.Health.Status}} user={{.Config.User}} entrypoint={{json .Config.Entrypoint}} cmd={{json .Config.Cmd}} capdrop={{json .HostConfig.CapDrop}} secopt={{json .HostConfig.SecurityOpt}}")}`,
  );
  const startup = await run(["docker", "logs", bouncer]);
  const banner = `${startup.stdout}\n${startup.stderr}`
    .split("\n")
    .find((line) => line.includes("process up"));
  if (!banner?.includes("PgBouncer 1.26.1")) throw new Error(`Unexpected PgBouncer banner: ${banner}`);
  log(`log: ${banner.trim()}`);

  const socket = await run([
    "docker",
    "exec",
    bouncer,
    "stat",
    "-c",
    "%F %u:%g %a",
    "/var/run/pgbouncer/.s.PGSQL.5432",
  ]);
  if (!socket.stdout.startsWith("socket ")) throw new Error(`Admin socket missing: ${socket.stdout}`);
  const socketDirMode = await run([
    "docker",
    "exec",
    bouncer,
    "stat",
    "-c",
    "%u:%g %a",
    "/var/run/pgbouncer",
  ]);
  record(
    "admin socket at /var/run/pgbouncer/.s.PGSQL.5432",
    `${socket.stdout} (dir ${socketDirMode.stdout})`,
  );

  // ---- Closed bootstrap: nobody admitted, nothing routed, no empty bundle --------------------
  await checkLoopbackPublication(bouncer);
  if ((bootstrapBundle.match(/BEGIN CERTIFICATE/g) ?? []).length !== 1) {
    throw new Error("The bootstrap CA bundle must hold exactly the deny-all CA.");
  }
  expectRejected(
    await hostPsql({ role: appRole, password: appPassword, sql: "SELECT 1", client: shop }),
    /unknown ca/,
    "zero clients: a valid Ark client certificate is not accepted (deny-all bundle)",
  );
  expectRejected(
    await hostPsql({ role: appRole, password: appPassword, sql: "SELECT 1", sslmode: "disable" }),
    /SSL required/,
    "zero clients: plaintext",
  );

  // ---- Admit two clients through the worker's renderer, then RELOAD over the socket ----------
  const now = new Date();
  const smokeClients = [
    {
      id: "dbc_shop",
      databaseId: "mdb_smoke",
      environment: "production",
      status: "active",
      caId: "pca_smoke_shop",
      role: { name: appRole, connectionLimit: 20, password: appPassword },
    },
    {
      id: "dbc_preview",
      databaseId: "mdb_smoke",
      environment: "preview",
      status: "active",
      caId: "pca_smoke_preview",
      role: { name: limitedRole, connectionLimit: 5, password: limitedPassword },
    },
  ];
  const smokeCertificates = [
    {
      id: "ccert_shop",
      caId: "pca_smoke_shop",
      status: "issued",
      rolloverState: "current",
      supersededBy: null,
      notAfter: shop.notAfter,
    },
    {
      id: "ccert_preview",
      caId: "pca_smoke_preview",
      status: "issued",
      rolloverState: "current",
      supersededBy: null,
      notAfter: preview.notAfter,
    },
  ];
  const smokeCas = [caShop, caPreview].map((item, index) => ({
    id: index === 0 ? "pca_smoke_shop" : "pca_smoke_preview",
    purpose: "db-client",
    status: "active",
    certPem: item.certPem,
    notAfter: item.notAfter,
  }));
  const plan = planPgbouncer({
    databases: [{ id: "mdb_smoke", name: database, exposure: "public" }],
    clients: smokeClients,
    certificates: smokeCertificates,
    cas: smokeCas,
    now,
    host: "app-postgres",
    settings: { previewMaxUserClientConnections: limitedClientConnections },
  });
  if (!plan.routed || plan.generations.length !== 2) throw new Error("The plan did not admit both clients.");
  if (plan.caBundle !== renderClientCaBundle([{ certPem: caPreview.certPem }, { certPem: caShop.certPem }])) {
    throw new Error("The rendered CA bundle is not exactly the two admitted generations.");
  }
  const files = renderPgbouncerFiles({ plan, adminPassword, certificateDir: "/var/lib/ark/certs/database" });
  assertTemplateCoverage(files[PGBOUNCER_FILES.config]!, await Bun.file(templates.ini).text());
  if (
    files[PGBOUNCER_FILES.hba] !== (await Bun.file(templates.hba).text()) ||
    files[PGBOUNCER_FILES.hba] !== pgbouncerHba()
  ) {
    throw new Error("Rendered pg_hba.conf drifts from the template.");
  }
  if (files[PGBOUNCER_FILES.userlist]!.includes(adminPassword))
    throw new Error("The admin password reached the userlist.");
  await asHost(() => writePgbouncerFiles(pgbouncerDir, files));
  const reload = await probe(["reload"]);
  if (!reload.ok) throw new Error(`RELOAD over the admin socket failed: ${reload.error}`);
  if (reload.environment.dockerCli || reload.environment.dockerSocket) {
    throw new Error("The worker stand-in can reach Docker; the reload path must not need it.");
  }
  record(
    "RELOAD via the admin socket (worker stand-in, no Docker CLI or socket)",
    `ok in ${reload.attempts} attempt(s); docker CLI=${reload.environment.dockerCli ?? "absent"}, docker.sock=${reload.environment.dockerSocket ? "present" : "absent"}, uid=${reload.environment.uid}`,
  );
  const config = await probe(["show", "SHOW CONFIG"]);
  const live = new Map((config.rows ?? []).map((row) => [String(row.key), String(row.value)]));
  for (const [key, value] of [
    ["auth_type", "hba"],
    ["client_tls_sslmode", "verify-full"],
    ["client_tls_protocols", "tlsv1.3"],
    ["max_prepared_statements", "200"],
    ["pool_mode", "transaction"],
    ["admin_users", "ark_pgbouncer_admin"],
  ] as const) {
    if (live.get(key) !== value) throw new Error(`Live ${key} is ${live.get(key)}, expected ${value}`);
  }
  record(
    "live SHOW CONFIG after RELOAD",
    "auth_type=hba, verify-full, tlsv1.3, max_prepared_statements=200, transaction",
  );

  // ---- V-8 matrix --------------------------------------------------------------------------
  const accepted = await hostPsql({
    role: appRole,
    password: appPassword,
    client: shop,
    sql: "SELECT current_user || ' @ ' || current_database()",
  });
  if (accepted.status !== 0) throw new Error(`Valid certificate + password was rejected: ${accepted.stderr}`);
  const conninfo = await hostPsql({ role: appRole, password: appPassword, client: shop, sql: "\\conninfo" });
  // psql 17 prints "SSL connection (protocol: TLSv1.3, …)"; psql 18 prints a table row "SSL Protocol | TLSv1.3".
  const protocol = /SSL connection \(protocol: (TLSv[\d.]+)|SSL Protocol\s*\|\s*(TLSv[\d.]+)/.exec(
    conninfo.stdout,
  );
  if ((protocol?.[1] ?? protocol?.[2]) !== "TLSv1.3") {
    throw new Error(`Client connection was not TLS 1.3: ${conninfo.stdout}`);
  }
  record(
    "V-8 valid certificate + correct password",
    `accepted — ${accepted.stdout.trim()}; client TLS ${protocol?.[1] ?? protocol?.[2]}`,
  );
  expectRejected(
    await hostPsql({ role: appRole, password: appPassword, sql: "SELECT 1" }),
    /certificate required/,
    "V-8 no client certificate",
  );
  expectRejected(
    await hostPsql({ role: appRole, password: appPassword, client: rogue, sql: "SELECT 1" }),
    /unknown ca/,
    "V-8 certificate from a rogue CA",
  );
  expectRejected(
    await hostPsql({ role: appRole, password: `${appPassword}x`, client: shop, sql: "SELECT 1" }),
    /SASL authentication failed|password authentication failed/,
    "V-8 wrong password",
  );
  expectRejected(
    await hostPsql({
      role: appRole,
      password: appPassword,
      client: shop,
      sql: "SELECT 1",
      extra: "ssl_max_protocol_version=TLSv1.2",
    }),
    /protocol version|unsupported protocol|no protocols available|wrong version/i,
    "V-8 TLS 1.2 (psql)",
  );
  const tls12 = await run(
    [
      openssl,
      "s_client",
      "-starttls",
      "postgres",
      "-connect",
      `127.0.0.1:${loopbackPort}`,
      "-tls1_2",
      "-cert",
      shop.cert,
      "-key",
      shop.key,
    ],
    { allowFailure: true, stdin: "" },
  );
  assertTls12Rejected(tls12);
  record(
    "V-8 TLS 1.2 (openssl s_client -tls1_2)",
    `refused — ${lastLine(tls12.stderr) || lastLine(tls12.stdout)}`,
  );
  // Negative control: the assertion must fail against a real TLS-1.2-enabled listener.
  const tls12Listener = createTlsServer(
    {
      key: await Bun.file(join(certDir, "privkey.pem")).text(),
      cert: await Bun.file(join(certDir, "fullchain.pem")).text(),
      minVersion: "TLSv1.2",
      maxVersion: "TLSv1.2",
    },
    (tlsClient) => tlsClient.end(),
  );
  try {
    await new Promise<void>((done) => tls12Listener.listen(0, "127.0.0.1", done));
    const port = (tls12Listener.address() as { port: number }).port;
    const enabled = await run([openssl, "s_client", "-connect", `127.0.0.1:${port}`, "-tls1_2"], {
      allowFailure: true,
      stdin: "",
    });
    let caught = false;
    try {
      assertTls12Rejected(enabled);
    } catch (error) {
      caught = error instanceof Error && error.message === "TLS 1.2 handshake succeeded.";
    }
    if (!caught) throw new Error("TLS 1.2 negative control did not establish a successful handshake.");
    record("TLS 1.2 rejection assertion negative control", "detects a real TLS-1.2-enabled listener");
  } finally {
    await new Promise<void>((done) => tls12Listener.close(() => done()));
  }

  const crossed = await hostPsql({
    role: appRole,
    password: appPassword,
    client: preview,
    sql: "SELECT current_user",
  });
  if (crossed.status !== 0) throw new Error(`Cross-client certificate check changed: ${crossed.stderr}`);
  record(
    "V-8 note: another client's certificate + this role's password",
    "accepted (the certificate does not bind the role; SCRAM does — §3.10.3)",
  );
  expectRejected(
    await hostPsql({ role: appRole, password: appPassword, sql: "SELECT 1", sslmode: "disable" }),
    /SSL required/,
    "plaintext client",
  );
  expectRejected(
    await hostPsql({ role: ownerRole, password: ownerPassword, client: shop, sql: "SELECT 1" }),
    /SASL authentication failed|password authentication failed|no such user|not allowed/,
    "_owner role (not in the userlist)",
  );

  // ---- Admin identity: local socket only -------------------------------------------------------
  const adminTcp = await hostPsql({
    role: "ark_pgbouncer_admin",
    password: adminPassword,
    client: shop,
    dbname: "pgbouncer",
    sql: "SHOW VERSION",
  });
  if (adminTcp.status === 0)
    throw new Error("The administrator was admitted over TCP with a valid application certificate.");
  record(
    "admin password + valid application certificate on the public endpoint",
    `rejected — ${lastLine(adminTcp.stderr)}`,
  );
  const adminSocket = await socketPsql("ark_pgbouncer_admin", adminPassword, "pgbouncer", "SHOW VERSION");
  if (adminSocket.status !== 0 || !adminSocket.stdout.includes("PgBouncer 1.26.1")) {
    throw new Error(`SCRAM admin login over the unix socket failed: ${adminSocket.stderr}`);
  }
  record(
    "same admin password over the shared unix socket (SCRAM)",
    `accepted — ${adminSocket.stdout.trim()}`,
  );
  const appSocket = await socketPsql(appRole, appPassword, database, "SELECT 1");
  if (appSocket.status === 0) throw new Error("An application role was admitted over the unix socket.");
  record("application role over the unix socket", `rejected — ${lastLine(appSocket.stderr)}`);

  // Exercise the actual worker's pinned Linux TLS runtime, independent of the host's Bun TLS.
  const clientProbe = await run([
    "docker",
    "run",
    "--rm",
    "--user",
    arkUid,
    "--read-only",
    "--cap-drop",
    "ALL",
    "--network",
    network,
    "--volume",
    `${probeDir}:/probe:ro`,
    bunImage,
    "bun",
    "/probe/pgbouncer-client-probe.js",
  ]);
  const clientChecks = JSON.parse(clientProbe.stdout.trim()) as {
    ok: boolean;
    checks: Array<{ check: string; outcome: string }>;
  };
  if (!clientChecks.ok) throw new Error("Linux pooling probe failed.");
  for (const { check, outcome } of clientChecks.checks) record(check, outcome);

  // ---- Server certificate swap: renewal reload verifies the served fingerprint ----------------
  const before = await opensslFingerprint();
  if (before !== (await fileFingerprint(serverCa)))
    throw new Error("openssl saw an unexpected initial certificate.");
  const renewed = join(work, "renewed");
  await mkdir(renewed, { recursive: true });
  await serverCertificate(renewed);
  const expected = await fileFingerprint(join(renewed, "fullchain.pem"));
  await asHost(async () => {
    // Atomic replacement, as certificate issuance does (`.next`, then rename).
    for (const name of ["privkey.pem", "fullchain.pem"]) {
      await Bun.write(join(certDir, `${name}.next`), await Bun.file(join(renewed, name)).text());
      await chmod(join(certDir, `${name}.next`), 0o600);
      await rename(join(certDir, `${name}.next`), join(certDir, name));
    }
  });
  const stillOld = await opensslFingerprint();
  if (stillOld !== before) throw new Error("PgBouncer served the new certificate before RELOAD.");
  const renewal = await probe(["reload", expected]);
  if (!renewal.ok || renewal.fingerprint !== expected)
    throw new Error(`Renewal reload failed: ${renewal.error}`);
  const after = await opensslFingerprint();
  if (after !== expected || after === before) throw new Error(`openssl sees ${after}, expected ${expected}`);
  record(
    "certificate swap + renewal reload (openssl s_client on the published port)",
    `before ${before.slice(0, 16)}…, after files swapped (no reload) ${stillOld.slice(0, 16)}…, after RELOAD ${after.slice(0, 16)}… (worker verified in ${renewal.attempts} attempt(s))`,
  );
  await Bun.write(serverCa, await Bun.file(join(renewed, "fullchain.pem")).text());

  // ---- Simulated reload failures: retries, then failure, never success ------------------------
  const noSocket = await probe(["reload", expected], {
    ARK_PGBOUNCER_SOCKET_DIR: "/tmp/no-admin-socket",
    ARK_PGBOUNCER_RELOAD_RETRY_MS: "100",
  });
  if (noSocket.ok || noSocket.status === 0 || noSocket.attempts !== 3 || noSocket.failures?.length !== 3) {
    throw new Error(`An unreachable admin socket did not fail after 3 attempts: ${JSON.stringify(noSocket)}`);
  }
  record(
    "simulated reload failure (no admin socket)",
    `failed after ${noSocket.attempts} attempts, no success state — ${noSocket.failures.at(-1)}`,
  );
  const stale = await probe(["reload", before], { ARK_PGBOUNCER_RELOAD_RETRY_MS: "100" });
  if (stale.ok || stale.attempts !== 3)
    throw new Error(`A stale served certificate was accepted: ${JSON.stringify(stale)}`);
  record(
    "simulated stale certificate (served fingerprint ≠ renewed)",
    `failed after ${stale.attempts} attempts — ${stale.failures?.at(-1)}`,
  );

  // ---- FD-17 database clients: connect, read-only preview, revoke ------------------------------
  const fdDatabase = "ark_fd17";
  const provision = buildProvisionPlan({
    name: fdDatabase,
    passwords: { owner: secret(), migration: secret(), runtime: secret(), readonly: secret() },
    withPgvector: false,
    withTestDatabase: false,
  });
  const appSql = (statements: string[], dbname = "postgres", extra: string[] = []) =>
    run([
      "docker",
      "exec",
      appContainer,
      "psql",
      "--username",
      "ark_cluster_admin",
      "--dbname",
      dbname,
      "--set",
      "ON_ERROR_STOP=1",
      ...extra,
      ...statements.flatMap((statement) => ["--command", statement]),
    ]);
  // The database worker's provisioning: owner, migration, runtime and readonly roles and grants.
  await appSql(provision.statements);
  await appSql(provision.extensionStatements, fdDatabase);
  await appSql(
    [
      `SET ROLE "${fdDatabase}_migration"`,
      "CREATE TABLE fd17_items (id serial PRIMARY KEY, value text NOT NULL)",
      "INSERT INTO fd17_items (value) VALUES ('seed')",
    ],
    fdDatabase,
  );
  const fdClients = await Promise.all(
    [
      { key: "a", id: "dbc_fd17_a", name: "shop", environment: "production" },
      { key: "b", id: "dbc_fd17_b", name: "shop", environment: "preview" },
    ].map(async (client) => {
      const role = clientRoleName(fdDatabase, client.name, client.environment);
      const roleKind = defaultClientRoleKind(client.environment);
      const caId = `pca_${client.id}`;
      const ca = pki.createCaMaterial({
        id: caId,
        purpose: "db-client",
        name: `${client.name}/${client.environment}`,
      });
      return {
        ...client,
        role,
        roleKind,
        caId,
        ca,
        password: secret(),
        issued: await issueClient(ca, role, `fd17-${client.key}`),
      };
    }),
  );
  const [clientA, clientB] = fdClients as [(typeof fdClients)[0], (typeof fdClients)[0]];
  if (clientB.roleKind !== "readonly" || clientA.roleKind !== "runtime")
    throw new Error("Preview must default to readonly and production to runtime (R5).");
  for (const client of fdClients) {
    await appSql(
      clientRoleSql({
        role: client.role,
        group: clientGroupRole(fdDatabase, client.roleKind),
        password: client.password,
        connectionLimit: DB_CLIENT_CONNECTION_LIMITS[client.roleKind],
        exists: false,
      }),
    );
  }
  const fdPlan = (revokedB: boolean) =>
    planPgbouncer({
      databases: [
        { id: "mdb_smoke", name: database, exposure: "public" },
        { id: "mdb_fd17", name: fdDatabase, exposure: "public" },
      ],
      clients: [
        ...smokeClients,
        ...fdClients.map((client) => {
          const revoked = revokedB && client === clientB;
          return {
            id: client.id,
            databaseId: "mdb_fd17",
            environment: client.environment,
            status: revoked ? "revoked" : "active",
            caId: client.caId,
            role: {
              name: client.role,
              connectionLimit: DB_CLIENT_CONNECTION_LIMITS[client.roleKind],
              password: revoked ? null : client.password,
            },
          };
        }),
      ],
      certificates: [
        ...smokeCertificates,
        ...fdClients.map((client) => ({
          id: `ccert_${client.id}`,
          caId: client.caId,
          status: revokedB && client === clientB ? "revoked" : "issued",
          rolloverState: "current",
          supersededBy: null,
          notAfter: client.issued.notAfter,
        })),
      ],
      cas: [
        ...smokeCas,
        ...fdClients.map((client) => ({
          id: client.caId,
          purpose: "db-client",
          status: revokedB && client === clientB ? "revoked" : "active",
          certPem: client.ca.certPem,
          notAfter: client.ca.notAfter,
        })),
      ],
      now: new Date(),
      host: "app-postgres",
      settings: { previewMaxUserClientConnections: limitedClientConnections },
    });
  const applyPlan = async (next: ReturnType<typeof planPgbouncer>) => {
    const rendered = renderPgbouncerFiles({
      plan: next,
      adminPassword,
      certificateDir: "/var/lib/ark/certs/database",
    });
    await asHost(() => writePgbouncerFiles(pgbouncerDir, rendered));
    const reloaded = await probe(["reload"]);
    if (!reloaded.ok) throw new Error(`RELOAD failed: ${reloaded.error}`);
    return rendered;
  };
  const admitted = fdPlan(false);
  for (const client of fdClients) {
    if (
      !admitted.users.some((user) => user.name === client.role) ||
      !admitted.caBundle.includes(client.ca.certPem.trim())
    )
      throw new Error(`${client.role} was not admitted with its CA generation.`);
  }
  await applyPlan(admitted);

  // Bundle Ark's §3.12 module, unmodified, with the real pg and @vercel/functions packages. It
  // is generated under the repository's ignored tmp/ so the packages resolve from node_modules.
  const appDir = join(root, "tmp", `fd17-vercel-${suffix}`);
  await mkdir(join(appDir, "lib"), { recursive: true });
  await Bun.write(join(appDir, "lib", "db.ts"), NODE_POSTGRES_SNIPPET);
  try {
    await asHost(async () => {
      for (const entry of [
        join(appDir, "lib", "db.ts"),
        join(import.meta.dir, "pgbouncer-vercel-probe.ts"),
      ]) {
        const output = await Bun.build({
          entrypoints: [entry],
          target: "bun",
          outdir: join(probeDir, "vercel"),
          external: ["pg-native"],
        });
        if (!output.success) throw new Error(`Could not bundle ${entry}:\n${output.logs.join("\n")}`);
      }
      await Bun.write(join(probeDir, "server-ca.pem"), await Bun.file(serverCa).text());
    });
  } finally {
    await rm(appDir, { recursive: true, force: true });
  }

  type FdClient = (typeof fdClients)[number];
  /** The probe's env is exactly the client's one-time reveal (`vercel.env`), host aside. */
  const revealedEnv = (client: FdClient) =>
    Object.fromEntries(
      databaseClientGuide({
        host: "pgbouncer-public",
        database: fdDatabase,
        role: client.role,
        environment: client.environment,
        roleKind: client.roleKind,
        region: "us-east",
        secrets: { password: client.password, certPem: client.issued.certPem, keyPem: client.issued.keyPem },
      }).env.map((item) => [item.name, item.value]),
    );
  const vercelCommand = (client: FdClient, mode: string, detach?: string) => {
    const values = revealedEnv(client);
    return {
      values,
      command: [
        "docker",
        "run",
        ...(detach ? ["--detach", "--name", detach] : ["--rm"]),
        "--user",
        arkUid,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--network",
        network,
        "--volume",
        `${probeDir}:/probe:ro`,
        ...Object.keys(values).flatMap((name) => ["--env", name]),
        // Stands in for the publicly trusted certificate production serves (§3.12 needs no CA).
        "--env",
        "NODE_EXTRA_CA_CERTS=/probe/server-ca.pem",
        bunImage,
        "bun",
        "/probe/vercel/pgbouncer-vercel-probe.js",
        mode,
      ],
    };
  };
  const vercelProbe = async (client: FdClient, mode: string) => {
    const { values, command } = vercelCommand(client, mode);
    const result = await run(command, { allowFailure: true, env: values });
    const line = result.stdout.split("\n").findLast((item) => item.startsWith("{"));
    if (!line) throw new Error(`Vercel probe printed no result:\n${result.stderr || result.stdout}`);
    return JSON.parse(line) as Record<string, unknown> & {
      ok: boolean;
      error?: string;
      code?: string;
    };
  };
  type Outcome = { ok: boolean; code?: string | null; error?: string; user?: string };

  for (const client of fdClients) {
    const connected = await vercelProbe(client, "connect");
    if (!connected.ok || connected.user !== client.role || connected.tls !== "TLSv1.3" || !connected.attached)
      throw new Error(
        `The §3.12 node-postgres module did not connect as ${client.role}: ${JSON.stringify(connected)}`,
      );
    record(
      `FD-17 connect: §3.12 node-postgres Pool + attachDatabasePool with the revealed env (${client.environment})`,
      `connected as ${connected.user} to ${connected.database} over ${connected.tls}; attachDatabasePool attached`,
    );
  }
  const writesA = (await vercelProbe(clientA, "write")) as unknown as Record<string, Outcome>;
  for (const action of ["select", "insert", "update", "delete"]) {
    if (!writesA[action]?.ok)
      throw new Error(`Production ${action} failed: ${JSON.stringify(writesA[action])}`);
  }
  record(
    `FD-17 production client (${clientA.role}, IN ROLE ${fdDatabase}_runtime)`,
    "SELECT, INSERT, UPDATE and DELETE succeed",
  );
  const writesB = (await vercelProbe(clientB, "write")) as unknown as Record<string, Outcome>;
  if (!writesB.select?.ok) throw new Error(`Preview SELECT failed: ${JSON.stringify(writesB.select)}`);
  for (const action of ["insert", "update", "delete"]) {
    const outcome = writesB[action];
    if (outcome?.ok || outcome?.code !== "42501" || !/permission denied/.test(outcome.error ?? ""))
      throw new Error(`Preview ${action} was not refused: ${JSON.stringify(outcome)}`);
  }
  record(
    `FD-17 preview client (${clientB.role}, IN ROLE ${fdDatabase}_readonly)`,
    `SELECT succeeds; INSERT, UPDATE and DELETE refused — ${writesB.insert!.code} ${writesB.insert!.error}`,
  );

  // Revocation with live sessions: hold one session per client across the revoke.
  const verifiers = async () => {
    const rows = await appSql(
      [
        `SELECT rolname || '|' || rolcanlogin || '|' || rolpassword FROM pg_authid WHERE rolname IN ('${clientA.role}', '${clientB.role}') ORDER BY rolname`,
      ],
      "postgres",
      ["--tuples-only", "--no-align"],
    );
    return new Map(
      rows.stdout.split("\n").map((line) => {
        const [name, login, scram] = line.split("|");
        return [name!, { login: login === "true", verifier: scram! }] as const;
      }),
    );
  };
  const holders = fdClients.map((client) => ({ client, name: `${project}-hold-${client.key}` }));
  try {
    for (const holder of holders) {
      const { values, command } = vercelCommand(holder.client, "hold", holder.name);
      await run(command, { env: values });
    }
    const deadline = Date.now() + 30_000;
    for (const holder of holders) {
      for (;;) {
        const logs = await run(["docker", "logs", holder.name], { allowFailure: true });
        if (logs.stdout.includes('"ready":true')) break;
        if (Date.now() > deadline)
          throw new Error(`${holder.name} never held a session:\n${logs.stdout}${logs.stderr}`);
        await Bun.sleep(250);
      }
    }
    const sessionsBefore = {
      a: (await probe(["clients", clientA.role])).ids ?? [],
      b: (await probe(["clients", clientB.role])).ids ?? [],
    };
    if (!sessionsBefore.a?.length || !sessionsBefore.b?.length)
      throw new Error(`Held sessions are not visible in SHOW CLIENTS: ${JSON.stringify(sessionsBefore)}`);
    const rolesBefore = await verifiers();

    // database.client_revoke, in the worker's order (§3.10.4):
    // 1. B, its certificate and its CA generation revoked: the bundle drops B's CA.
    const reduced = fdPlan(true);
    if (
      reduced.caBundle.includes(clientB.ca.certPem.trim()) ||
      !reduced.caBundle.includes(clientA.ca.certPem.trim())
    )
      throw new Error("The reduced bundle must drop exactly B's CA generation.");
    if (reduced.users.some((user) => user.name === clientB.role)) throw new Error("B is still in [users].");
    // 2. Rotate B's password to one nobody sees, NOLOGIN, and end its cluster backends.
    await appSql([...revokedClientRoleSql(clientB.role, secret()), terminateRoleSessionsSql(clientB.role)]);
    // 3. Userlist and CA bundle written atomically, then RELOAD over the admin socket.
    await applyPlan(reduced);
    const survivedReload = (await probe(["clients", clientB.role])).ids ?? [];
    // 4. KILL_CLIENT every session of B's role.
    const killed = await probe(["kill", clientB.role]);
    if (!killed.ok) throw new Error(`KILL_CLIENT failed: ${killed.error}`);
    const sessionsAfter = {
      a: (await probe(["clients", clientA.role])).ids ?? [],
      b: (await probe(["clients", clientB.role])).ids ?? [],
    };

    for (const holder of holders)
      await run(["docker", "kill", "--signal", "USR1", holder.name], { allowFailure: true });
    const held: Record<string, { existing: Outcome; ended: boolean; errors: string[] }> = {};
    for (const holder of holders) {
      await run(["docker", "wait", holder.name]);
      const logs = await run(["docker", "logs", holder.name]);
      const line = logs.stdout.split("\n").findLast((item) => item.includes('"done":true'));
      if (!line) throw new Error(`${holder.name} reported nothing:\n${logs.stdout}${logs.stderr}`);
      held[holder.client.key] = JSON.parse(line);
    }
    const rolesAfter = await verifiers();

    if (!survivedReload.length)
      throw new Error("B's session should survive the RELOAD (V-8); KILL_CLIENT must be what closes it.");
    if ((killed.killed ?? 0) < 1 || sessionsAfter.b.length)
      throw new Error(`B's sessions were not killed: ${JSON.stringify({ killed, sessionsAfter })}`);
    if (held.b?.existing.ok) throw new Error("B's held session still answers after revocation.");
    record(
      "FD-17 revoke B: existing session",
      `${survivedReload.length} session(s) survived the RELOAD as expected, KILL_CLIENT closed ${killed.killed ?? 0}; the held node-postgres client then fails — ${held.b?.existing.error ?? held.b?.errors.at(-1)}`,
    );
    expectRejected(
      await hostPsql({
        role: clientB.role,
        password: clientB.password,
        dbname: fdDatabase,
        client: clientB.issued,
        sql: "SELECT 1",
      }),
      /unknown ca/,
      "FD-17 revoke B: new connection (psql, B's certificate)",
    );
    // In TLS 1.3 the server checks the client certificate after the client's handshake is done,
    // so node-postgres sees the connection closed rather than the alert name. Tie the failure to
    // PgBouncer's own certificate-verification failure for exactly this attempt.
    const verifyFailures = async () => {
      const logs = await run(["docker", "logs", bouncer], { allowFailure: true });
      return (`${logs.stdout}\n${logs.stderr}`.match(/certificate verify failed/g) ?? []).length;
    };
    const failuresBefore = await verifyFailures();
    const newB = await vercelProbe(clientB, "connect");
    const failuresAfter = await verifyFailures();
    if (newB.ok || /SASL|password/i.test(newB.error ?? "") || failuresAfter <= failuresBefore)
      throw new Error(
        `B's new connection should fail at TLS certificate verification: ${JSON.stringify({ newB, failuresBefore, failuresAfter })}`,
      );
    record(
      "FD-17 revoke B: new connection (§3.12 node-postgres module)",
      `rejected at TLS — client: ${newB.error}; PgBouncer: certificate verify failed (+${failuresAfter - failuresBefore})`,
    );
    if (
      !rolesBefore.get(clientB.role)?.login ||
      rolesBefore.get(clientB.role)?.verifier === rolesAfter.get(clientB.role)?.verifier ||
      rolesAfter.get(clientB.role)?.login
    )
      throw new Error("B's password was not rotated with NOLOGIN.");
    record(
      "FD-17 revoke B: password",
      `SCRAM verifier changed (${rolesBefore.get(clientB.role)!.verifier.slice(0, 28)}… → ${rolesAfter.get(clientB.role)!.verifier.slice(0, 28)}…), rolcanlogin=false`,
    );
    if (
      !held.a?.existing.ok ||
      held.a.ended ||
      JSON.stringify(sessionsAfter.a) !== JSON.stringify(sessionsBefore.a)
    )
      throw new Error(
        `A's session was disturbed: ${JSON.stringify({ held: held.a, sessionsBefore, sessionsAfter })}`,
      );
    if (
      rolesBefore.get(clientA.role)?.verifier !== rolesAfter.get(clientA.role)?.verifier ||
      !rolesAfter.get(clientA.role)?.login
    )
      throw new Error(
        `A's password or login changed: ${JSON.stringify({ before: rolesBefore.get(clientA.role), after: rolesAfter.get(clientA.role) })}`,
      );
    const newA = await vercelProbe(clientA, "connect");
    if (!newA.ok || newA.user !== clientA.role)
      throw new Error(`A's new connection failed: ${JSON.stringify(newA)}`);
    record(
      "FD-17 revoke B: client A unaffected",
      `held session alive (same console id ${sessionsBefore.a.join(",")}, query ok as ${held.a.existing.user ?? clientA.role}), SCRAM verifier unchanged, new connection ok over ${newA.tls}`,
    );
  } finally {
    for (const holder of holders) await run(["docker", "rm", "--force", holder.name], { allowFailure: true });
  }

  const health = await inspect(bouncer, "{{.State.Health.Status}} restarts={{.RestartCount}}");
  if (!health.startsWith("healthy restarts=0")) throw new Error(`pgbouncer-public degraded: ${health}`);
  record("pgbouncer-public after all checks", health);

  log("\n---- rendered pgbouncer.ini ----\n" + files[PGBOUNCER_FILES.config]);
  log("---- rendered pg_hba.conf ----\n" + files[PGBOUNCER_FILES.hba]);
  log(
    "---- rendered userlist.txt (redacted) ----\n" +
      files[PGBOUNCER_FILES.userlist]!.replace(/^("[^"]+") "[^"]*"$/gm, '$1 "<redacted>"') +
      "\n",
  );
  log("---- results ----");
  for (const [check, outcome] of results) log(`| ${check} | ${outcome} |`);
  log("\npgbouncer-public smoke test passed.");
} catch (error) {
  const bouncer = await run([...compose, "logs", "--no-color", "pgbouncer-public"], { allowFailure: true });
  console.error(bouncer.stdout || bouncer.stderr);
  throw error;
} finally {
  await run([...compose, "down", "--volumes", "--remove-orphans", "--timeout", "5"], { allowFailure: true });
  // Files are owned by uid 1000 now; hand them back so the runner can delete them.
  if (pgbouncerImage) await chownState(hostUid).catch(() => undefined);
  await rm(work, { recursive: true, force: true });
}
