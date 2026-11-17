// FD-30 acceptance suite: home-machine backups over the tailnet, run locally in disposable containers
// (docs/design/front-door.md §3.18.3, §5 FD-30). No tailnet login is needed; the opt-in real-tailnet
// check is scripts/test-backups-tailnet-live.ts.
//
// Fixtures, following the FD-05/FD-06 edge harness (scripts/test-edge-observer.ts):
//   - backup-ts started from the shipped Compose service (pinned tailscale v1.86.2, userspace, no
//     capabilities, its socket volume and internal backup-tailnet network) with tailscaled run directly
//     (containerboot gives up without a login) and the shipped SOCKS5 listener on :1055;
//   - a Docker network inside 100.64.0.0/10 that only backup-ts joins stands in for the tailnet, with
//     `rest-server --append-only --private-repos` (pinned by digest) on it, plus a negative fixture
//     without --append-only;
//   - a mocked LocalAPI for backup-ts's tailnet view (observation, pinning, replacement, removal and
//     lease expiry), committed by the production `backup.observe` operation; the real tailscaled
//     socket is used for the UID and write-denial checks;
//   - a pinned MinIO for the S3 target, a throwaway control database (postgres:17.6) and a fake
//     PostgreSQL executor; the production exporter runs in-process and restic runs in the pinned image
//     on the network a deployed backup worker would use (scripts/backup-test/restic-docker-tailnet.sh).
// Checks:
//   1. Deployment: Compose isolation claims; backup-ts's LocalAPI read as uid 1000 through the read-only
//      mount, every write refused (403), root control allowed; the production client sees a logged-out
//      node as a partial observation.
//   2. Pinning with disjoint grants: the edge generation does not see the home machine, backup-ts's
//      does; the target pins and backs up from the backup generation alone.
//   3. Proxy scoping: the backup worker's network has no tailnet route; REST traffic reaches rest-server
//      only from backup-ts's address; the REST subprocess gets exactly HTTP_PROXY=socks5://backup-ts:1055
//      while S3 subprocesses get no proxy even with conflicting variables on the worker; API calls
//      are direct.
//   4. Append-only: the canary passes on --append-only and reports the negative fixture as deletable;
//      `restic forget --prune` from the VPS removes nothing and no stale locks remain (V-18).
//   5. Identity and freshness: replacing the StableNodeID, removing the node or letting the lease
//      expire stops an active REST transfer within the documented bound (no edge grant, no apply);
//      new transfers then fail without contacting rest-server.
//   6. Health: with both targets fresh backups are healthy; either target stale is unhealthy and alerts.
import { randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import {
  PROXY_ENV_NAMES,
  TRANSFER_STOP_BOUND_MS,
  parseLocalApiStatus,
  repositoryProtectionPolicy,
  writerPolicy,
  type StageManifest,
} from "@ark-stack/shared";

import type { RestCanaryEvidence } from "../server/src/modules/rest-canary.ts";
import { EdgeTestRuntime } from "./edge-test/runtime.ts";
import { startControlDb, testNetworkBase, type ControlDb } from "./backup-test/harness.ts";
import { REST_SERVER_IMAGE, startMinio, type MinioFixture } from "./backup-test/minio.ts";
import { loadCompose, tailnetComposeClaims, composePath } from "./backup-test/tailnet-compose.ts";
import { createWorkVolume } from "./backup-test/work-volume.ts";

const root = resolve(import.meta.dir, "..");
const bunImage =
  "oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61";

const suffix = randomBytes(4).toString("hex");
const project = `ark-fd30-${suffix}`;
const work = await mkdtemp(join(tmpdir(), `ark-fd30-${suffix}-`));
await chmod(work, 0o755);
const tailnetNetwork = `${project}-tailnet`;
const runtime = new EdgeTestRuntime(work, tailnetNetwork);
const removeSignalHandlers = runtime.installSignalHandlers();
const docker = (...args: string[]) => runtime.docker(...args);
const suffixDns = ".tail9fd30.ts.net";
// A random /24 inside 100.64.0.0/10 for the simulated tailnet.
const octet = 64 + (randomBytes(1)[0]! % 64);
const third = 1 + (randomBytes(1)[0]! % 250);
const homeIp = `100.${octet}.${third}.10`;
const home2Ip = `100.${octet}.${third}.11`;
const homeUrl = `http://backup-home${suffixDns}:8000/ark`;
const home2Url = `http://backup-home2${suffixDns}:8000/ark`;
const restPassword = randomBytes(18).toString("base64url");
const repositoryPassword = randomBytes(24).toString("base64url");

const results: Array<{ check: string; observed: string }> = [];
function check(condition: unknown, claim: string, observed: string): asserts condition {
  if (!condition) throw new Error(`FAILED: ${claim} (observed: ${observed})`);
  results.push({ check: claim, observed });
  console.log(`  ok  ${claim} [${observed}]`);
}

async function waitFor<T>(
  what: string,
  attempt: () => Promise<T | undefined>,
  timeoutMs = 60_000,
  stepMs = 200,
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await attempt().catch(() => undefined);
    if (value !== undefined) return value;
    await Bun.sleep(stepMs);
  }
  throw new Error(`Timed out after ${timeoutMs} ms waiting for ${what}.`);
}

async function bundle(entry: string, name: string) {
  const outdir = join(work, name);
  const built = await Bun.build({ entrypoints: [entry], target: "bun", outdir });
  if (!built.success) throw new Error(`Bundling ${entry} failed: ${built.logs.join("\n")}`);
  await chmod(outdir, 0o755);
  return outdir;
}

const state: {
  control?: ControlDb;
  minio?: MinioFixture;
  executor?: ReturnType<typeof Bun.serve>;
  api?: ReturnType<typeof Bun.serve>;
  mock?: import("../server/src/mock-localapi.ts").MockLocalApi;
  decoy?: ReturnType<typeof createServer>;
} = {};

// ---- Fixtures ------------------------------------------------------------------------------------

const backupTs = `${project}-backup-ts-1`;
const homeServer = `${project}-rest-home`;
const home2Server = `${project}-rest-home2`;
let socksPort = 0;
let workVolume!: Awaited<ReturnType<typeof createWorkVolume>>;
let backupTsTailnetIp = "";

async function startRestServer(name: string, ip: string, appendOnly: boolean) {
  const htpasswd = join(work, `${name}.htpasswd`);
  // Apache's bcrypt prefix; the hash itself is standard bcrypt.
  const hash = (await Bun.password.hash(restPassword, { algorithm: "bcrypt", cost: 4 })).replace(
    /^\$2[ab]\$/,
    "$2y$",
  );
  await writeFile(htpasswd, `ark:${hash}\n`);
  await chmod(htpasswd, 0o644);
  runtime.containers.push(name);
  await docker(
    "run",
    "--detach",
    "--name",
    name,
    "--label",
    "ark.test=fd30-backups",
    "--network",
    tailnetNetwork,
    "--ip",
    ip,
    "--tmpfs",
    "/data:rw,size=1g",
    "--volume",
    `${htpasswd}:/etc/rest-server/.htpasswd:ro`,
    "--entrypoint",
    "rest-server",
    REST_SERVER_IMAGE,
    "--path",
    "/data",
    "--listen",
    ":8000",
    "--htpasswd-file",
    "/etc/rest-server/.htpasswd",
    "--private-repos",
    ...(appendOnly ? ["--append-only"] : []),
    "--log",
    "-",
  );
  await waitFor(`${name} to listen`, async () => {
    const { stdout, stderr } = await runtime.dockerOutput("logs", name);
    return /start server/.test(stdout + stderr) ? true : undefined;
  });
}

/** rest-server's combined log: one line per request, with the client address. */
async function restLog(name = homeServer) {
  const { stdout, stderr } = await runtime.dockerOutput("logs", name);
  return `${stdout}\n${stderr}`.split("\n").filter((line) => /"(GET|POST|HEAD|DELETE) /.test(line));
}

async function startBackupTs() {
  const compose = await Bun.file(composePath).text();
  const required = [...new Set([...compose.matchAll(/\$\{([A-Z0-9_]+):\?/g)].map((match) => match[1]))];
  const envFile = join(work, `${project}.env`);
  await Bun.write(envFile, required.map((name) => `${name}=fd30-test-unused`).join("\n") + "\n");
  const document = Bun.YAML.parse(compose) as {
    services: { "backup-ts": { environment: Record<string, string> } };
    networks: Record<string, { external?: boolean } | null>;
  };
  const env = document.services["backup-ts"].environment;
  const base = await testNetworkBase();
  const external = Object.entries(document.networks)
    .filter(([, network]) => network?.external)
    .map(([name]) => name);
  // tailscaled itself with the shipped settings: userspace networking (TS_USERSPACE), SOCKS5
  // (TS_SOCKS5_SERVER), the socket path (TS_SOCKET) and port (TS_TAILSCALED_EXTRA_ARGS). The only
  // test-only additions are in-memory state and a loopback publish of :1055 for this process.
  const command = [
    "tailscaled",
    "--tun=userspace-networking",
    `--socks5-server=${env.TS_SOCKS5_SERVER}`,
    "--state=mem:",
    `--socket=${env.TS_SOCKET}`,
    ...(env.TS_TAILSCALED_EXTRA_ARGS ?? "").split(" ").filter(Boolean),
  ];
  const override = [
    "services:",
    "  backup-ts:",
    `    entrypoint: ${JSON.stringify(command.slice(0, 1))}`,
    `    command: ${JSON.stringify(command.slice(1))}`,
    `    ports: ["127.0.0.1::1055"]`,
    "networks:",
    "  backup-tailnet:",
    `    ipam: { config: [{ subnet: "${base}.0/26" }] }`,
    "  backup-ts-egress:",
    `    ipam: { config: [{ subnet: "${base}.64/26" }] }`,
    ...external.flatMap((name) => [`  ${name}:`, "    external: false", `    name: ${project}_${name}`]),
    "",
  ].join("\n");
  const overrideFile = join(work, `${project}.override.yml`);
  await Bun.write(overrideFile, override);
  runtime.composeProjects.push(project);
  runtime.containers.push(backupTs);
  await docker(
    "compose",
    "-p",
    project,
    "--env-file",
    envFile,
    "-f",
    composePath,
    "-f",
    overrideFile,
    "up",
    "--detach",
    "--no-deps",
    "backup-ts",
  );
  await waitFor(
    "backup-ts's LocalAPI socket",
    async () => (await docker("exec", backupTs, "test", "-S", env.TS_SOCKET!).then(() => true)) || undefined,
  );
  const mapped = await waitFor("backup-ts's SOCKS5 publish", async () => {
    const value = await docker("port", backupTs, "1055/tcp");
    return value.match(/:(\d+)\s*$/m)?.[1];
  });
  socksPort = Number(mapped);
  await docker("network", "connect", tailnetNetwork, backupTs);
  backupTsTailnetIp = await docker(
    "inspect",
    "-f",
    `{{(index .NetworkSettings.Networks "${tailnetNetwork}").IPAddress}}`,
    backupTs,
  );
}

// ---- 1. Deployment ------------------------------------------------------------------------------

async function deploymentChecks() {
  console.log("\n[1] deployment: Compose isolation and backup-ts's LocalAPI");
  for (const claim of tailnetComposeClaims(await loadCompose())) check(claim.ok, claim.claim, claim.observed);
  const dockerfile = await Bun.file(join(root, "Dockerfile")).text();
  const uid = await docker("run", "--rm", "--entrypoint", "id", bunImage, "-u", "bun");
  check(
    uid === "1000" && /FROM runtime AS backup-worker[\s\S]*?\nUSER bun\n/.test(dockerfile),
    "the backup worker runs as the image's non-root `bun` user, uid 1000",
    `id -u bun = ${uid}; Dockerfile backup-worker stage ends with USER bun`,
  );
  const volume = `${project}_ark_backup_ts_socket`;
  const probe = `
    const sock = "/var/run/tailscale-backup/tailscaled.sock";
    const call = async (method, path, body) => {
      try {
        const response = await fetch("http://local-tailscaled.sock" + path, { method, unix: sock, body,
          headers: { "Sec-Tailscale": "localapi", ...(body ? { "content-type": "application/json" } : {}) },
          signal: AbortSignal.timeout(5000) });
        return response.status + " " + (await response.text()).replace(/\\s+/g, " ").slice(0, 120);
      } catch (error) { return "error " + (error.code ?? error.name); }
    };
    const out = { uid: process.getuid() };
    out.status = await call("GET", "/localapi/v0/status");
    out.prefsPatch = await call("PATCH", "/localapi/v0/prefs", PATCH_BODY);
    out.prefsPost = await call("POST", "/localapi/v0/prefs", "{}");
    out.start = await call("POST", "/localapi/v0/start", "{}");
    out.logout = await call("POST", "/localapi/v0/logout");
    out.serveConfig = await call("POST", "/localapi/v0/serve-config", "{}");
    out.resetAuth = await call("POST", "/localapi/v0/reset-auth");
    try { await Bun.write("/var/run/tailscale-backup/ark-write-test", "x"); out.mountWrite = "allowed"; }
    catch (error) { out.mountWrite = "refused (" + (error.code ?? error.name) + ")"; }
    console.log(JSON.stringify(out));
  `;
  const probeAs = async (user: string, patchBody: string) =>
    JSON.parse(
      (
        await docker(
          "run",
          "--rm",
          "--user",
          user,
          "--read-only",
          "--tmpfs",
          "/tmp",
          "--cap-drop",
          "ALL",
          "--security-opt",
          "no-new-privileges:true",
          "--volume",
          `${volume}:/var/run/tailscale-backup:ro`,
          bunImage,
          "bun",
          "--eval",
          probe.replace("PATCH_BODY", patchBody),
        )
      )
        .split("\n")
        .at(-1)!,
    ) as Record<string, string>;
  const worker = await probeAs("bun", "JSON.stringify({ ShieldsUpSet: true, ShieldsUp: false })");
  console.log(`      evidence (uid ${worker.uid}, ${volume} mounted :ro): ${JSON.stringify(worker)}`);
  check(
    (worker.status ?? "").startsWith('200 { "Version": "1.86.2') && worker.status!.includes("BackendState"),
    "backup worker uid 1000 reads GET /localapi/v0/status through the read-only mount",
    worker.status ?? "",
  );
  check(
    worker.prefsPatch?.startsWith("403") === true &&
      worker.prefsPost?.startsWith("405") === true &&
      ["start", "logout", "serveConfig", "resetAuth"].every((key) => worker[key]?.startsWith("403")),
    "every LocalAPI write is refused for uid 1000: PATCH /prefs 403, POST /prefs 405, start/logout/serve-config/reset-auth 403",
    `PATCH ${worker.prefsPatch}; POST ${worker.prefsPost}; start ${worker.start}; logout ${worker.logout}; serve-config ${worker.serveConfig}; reset-auth ${worker.resetAuth}`,
  );
  check(
    worker.mountWrite?.startsWith("refused") === true,
    "the socket directory is mounted read-only",
    worker.mountWrite ?? "",
  );
  const control = await probeAs("0:0", '"{}"');
  check(
    control.prefsPatch?.startsWith("200") === true,
    "control: root through the same mount may PATCH /prefs, so the refusals come from tailscaled's uid check",
    `root PATCH /prefs ${control.prefsPatch}`,
  );
  const harness = await bundle(
    join(import.meta.dir, "backup-test", "observe-backup-status.ts"),
    "observe-backup-status",
  );
  const client = JSON.parse(
    (
      await docker(
        "run",
        "--rm",
        "--user",
        "1000:1000",
        "--volume",
        `${volume}:/var/run/tailscale-backup:ro`,
        "--volume",
        `${harness}:/harness:ro`,
        bunImage,
        "bun",
        "/harness/observe-backup-status.js",
        "/var/run/tailscale-backup/tailscaled.sock",
      )
    )
      .split("\n")
      .at(-1)!,
  ) as { backendState?: string; parsed?: { ok: boolean; reason?: string } };
  check(
    client.backendState !== undefined && client.parsed?.ok === false,
    "the production client reads backup-ts as uid 1000; a logged-out node is refused as a partial observation",
    `BackendState ${client.backendState}; parse: ${client.parsed?.reason}`,
  );
}

// ---- In-process control plane --------------------------------------------------------------------

type Offsite = typeof import("../server/src/modules/offsite-backups.ts");
type Coordinator = typeof import("../server/src/coordinator.ts");
let offsite!: Offsite;
let coordinator!: Coordinator;
let sql!: typeof import("../server/src/db.ts").sql;

const self = { id: "nBACKUPTSFD30", name: "ark-backup", ips: ["100.64.0.2"], tags: ["tag:ark-backup"] };
const home = { id: "nHOMEFD30", name: "backup-home", ips: [homeIp] };
const home2 = { id: "nHOME2FD30", name: "backup-home2", ips: [home2Ip] };
const impostor = { id: "nIMPOSTORFD30", name: "backup-home", ips: [homeIp] };

async function observe(validityMs?: number) {
  if (validityMs) process.env.ARK_BACKUP_LEASE_VALIDITY_MS = String(validityMs);
  try {
    const operation = await coordinator.enqueue({
      kind: "backup.observe",
      targetIds: ["tailnet:backup"],
      payload: { at: Date.now() },
    });
    const result = (await coordinator.runOperation("backup.observe", operation)) as { validUntil: string };
    await sql`UPDATE operations SET status = 'succeeded' WHERE id = ${operation.id}`;
    return result;
  } finally {
    delete process.env.ARK_BACKUP_LEASE_VALIDITY_MS;
  }
}

function startExecutor() {
  return Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(request) {
      const action = new URL(request.url).pathname.replace("/v1/", "");
      const stanza = request.headers.get("host")?.startsWith("127.0.0.1") ? "ark-platform" : "ark-app";
      if (action === "stage") {
        const stageId = `${new Date().toISOString().replace(/[-:.]/g, "").slice(0, 15)}Z-${randomBytes(3).toString("hex")}`;
        const directory = join(work, "stages", stanza, stageId);
        await mkdir(join(directory, "repo2", "backup", stanza), { recursive: true });
        await writeFile(join(directory, "repo2", "backup", stanza, "backup.info"), randomBytes(2048));
        const manifest: StageManifest = {
          version: 1,
          stanza,
          stageId,
          createdAt: new Date().toISOString(),
          lastRecoverableAt: new Date(Date.now() - 30_000).toISOString(),
          walSegment: "000000010000000000000009",
          archive: { min: "000000010000000000000001", max: "000000010000000000000009" },
          backups: [],
          repoBytes: 4096,
          pgbackrestVersion: "2.60.0",
        } as StageManifest;
        await writeFile(join(directory, "manifest.json"), JSON.stringify(manifest));
        await workVolume.sync(directory);
        return Response.json({ reused: false, manifest });
      }
      if (action === "status") {
        return Response.json({
          info: { backups: [] },
          archiver: { archiveMode: "on", lastArchivedAt: new Date().toISOString() },
          repoBytes: 4096,
          repoFs: { totalBytes: 100 * 1024 ** 3, freeBytes: 90 * 1024 ** 3 },
          stagingFs: { totalBytes: 100 * 1024 ** 3, freeBytes: 90 * 1024 ** 3 },
          newestStage: { lastRecoverableAt: new Date(Date.now() - 30_000).toISOString(), stageId: "x" },
        });
      }
      return Response.json({ kept: 2, removed: [] });
    },
  });
}

async function startControlPlane() {
  state.control = await startControlDb("fd30");
  state.minio = await startMinio("fd30");
  state.executor = startExecutor();
  const mockSocket = join(tmpdir(), `ark-fd30-${suffix}.sock`);
  Object.assign(process.env, {
    DATABASE_URL: state.control.url,
    ARK_ROOT_KEY: randomBytes(32).toString("base64url"),
    ARK_ROOT_KEY_ID: "k1",
    ARK_RUNTIME_ROLE: "worker",
    ARK_BACKUP_TS_SOCKET: mockSocket,
    ARK_BACKUP_SOCKS5_PROXY: "socks5://backup-ts:1055",
    ARK_TEST_SOCKS5_DIAL: `127.0.0.1:${socksPort}`,
    ARK_RESTIC_BIN: join(import.meta.dir, "backup-test", "restic-docker-tailnet.sh"),
    ARK_TEST_RESTIC_REST_NETWORK: `${project}_backup-tailnet`,
    ARK_TEST_RESTIC_S3_NETWORK: `container:${state.minio.container}`,
    ARK_TEST_RESTIC_WORK: work,
    ARK_TEST_RESTIC_VOLUME: workVolume.volume,
    ARK_TEST_RESTIC_ENV_LOG: join(work, "restic-env.log"),
    ARK_TEST_RESTIC_NAME_PREFIX: `${project}-restic`,
    ARK_RESTIC_PROBE_TIMEOUT_MS: "30000",
    // The Docker CLI in the restic wrapper finds its context under HOME (as in the FD-21 harness).
    ARK_RESTIC_HOME: process.env.HOME ?? "/tmp",
    ARK_PG_STAGE_ROOT: join(work, "stages"),
    ARK_PLATFORM_PG_EXECUTOR_URL: `http://127.0.0.1:${state.executor.port}`,
    ARK_PLATFORM_PG_EXECUTOR_TOKEN: "platform-token-0123456789-abcdef",
    ARK_APP_PG_EXECUTOR_URL: `http://localhost:${state.executor.port}`,
    ARK_APP_PG_EXECUTOR_TOKEN: "app-token-0123456789-abcdef",
  });
  for (const name of PROXY_ENV_NAMES) delete process.env[name];
  offsite = await import("../server/src/modules/offsite-backups.ts");
  coordinator = await import("../server/src/coordinator.ts");
  ({ sql } = await import("../server/src/db.ts"));
  const { MockLocalApi } = await import("../server/src/mock-localapi.ts");
  state.mock = new MockLocalApi({
    backendState: "Running",
    suffix: suffixDns,
    self,
    peers: [home, home2],
    reachable: new Set(),
  });
  await state.mock.listen(mockSocket);
}

// ---- 2. Pinning with disjoint grants ---------------------------------------------------------------

type Target = Awaited<ReturnType<Offsite["saveTailnetRestTarget"]>>;
let homeTarget!: Target;
let s3Target!: Awaited<ReturnType<Offsite["saveS3Target"]>>;

async function pinningChecks() {
  console.log("\n[2] pinning from backup-ts's own observation (disjoint edge and backup grants)");
  const { commitTailnetGeneration } = await import("../server/src/modules/tailnet-snapshot.ts");
  const { mockStatusDocument } = await import("../server/src/mock-localapi.ts");
  // The edge node's view: its own grants reach a route target, never the home backup server.
  const edgeView = parseLocalApiStatus(
    mockStatusDocument({
      backendState: "Running",
      suffix: suffixDns,
      self: { id: "nEDGEFD30", name: "ark-edge", ips: ["100.64.0.1"], tags: ["tag:ark-edge"] },
      peers: [{ id: "nROUTEFD30", name: "web", ips: ["100.64.0.9"] }],
      reachable: new Set(),
    }),
    { generation: "gen_edge_fd30" },
  );
  if (!edgeView.ok) throw new Error(edgeView.reason);
  const now = new Date();
  await commitTailnetGeneration("edge", {
    generation: "gen_edge_fd30",
    self: edgeView.self,
    peers: edgeView.peers,
    completedAt: now,
    validUntil: new Date(now.getTime() + 6 * 60_000),
  });
  const observed = await observe();
  homeTarget = await offsite.saveTailnetRestTarget({
    name: "home",
    restUrl: homeUrl,
    recoveryWindowDays: 30,
    password: restPassword,
    repositoryPassword,
  });
  const edgeNodes = await sql`SELECT stable_id FROM tailnet_nodes WHERE source = 'edge'`;
  check(
    homeTarget.targetNodeStableId === home.id &&
      homeTarget.targetIp === homeIp &&
      !edgeNodes.some((row) => row.stable_id === home.id),
    "the home target pins StableNodeID and address from backup-ts's generation; the edge generation never saw it",
    `pinned ${homeTarget.targetNodeStableId} ${homeTarget.targetIp} from generation valid until ${observed.validUntil}; edge nodes: ${edgeNodes.map((row) => row.stable_id).join(",")}`,
  );
}

// ---- 3. Proxy scoping ---------------------------------------------------------------------------

async function tcpFrom(network: string, host: string, port: number) {
  return docker(
    "run",
    "--rm",
    "--network",
    network,
    bunImage,
    "bun",
    "--eval",
    `const net = require("node:net"); const s = net.connect({ host: ${JSON.stringify(host)}, port: ${port}, timeout: 3000 });
     s.on("connect", () => { console.log("connected"); process.exit(0); });
     s.on("timeout", () => { console.log("timeout"); process.exit(0); });
     s.on("error", (e) => { console.log("error " + (e.code ?? e.message)); process.exit(0); });`,
  );
}

/** True when every named variable was unset in the logged restic environment. */
function unset(line: string | undefined, names: string[]) {
  return names.every((name) => line?.includes(` ${name}=<unset>`));
}

function envLog() {
  return Bun.file(join(work, "restic-env.log"))
    .text()
    .catch(() => "")
    .then((text) => text.split("\n").filter(Boolean));
}

async function proxyChecks() {
  console.log("\n[3] proxy scoping: REST through backup-ts's SOCKS5 only");
  const direct = await tcpFrom(`${project}_backup-tailnet`, homeIp, 8000);
  const fromS3 = await tcpFrom(`container:${state.minio!.container}`, homeIp, 8000);
  check(
    direct.startsWith("error") || direct === "timeout",
    "the backup worker's networks have no direct tailnet route to the home server",
    `backup-tailnet -> ${homeIp}:8000: ${direct}; S3 restic namespace -> ${homeIp}:8000: ${fromS3}`,
  );
  check(fromS3 !== "connected", "the S3 restic namespace cannot reach the home server either", fromS3);
  const socks = await tcpFrom(`${project}_backup-tailnet`, "backup-ts", 1055);
  check(socks === "connected", "backup-ts's SOCKS5 listener answers on backup-tailnet", socks);

  // S3 target (append-only recipe as FD-21) for the "not proxied" side.
  const m = state.minio!;
  await m.mc(["mb", "--with-lock", "ark/fd30"]);
  await m.mc(["retention", "set", "--default", "COMPLIANCE", "2d", "ark/fd30"]);
  const writer = await m.createUser("ark-fd30-writer", "ark-fd30-writer", writerPolicy("fd30", "ark"));
  // The repository protection bucket policy, installed by an administrator as in the FD-21 recipe.
  const { S3Client } = await import("../server/src/modules/s3-client.ts");
  const installed = await new S3Client(
    { endpoint: m.endpoint, region: "us-east-1", bucket: "fd30", pathStyle: true },
    { accessKeyId: m.rootUser, secretAccessKey: m.rootPassword },
  ).request("PUT", undefined, {
    query: { policy: "" },
    body: JSON.stringify(repositoryProtectionPolicy("fd30", "ark")),
  });
  if (installed.status !== 204 && installed.status !== 200)
    throw new Error(`bucket policy not installed: ${installed.status} ${installed.text}`);
  s3Target = await offsite.saveS3Target({
    name: "minio",
    provider: "minio",
    endpoint: m.endpoint,
    region: "us-east-1",
    bucket: "fd30",
    prefix: "ark",
    pathStyle: true,
    recoveryWindowDays: 1,
    accessKeyId: writer.accessKeyId,
    secretAccessKey: writer.secretAccessKey,
    repositoryPassword,
  });

  // A decoy proxy the worker process "inherits": neither subprocess may use or even see it.
  let decoyConnections = 0;
  state.decoy = createServer((socket) => {
    decoyConnections += 1;
    socket.destroy();
  });
  const decoyPort = await new Promise<number>((done) =>
    state.decoy!.listen(0, "127.0.0.1", () => done((state.decoy!.address() as { port: number }).port)),
  );
  const mail = join(work, "mail");
  await mkdir(mail, { recursive: true });
  await writeFile(join(mail, "message.eml"), `Subject: fd30\n\n${randomBytes(4096).toString("hex")}\n`);
  await workVolume.sync(mail);
  const logBefore = (await restLog()).length;
  const decoys = {
    HTTP_PROXY: `http://127.0.0.1:${decoyPort}`,
    HTTPS_PROXY: `http://127.0.0.1:${decoyPort}`,
    ALL_PROXY: `socks5://127.0.0.1:${decoyPort}`,
    NO_PROXY: "*",
    no_proxy: "*",
  };
  Object.assign(process.env, decoys);
  let exported: Awaited<ReturnType<Offsite["exportFiles"]>>;
  try {
    exported = await offsite.exportFiles("mail", mail, ["fd30"]);
  } finally {
    for (const name of Object.keys(decoys)) delete process.env[name];
  }
  check(
    exported.every((item) => !item.error) && exported.length === 2,
    "a mail backup reaches both destinations: S3 directly and home through backup-ts",
    exported.map((item) => `${item.targetId}: ${item.snapshotId ?? item.error}`).join("; "),
  );
  const lines = await envLog();
  const restLine = lines.find((line) => line.startsWith("kind=rest") && line.includes(" backup "));
  const s3Line = lines.find((line) => line.startsWith("kind=s3") && line.includes(" backup "));
  check(
    restLine?.includes(" HTTP_PROXY=socks5://backup-ts:1055 ") === true &&
      unset(restLine, [
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
      ]) &&
      restLine.includes(`-r rest:http://${homeIp}:8000/ark/`),
    "the REST restic subprocess gets exactly HTTP_PROXY=socks5://backup-ts:1055 and the pinned address, with the worker's conflicting proxy variables cleared",
    restLine?.slice(0, 260) ?? "missing",
  );
  check(
    unset(s3Line, [
      "HTTP_PROXY",
      "http_proxy",
      "HTTPS_PROXY",
      "https_proxy",
      "ALL_PROXY",
      "all_proxy",
      "NO_PROXY",
      "no_proxy",
    ]),
    "S3 restic subprocesses get no proxy variable at all, even with HTTP_PROXY/ALL_PROXY/NO_PROXY set on the worker",
    s3Line?.slice(0, 200) ?? "missing",
  );
  check(
    decoyConnections === 0,
    "nothing ever connected to the worker's decoy proxy",
    `${decoyConnections} connections`,
  );
  const requests = (await restLog()).slice(logBefore);
  const sources = [...new Set(requests.map((line) => line.split(" ")[0]))];
  check(
    requests.length > 0 && sources.length === 1 && sources[0] === backupTsTailnetIp,
    "every request rest-server received came from backup-ts (through its SOCKS5 proxy)",
    `${requests.length} requests from ${sources.join(",")}; backup-ts is ${backupTsTailnetIp}`,
  );
  // API/control calls run with the worker's own (proxy-free) environment and are direct.
  let apiSeen = "";
  state.api = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(request, server) {
      apiSeen = server.requestIP(request)?.address ?? "";
      return Response.json({ jobs: [] });
    },
  });
  const leaked = PROXY_ENV_NAMES.filter((name) => process.env[name] !== undefined);
  const response = await fetch(`http://127.0.0.1:${state.api.port}/api/internal/jobs`);
  check(
    leaked.length === 0 && response.ok && /127\.0\.0\.1/.test(apiSeen) && decoyConnections === 0,
    "after REST transfers the worker's environment still has no proxy, and API calls go directly to the API",
    `proxy variables on the worker: ${leaked.join(",") || "none"}; API saw ${apiSeen}`,
  );
}

// ---- 4. Append-only ------------------------------------------------------------------------------

async function snapshotCount(target: Target) {
  const keys = await offsite.targetSecrets(target);
  const listed = await offsite.runRestic(target, keys, ["snapshots", "--json"], 120_000);
  if (listed.status !== 0) throw new Error(`restic snapshots failed: ${listed.stderr}`);
  return (JSON.parse(listed.stdout) as unknown[]).length;
}

async function appendOnlyChecks() {
  console.log("\n[4] append-only home server (canary and V-18)");
  const evidence = await offsite.verifyTarget<RestCanaryEvidence>(homeTarget.id);
  check(
    evidence.status === "append_only",
    "the canary, through backup-ts with the deployed htpasswd credentials, reports append-only: yes",
    `${evidence.status}; ${JSON.stringify(evidence.attempts)}`,
  );
  const negative = await offsite.saveTailnetRestTarget({
    name: "home-not-append-only",
    restUrl: home2Url,
    recoveryWindowDays: 30,
    password: restPassword,
    repositoryPassword,
  });
  const negativeEvidence = await offsite.verifyTarget<RestCanaryEvidence>(negative.id);
  check(
    negativeEvidence.status === "deletable",
    "a rest-server without --append-only is reported deletable",
    negativeEvidence.findings.map((item) => item.message).join(" | "),
  );
  await sql`UPDATE backup_targets SET enabled = false WHERE id = ${negative.id}`;
  const s3Evidence = await offsite.verifyTarget(s3Target.id);
  check(s3Evidence.status === "append_only", "the S3 target's canary also passes", s3Evidence.status);

  // More snapshots, so `forget --keep-last 1` has something to remove.
  const exported = await offsite.exportTarget(homeTarget.id, { fresh: true });
  check(
    exported.sources.every((item) => item.ok),
    "both PostgreSQL stages export to the home target through the production exporter",
    exported.sources
      .map((item) => `${item.source}: ${"snapshotId" in item ? item.snapshotId : item.error}`)
      .join("; "),
  );
  const before = await snapshotCount(homeTarget);
  const keys = await offsite.targetSecrets(homeTarget);
  // One group (forget groups by host and paths by default), so forget really tries to remove two.
  const forget = await offsite.runRestic(
    homeTarget,
    keys,
    ["forget", "--group-by", "", "--keep-last", "1", "--prune"],
    120_000,
  );
  const after = await snapshotCount(homeTarget);
  const locks = await docker("exec", homeServer, "ls", "-A", "/data/ark/locks");
  const refusal = `${forget.stderr}\n${forget.stdout}`
    .split("\n")
    .find((line) => /403|forbidden/i.test(line));
  check(
    forget.status !== 0 && before >= 3 && after === before && locks === "",
    "`restic forget --group-by '' --keep-last 1 --prune` from the VPS removes nothing and no stale locks remain (V-18)",
    `forget exit ${forget.status} (${refusal?.trim().slice(0, 160) ?? "no 403 line"}); snapshots ${before} -> ${after}; locks/ empty`,
  );
}

// ---- 5. Identity and freshness during transfers -------------------------------------------------------

async function runningResticContainers() {
  const { stdout } = await runtime.dockerOutput("ps", "--quiet", "--filter", `name=^/${project}-restic-`);
  return stdout.split("\n").filter(Boolean);
}

async function guardedTransfer(change: "replaced" | "removed" | "expired") {
  await observe(change === "expired" ? 12_000 : undefined);
  const directory = join(work, `bulk-${change}`);
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, "bulk.bin"), randomBytes(24 * 1024 * 1024));
  await workVolume.sync(directory);
  process.env.ARK_TEST_RESTIC_LIMIT_UPLOAD = "512";
  const before = (await restLog()).length;
  const started = Date.now();
  const running = offsite.exportFiles(`volume:guard-${change}`, directory, []);
  // The transfer is active once restic holds its lock on the home repository.
  await waitFor("the REST transfer to start", async () =>
    (await restLog()).slice(before).some((line) => line.includes("POST /ark/locks/")) ? true : undefined,
  );
  await Bun.sleep(1_500);
  let changedAt: number;
  if (change === "replaced") {
    state.mock!.state.peers = [impostor, home2];
    await observe();
    changedAt = Date.now();
  } else if (change === "removed") {
    state.mock!.state.peers = [home2];
    await observe();
    changedAt = Date.now();
  } else {
    const [row] = await sql`SELECT valid_until FROM tailnet_snapshots WHERE source = 'backup'`;
    changedAt = new Date(row!.valid_until).getTime();
  }
  const outcome = await running;
  const stoppedAt = Date.now();
  delete process.env.ARK_TEST_RESTIC_LIMIT_UPLOAD;
  const mine = outcome.find((item) => item.targetId === homeTarget.id);
  const left = await runningResticContainers();
  const countAtStop = (await restLog()).length;
  await Bun.sleep(2_500);
  const countLater = (await restLog()).length;
  check(
    Boolean(mine?.error?.match(/transfer watchdog|Transfer stopped/)) &&
      stoppedAt - changedAt < TRANSFER_STOP_BOUND_MS &&
      left.length === 0 &&
      countLater === countAtStop,
    `identity ${change}: the active REST transfer stops within ${TRANSFER_STOP_BOUND_MS / 1000} s, restic is gone and rest-server sees no further request`,
    `${stoppedAt - changedAt} ms after the ${change === "expired" ? "lease ran out" : "new generation committed"} (transfer ran ${Math.round((changedAt - started) / 1000)} s); restic containers left: ${left.length}; ${mine?.error?.slice(0, 120)}`,
  );
}

async function freshnessChecks() {
  console.log("\n[5] identity and freshness: active transfers stop, new transfers fail");
  await sql`UPDATE backup_targets SET enabled = false WHERE id = ${s3Target.id}`;
  try {
    for (const change of ["replaced", "removed", "expired"] as const) {
      state.mock!.state.peers = [home, home2];
      await guardedTransfer(change);
    }
    // The lease has expired and nothing observes: a new transfer must not even reach rest-server.
    const before = (await restLog()).length;
    const refused = await offsite.exportFiles("volume:after-expiry", join(work, "mail"), []);
    const refusedHome = refused.find((item) => item.targetId === homeTarget.id);
    await Bun.sleep(500);
    check(
      Boolean(refusedHome?.error?.includes("not started")) && (await restLog()).length === before,
      "with the observation expired, a new transfer fails before contacting rest-server",
      refusedHome?.error?.slice(0, 160) ?? "no result",
    );
    let exportError = "";
    await offsite.exportTarget(homeTarget.id).catch((error: Error) => (exportError = error.message));
    check(
      exportError.includes("not started"),
      "a scheduled PostgreSQL export to the home target fails the same way, recording failed attempts",
      exportError.slice(0, 160),
    );
    await offsite.evaluateBackupAlerts();
    const [alert] = await sql`
      SELECT severity, title FROM alerts WHERE dedup_key = ${`backup-tailnet:${homeTarget.id}`} AND resolved_at IS NULL`;
    check(
      alert?.severity === "critical",
      "the suspension raises a critical alert at once",
      alert?.title ?? "none",
    );
  } finally {
    state.mock!.state.peers = [home, home2];
    await sql`UPDATE backup_targets SET enabled = true WHERE id = ${s3Target.id}`;
  }
}

// ---- 6. Health -----------------------------------------------------------------------------------

async function healthChecks() {
  console.log("\n[6] health: both destinations required");
  await observe();
  await offsite.exportTarget(homeTarget.id, { fresh: true });
  await offsite.exportTarget(s3Target.id, { fresh: true });
  let health = await offsite.evaluateBackupAlerts();
  check(
    Boolean(health?.healthy),
    "with both targets fresh and append-only, backups are healthy",
    health?.reasons.join("; ") || "no reasons",
  );
  for (const [stale, other] of [
    [homeTarget.id, s3Target.id],
    [s3Target.id, homeTarget.id],
  ] as const) {
    await sql`UPDATE backup_targets SET last_success_at = now() - interval '40 hours' WHERE id = ${stale}`;
    health = await offsite.evaluateBackupAlerts();
    const [alert] = await sql`
      SELECT severity FROM alerts WHERE dedup_key = ${`backup-target-stale:${stale}`} AND resolved_at IS NULL`;
    check(
      health?.healthy === false &&
        health.targets.find((item) => item.id === stale)?.healthy === false &&
        health.targets.find((item) => item.id === other)?.healthy === true &&
        Boolean(alert),
      `the ${stale === homeTarget.id ? "home" : "S3"} target stale: backups unhealthy and an alert fires`,
      health?.reasons.join("; ").slice(0, 200) ?? "",
    );
    await sql`UPDATE backup_targets SET last_success_at = now() WHERE id = ${stale}`;
  }
  health = await offsite.evaluateBackupAlerts();
  check(
    Boolean(health?.healthy),
    "healthy again once both are fresh (alerts resolve)",
    health?.reasons.join("; ") || "no reasons",
  );
}

// ---- Runner ---------------------------------------------------------------------------------------

let failed = false;
try {
  console.log(`FD-30 tailnet backups (${project})`);
  await runtime.docker(
    "network",
    "create",
    "--subnet",
    `100.${octet}.${third}.0/24`,
    "--label",
    "ark.test=fd30-backups",
    tailnetNetwork,
  );
  runtime.networkCreated = true;
  await Promise.all([
    startRestServer(homeServer, homeIp, true),
    startRestServer(home2Server, home2Ip, false),
  ]);
  await startBackupTs();
  workVolume = await createWorkVolume(runtime, project, work);
  await deploymentChecks();
  await startControlPlane();
  await pinningChecks();
  await proxyChecks();
  await appendOnlyChecks();
  await freshnessChecks();
  await healthChecks();
  console.log(`\nAll ${results.length} FD-30 checks passed.`);
} catch (error) {
  failed = true;
  console.error(`\n${(error as Error).stack ?? error}`);
  await runtime.dumpLogs();
} finally {
  state.mock?.stop();
  state.executor?.stop(true);
  state.api?.stop(true);
  state.decoy?.close();
  await sql?.end().catch(() => undefined);
  const leftovers = await runtime
    .dockerOutput("ps", "--all", "--quiet", "--filter", `name=^/${project}-restic-`)
    .then(({ stdout }) => stdout.split("\n").filter(Boolean))
    .catch(() => [] as string[]);
  if (leftovers.length) await runtime.dockerOutput("rm", "--force", ...leftovers).catch(() => undefined);
  await state.minio?.stop();
  await state.control?.stop();
  await runtime.cleanup();
  removeSignalHandlers();
}
if (failed) process.exit(1);
