// `mise run test:backups-tailnet-live`: the FD-30 checks that need a real tailnet (docs/design/
// front-door.md §5 FD-30). Opt-in, because CI has no tailnet: without the keys below it prints a skip
// message and exits 0. Everything that does not need a tailnet runs in `mise run test:backups-tailnet`.
//
//   ARK_TEST_TS_BACKUP_AUTHKEY  required: pre-approved, ephemeral key tagged tag:ark-backup
//   ARK_TEST_TS_HOME_AUTHKEY    required: pre-approved, ephemeral key for the test home machine (no
//                               tag:ark-* tag)
//   ARK_TEST_TS_EDGE_AUTHKEY    optional: pre-approved, ephemeral key tagged tag:ark-edge, for the live
//                               "edge cannot reach the home backup server" deny check
//   ARK_TEST_TS_POLICY_API_KEY  optional: API token (policy_file:read) to validate the generated snippet
//                               for this exact home machine with POST /acl/validate (never written)
//   ARK_TEST_TS_TAILNET         optional: tailnet name for the API (default "-")
//
// The scratch tailnet's policy must hold only what Ark generates for the home target (Front door ACL,
// or the snippet this script prints): `tag:ark-backup` -> the home machine on tcp:8000, and no grant
// from `tag:ark-edge` to it. It starts the shipped backup-ts service (real containerboot login,
// userspace, SOCKS5), a home node running `rest-server --append-only --private-repos` in its netns and
// a listener on an ungranted port, then drives the production code: backup-ts's status read as uid 1000
// through the read-only socket mount, pinning, a backup through backup-ts's SOCKS5 proxy, the
// append-only canary, and `restic forget` refused. Every node it enrols is logged out at the end.
import { randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { generateTailnetAcl, PROXY_ENV_NAMES } from "@ark-stack/shared";

import type { RestCanaryEvidence } from "../server/src/modules/rest-canary.ts";
import { startControlDb, testNetworkBase, type ControlDb } from "./backup-test/harness.ts";
import { REST_SERVER_IMAGE } from "./backup-test/minio.ts";
import { composePath } from "./backup-test/tailnet-compose.ts";
import { createWorkVolume } from "./backup-test/work-volume.ts";
import { EdgeTestRuntime } from "./edge-test/runtime.ts";

const backupKey = process.env.ARK_TEST_TS_BACKUP_AUTHKEY?.trim() ?? "";
const homeKey = process.env.ARK_TEST_TS_HOME_AUTHKEY?.trim() ?? "";
if (!backupKey || !homeKey) {
  console.log(
    "SKIP test:backups-tailnet-live: ARK_TEST_TS_BACKUP_AUTHKEY and ARK_TEST_TS_HOME_AUTHKEY are not both set. " +
      "These checks need a scratch tailnet with pre-approved tag:ark-backup and home-machine keys; see " +
      'docs/guides/backups.md, "Home machine over the tailnet". Everything that does not need a tailnet ' +
      "runs in `mise run test:backups-tailnet`.",
  );
  process.exit(0);
}
const edgeKey = process.env.ARK_TEST_TS_EDGE_AUTHKEY?.trim() ?? "";
const policyKey = process.env.ARK_TEST_TS_POLICY_API_KEY?.trim() ?? "";
const tailnetName = process.env.ARK_TEST_TS_TAILNET?.trim() || "-";

const tailscaleImage =
  "tailscale/tailscale:v1.86.2@sha256:241d9518b7e0b6e533dbd0117fcea15acb4174249210837f52b71615949ce9d2";
const bunImage =
  "oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61";
const suffix = randomBytes(4).toString("hex");
const project = `ark-fd30-live-${suffix}`;
const work = await mkdtemp(join(tmpdir(), `${project}-`));
await chmod(work, 0o755);
const runtime = new EdgeTestRuntime(work, `${project}-unused`);
const removeSignalHandlers = runtime.installSignalHandlers();
const docker = (...args: string[]) => runtime.docker(...args);
const restPassword = randomBytes(18).toString("base64url");
const repositoryPassword = randomBytes(24).toString("base64url");
const enrolled: string[] = [];

function check(condition: unknown, claim: string, observed: string): asserts condition {
  if (!condition) throw new Error(`FAILED: ${claim} (observed: ${observed})`);
  console.log(`  ok  ${claim} [${observed}]`);
}

async function waitFor<T>(what: string, attempt: () => Promise<T | undefined>, timeoutMs = 120_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await attempt().catch(() => undefined);
    if (value !== undefined) return value;
    await Bun.sleep(1_000);
  }
  throw new Error(`Timed out after ${timeoutMs} ms waiting for ${what}.`);
}

type Status = {
  BackendState?: string;
  Self?: { ID?: string; DNSName?: string; TailscaleIPs?: string[]; Tags?: string[] };
};

async function cliStatus(container: string, socket = "/var/run/tailscale/tailscaled.sock") {
  return JSON.parse(
    await docker("exec", container, "tailscale", `--socket=${socket}`, "status", "--json"),
  ) as Status;
}

/** A userspace tailnet node; `extra` services join its namespace and receive its inbound tailnet TCP. */
async function startNode(name: string, key: string, hostname: string) {
  runtime.containers.push(name);
  await docker(
    "run",
    "--detach",
    "--name",
    name,
    "--label",
    "ark.test=fd30-live",
    "--hostname",
    hostname,
    "--env",
    "TS_USERSPACE=true",
    "--env",
    `TS_AUTHKEY=${key}`,
    "--env",
    "TS_STATE_DIR=/var/lib/tailscale",
    "--env",
    "TS_ACCEPT_DNS=false",
    "--env",
    "TS_SOCKS5_SERVER=:1055",
    tailscaleImage,
  );
  enrolled.push(name);
  return waitFor(`${name} to join the tailnet`, async () => {
    const status = await cliStatus(name);
    return status.BackendState === "Running" && status.Self?.TailscaleIPs?.length ? status : undefined;
  });
}

/** TCP through a node's SOCKS5 proxy, from a container in that node's namespace. */
async function socksConnect(namespace: string, host: string, port: number) {
  const script = `const net = require("node:net");
    const s = net.connect({ host: "127.0.0.1", port: 1055 });
    const ip = ${JSON.stringify(host)}.split(".").map(Number);
    let stage = 0;
    const timer = setTimeout(() => { console.log("timeout"); process.exit(0); }, 8000);
    s.on("connect", () => s.write(Buffer.from([5, 1, 0])));
    s.on("data", (d) => {
      if (stage === 0) { stage = 1; s.write(Buffer.from([5, 1, 0, 1, ...ip, ${port} >> 8, ${port} & 255])); return; }
      clearTimeout(timer); console.log(d[1] === 0 ? "connected" : "refused " + d[1]); process.exit(0);
    });
    s.on("error", (e) => { console.log("error " + (e.code ?? e.message)); process.exit(0); });`;
  return docker("run", "--rm", "--network", `container:${namespace}`, bunImage, "bun", "--eval", script);
}

const state: { control?: ControlDb } = {};
const backupTs = `${project}-backup-ts-1`;
let failed = false;
try {
  console.log(`FD-30 live tailnet checks (${project})`);
  // 1. The home machine: rest-server --append-only --private-repos in the node's namespace, plus an
  //    ungranted listener on 2222.
  const homeNode = `${project}-home`;
  const home = await startNode(homeNode, homeKey, `ark-fd30-home-${suffix}`);
  const homeIp = home.Self!.TailscaleIPs!.find((ip) => ip.includes("."))!;
  const homeName = home.Self!.DNSName!.replace(/\.$/, "");
  const htpasswd = join(work, "htpasswd");
  const hash = (await Bun.password.hash(restPassword, { algorithm: "bcrypt", cost: 4 })).replace(
    /^\$2[ab]\$/,
    "$2y$",
  );
  await writeFile(htpasswd, `ark:${hash}\n`);
  await chmod(htpasswd, 0o644);
  runtime.containers.push(`${project}-rest`, `${project}-other`);
  await docker(
    "run",
    "--detach",
    "--name",
    `${project}-rest`,
    "--network",
    `container:${homeNode}`,
    "--tmpfs",
    "/data:rw,size=512m",
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
    "--append-only",
  );
  await docker(
    "run",
    "--detach",
    "--name",
    `${project}-other`,
    "--network",
    `container:${homeNode}`,
    bunImage,
    "bun",
    "--eval",
    `Bun.listen({ hostname: "0.0.0.0", port: 2222, socket: { open(s) { s.end("hello\\n"); }, data() {} } }); setInterval(() => {}, 1e9);`,
  );

  // 2. The shipped backup-ts service with a real login.
  const base = await testNetworkBase();
  const document = Bun.YAML.parse(await Bun.file(composePath).text()) as {
    networks: Record<string, { external?: boolean } | null>;
  };
  const external = Object.entries(document.networks)
    .filter(([, value]) => value?.external)
    .map(([name]) => name);
  const required = [
    ...new Set(
      [...(await Bun.file(composePath).text()).matchAll(/\$\{([A-Z0-9_]+):\?/g)].map((match) => match[1]),
    ),
  ];
  const envFile = join(work, "compose.env");
  await Bun.write(
    envFile,
    [...required.map((name) => `${name}=fd30-live-unused`), `TS_BACKUP_AUTHKEY=${backupKey}`].join("\n") +
      "\n",
  );
  const overrideFile = join(work, "override.yml");
  await Bun.write(
    overrideFile,
    [
      "services:",
      "  backup-ts:",
      `    ports: ["127.0.0.1::1055"]`,
      "networks:",
      "  backup-tailnet:",
      `    ipam: { config: [{ subnet: "${base}.0/26" }] }`,
      "  backup-ts-egress:",
      `    ipam: { config: [{ subnet: "${base}.64/26" }] }`,
      ...external.flatMap((name) => [`  ${name}:`, "    external: false", `    name: ${project}_${name}`]),
      "",
    ].join("\n"),
  );
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
  enrolled.push(backupTs);
  const backup = await waitFor("backup-ts to join as tag:ark-backup", async () => {
    const status = await cliStatus(backupTs);
    return status.BackendState === "Running" ? status : undefined;
  });
  check(
    backup.Self?.Tags?.includes("tag:ark-backup"),
    "backup-ts joined the tailnet as tag:ark-backup",
    JSON.stringify(backup.Self?.Tags),
  );

  // 3. The generated snippet for this exact home machine, and the policy it expects.
  const snippet = generateTailnetAcl({
    routes: [],
    backupTargets: [
      {
        id: "bkt_live",
        name: "home",
        ip: homeIp,
        port: 8000,
        stableId: home.Self!.ID!,
        targetName: homeName,
      },
    ],
    tailnet: null,
  });
  console.log(`\nExpected tailnet policy (the only grant to the home machine):\n${snippet.hujson}\n`);
  if (policyKey) {
    const response = await fetch(
      `https://api.tailscale.com/api/v2/tailnet/${encodeURIComponent(tailnetName)}/acl/validate`,
      {
        method: "POST",
        headers: { authorization: `Bearer ${policyKey}`, "content-type": "application/hujson" },
        body: snippet.hujson,
        signal: AbortSignal.timeout(30_000),
      },
    );
    const text = (await response.text()).trim();
    check(
      response.ok && (!text || text === "{}"),
      "Tailscale validates the generated snippet and its tests",
      text || `${response.status}`,
    );
  }

  // 4. Production code in-process: observation (uid 1000, read-only mount), pinning, backup, canary.
  state.control = await startControlDb("fd30-live");
  const workVolume = await createWorkVolume(runtime, project, work);
  const socksPort = Number((await docker("port", backupTs, "1055/tcp")).match(/:(\d+)\s*$/m)?.[1]);
  for (const name of PROXY_ENV_NAMES) delete process.env[name];
  Object.assign(process.env, {
    DATABASE_URL: state.control.url,
    ARK_ROOT_KEY: randomBytes(32).toString("base64url"),
    ARK_RUNTIME_ROLE: "worker",
    ARK_BACKUP_SOCKS5_PROXY: "socks5://backup-ts:1055",
    ARK_TEST_SOCKS5_DIAL: `127.0.0.1:${socksPort}`,
    ARK_RESTIC_BIN: join(import.meta.dir, "backup-test", "restic-docker-tailnet.sh"),
    ARK_RESTIC_HOME: process.env.HOME ?? "/tmp",
    ARK_TEST_RESTIC_REST_NETWORK: `${project}_backup-tailnet`,
    ARK_TEST_RESTIC_S3_NETWORK: "none",
    ARK_TEST_RESTIC_WORK: work,
    ARK_TEST_RESTIC_VOLUME: workVolume.volume,
    ARK_TEST_RESTIC_NAME_PREFIX: `${project}-restic`,
    ARK_RESTIC_PROBE_TIMEOUT_MS: "60000",
  });
  const observer = await import("../server/src/modules/backup-observe.ts");
  const offsite = await import("../server/src/modules/offsite-backups.ts");
  // backup-ts's own status, read as the backup worker's uid 1000 through the read-only socket mount.
  const readStatus = async () => {
    const raw = await docker(
      "run",
      "--rm",
      "--user",
      "1000:1000",
      "--volume",
      `${project}_ark_backup_ts_socket:/var/run/tailscale-backup:ro`,
      bunImage,
      "bun",
      "--eval",
      `const r = await fetch("http://local-tailscaled.sock/localapi/v0/status", { unix: "/var/run/tailscale-backup/tailscaled.sock", headers: { "Sec-Tailscale": "localapi" } });
       if (!r.ok) throw new Error("status " + r.status);
       console.log(await r.text());`,
    );
    return JSON.parse(raw) as unknown;
  };
  const observed = await waitFor("backup-ts to see the home machine", async () => {
    const result = await observer.observeBackupTailnet({ api: { status: readStatus } });
    return result.peers > 0 ? result : undefined;
  });
  const target = await offsite.saveTailnetRestTarget({
    name: "home",
    restUrl: `http://${homeName}:8000/ark`,
    recoveryWindowDays: 30,
    password: restPassword,
    repositoryPassword,
  });
  check(
    target.targetNodeStableId === home.Self!.ID && target.targetIp === homeIp,
    "the home target pins the home machine from backup-ts's own observation",
    `${target.targetNodeStableId} ${target.targetIp} (generation of ${observed.peers} peers)`,
  );
  const data = join(work, "data");
  await mkdir(data, { recursive: true });
  await writeFile(join(data, "payload.bin"), randomBytes(1024 * 1024));
  await workVolume.sync(data);
  const exported = await offsite.exportFiles("volume:fd30-live", data, []);
  check(
    exported.length === 1 && !exported[0]!.error,
    "a backup reaches the home rest-server through backup-ts with only the tag:ark-backup -> home:8000 grant",
    exported[0]?.snapshotId ?? exported[0]?.error ?? "no result",
  );
  const evidence = await offsite.verifyTarget<RestCanaryEvidence>(target.id);
  check(
    evidence.status === "append_only",
    "the append-only canary passes over the tailnet",
    JSON.stringify(evidence.attempts),
  );
  // Make retention select an actual snapshot for deletion (disable grouping explicitly).
  await writeFile(join(data, "payload.bin"), randomBytes(1024 * 1024));
  await workVolume.sync(data);
  const second = await offsite.exportFiles("volume:fd30-live", data, []);
  check(
    second.length === 1 && !second[0]!.error,
    "a second distinct snapshot exists before forget",
    second[0]?.error ?? "",
  );
  const keys = await offsite.targetSecrets(target);
  const before = await offsite.runRestic(target, keys, ["snapshots", "--json"], 180_000);
  const beforeIds = (JSON.parse(before.stdout) as { id: string }[]).map((snapshot) => snapshot.id).toSorted();
  check(
    before.status === 0 && beforeIds.length >= 2,
    "forget fixture has at least two snapshots",
    `${beforeIds.length}`,
  );
  const forget = await offsite.runRestic(
    target,
    keys,
    ["forget", "--keep-last", "1", "--group-by", "", "--prune"],
    180_000,
  );
  const listed = await offsite.runRestic(target, keys, ["snapshots", "--json"], 180_000);
  const afterIds = (JSON.parse(listed.stdout) as { id: string }[]).map((snapshot) => snapshot.id).toSorted();
  check(
    forget.status !== 0 &&
      /403|forbidden|not allowed/i.test(forget.stderr) &&
      listed.status === 0 &&
      JSON.stringify(afterIds) === JSON.stringify(beforeIds),
    "`restic forget` attempts snapshot deletion, is refused, and leaves every snapshot intact",
    `forget exit ${forget.status}: ${forget.stderr}`,
  );

  // 5. Deny checks: the backup node reaches no other port; the edge node reaches nothing there.
  const ungranted = await socksConnect(backupTs, homeIp, 2222);
  check(ungranted !== "connected", "backup-ts cannot reach an ungranted port on the home machine", ungranted);
  if (edgeKey) {
    const edgeNode = `${project}-edge`;
    const edge = await startNode(edgeNode, edgeKey, `ark-fd30-edge-${suffix}`);
    check(
      edge.Self?.Tags?.includes("tag:ark-edge"),
      "the test edge node joined as tag:ark-edge",
      JSON.stringify(edge.Self?.Tags),
    );
    const denied = await socksConnect(edgeNode, homeIp, 8000);
    check(denied !== "connected", "the edge node cannot reach the home backup server on tcp:8000", denied);
  } else {
    console.log(
      "  skip live edge deny check: ARK_TEST_TS_EDGE_AUTHKEY is not set (the snippet's deny tests still cover it)",
    );
  }
  console.log("\nAll FD-30 live tailnet checks passed.");
} catch (error) {
  failed = true;
  console.error(`\n${(error as Error).stack ?? error}`);
  await runtime.dumpLogs();
} finally {
  for (const node of enrolled)
    await runtime.dockerOutput("exec", node, "tailscale", "logout").catch(() => undefined);
  const leftovers = await runtime
    .dockerOutput("ps", "--all", "--quiet", "--filter", `name=^/${project}-restic-`)
    .then(({ stdout }) => stdout.split("\n").filter(Boolean))
    .catch(() => [] as string[]);
  if (leftovers.length) await runtime.dockerOutput("rm", "--force", ...leftovers).catch(() => undefined);
  await (await import("../server/src/db.ts").catch(() => null))?.sql.end().catch(() => undefined);
  await state.control?.stop();
  await runtime.cleanup();
  removeSignalHandlers();
}
if (failed) process.exit(1);
