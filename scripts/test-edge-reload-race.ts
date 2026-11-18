// `mise run test:edge-reload` (also part of `mise run test:edge`): HAProxy master-CLI reload safety
// (docs/design/front-door.md §3.8.6, FD-25) against the pinned edge-l4 image and the shipped launch
// guard, in disposable containers. No Compose stack, watchdog, Caddy or Python is needed.
//
// The race being fixed: HAProxy's master re-executes as soon as it parses a `reload` and answers only
// the connection that sent it. Every other master-CLI connection it had accepted is closed with no
// reply, and a second `reload` on one of them is never executed. The launch guard's reopen reload and
// the domain worker's `edge.l4_apply` reload used to meet like that, failing the apply with "the
// master CLI did not answer the reload" although HAProxy ended up on the right configuration.
//
// edge-l4 runs as in production (uid 99, group 4400, read-only root, no capabilities, the guard as its
// entrypoint), with the configuration root (uid 1000, 2750) and the `ark_haproxy_run` socket tmpfs
// (uid 99, group 4400, 2770, holding `reload.lock`) as Docker tmpfs volumes. The domain worker's side
// is scripts/edge-test/reload-race-probe.ts in the pinned Bun image as uid 1000, in two containers.
//
// Covered:
// - serialised: a publisher (installEdgeL4Generation, alternating two generations), a second reloader
//   (HaproxyMaster.reload) and the launch guard's own locked reload, each sending ROUNDS reloads at the
//   same time: every request is answered Success=1, every publication is served with its version, and
//   the master's reload count advances by exactly the number of requests (none was dropped);
// - recovered: a publisher against a reloader that ignores the lock (the pre-fix behaviour): every
//   publication still ends confirmed, served with its version, with no "did not answer" failure;
// - real failures stay failures: an invalid configuration answers Success=0, the installer reports
//   it, restores `current`, and the old worker keeps serving the previous version, both alone and while
//   the unlocked reloader runs.
//
// `ARK_EDGE_RELOAD_ROUNDS` sets ROUNDS (default 50).
import { randomBytes } from "node:crypto";
import { chmod, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { EdgeTestRuntime } from "./edge-test/runtime.ts";

const root = resolve(import.meta.dir, "..");
const haproxyImage =
  "haproxy:3.2.26-alpine@sha256:1c3568e520453cc8ba98c39501febcf450429c80e6cc27ecad779961d76e597c";
const bunImage =
  "oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61";
const rounds = Number(process.env.ARK_EDGE_RELOAD_ROUNDS ?? 50);
if (!Number.isInteger(rounds) || rounds < 1)
  throw new Error("ARK_EDGE_RELOAD_ROUNDS must be a positive integer");

const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const project = `ark-edge-reload-${suffix}`;
const directory = await mkdtemp(join(tmpdir(), `${project}-`));
const runtime = new EdgeTestRuntime(directory, `${project}-unused`, bunImage);
// Volumes carry the project label so the runtime removes them (and only them) at cleanup.
runtime.composeProjects.push(project);
const removeSignalHandlers = runtime.installSignalHandlers();
const docker = (...args: string[]) => runtime.docker(...args);
const label = ["--label", `com.docker.compose.project=${project}`];
const volumes = { config: `${project}_edge_l4`, run: `${project}_haproxy_run` };
const edgeL4 = `${project}-edge-l4`;
const publisher = `${project}-publisher`;
const reloader = `${project}-reloader`;
const guard = "/usr/local/bin/ark-edge-l4-launch-guard";
const hammerStop = "/run/ark-l4/stop-hammer";

type Report = { name: string; lines: string[] };

function expect(report: Report, condition: boolean, claim: string, observed: string) {
  if (!condition) throw new Error(`[${report.name}] FAILED: ${claim} (observed: ${observed})`);
  report.lines.push(`  ok  ${claim} [${observed}]`);
}

async function waitFor<T>(what: string, attempt: () => Promise<T | undefined>, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await attempt().catch(() => undefined);
    if (value !== undefined) return value;
    await Bun.sleep(200);
  }
  throw new Error(`Timed out after ${timeoutMs} ms waiting for ${what}.`);
}

type Proc = {
  reloads: number;
  failed: number;
  workers: Array<{ pid: number; section: string; version: string | null }>;
  serving: Array<string | null>;
  error?: string;
};
type Publish = {
  rounds: number;
  succeeded: number;
  failures: Array<{ round: number; error?: string }>;
  confirmedByWorkers: number;
  retried: number;
  requests: number;
  maxMs: number;
  error?: string;
};
type Reload = {
  rounds: number;
  succeeded: number;
  answered: number;
  failures: unknown[];
  requests: number;
  error?: string;
};
type Invalid = {
  installed: boolean;
  error: string;
  restored: boolean;
  previousVersion: string;
  before: Proc;
  after: Proc;
};

async function probe<T>(container: string, ...args: string[]) {
  const output = await docker("exec", container, "bun", "/probe/reload-race-probe.js", ...args);
  const result = JSON.parse(output.split("\n").at(-1) ?? "{}") as T & { error?: string };
  return result;
}

async function proc() {
  const result = await probe<Proc>(publisher, "proc");
  if (result.error) throw new Error(result.error);
  return result;
}

/** The domain worker's identity and mounts (as in scripts/test-edge-l4.ts). */
function workerArgs(name: string, bundle: string) {
  return [
    "--detach",
    "--name",
    name,
    ...label,
    "--user",
    "1000:1000",
    "--group-add",
    "4400",
    "--read-only",
    "--tmpfs",
    "/tmp",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges:true",
    "--network",
    "none",
    "--env",
    "HOME=/tmp",
    "--env",
    "ARK_EDGE_L4_DIR=/usr/local/etc/haproxy",
    "--env",
    "ARK_HAPROXY_MASTER_SOCKET=/var/run/haproxy/master.sock",
    "--volume",
    `${volumes.config}:/usr/local/etc/haproxy`,
    "--volume",
    `${volumes.run}:/var/run/haproxy`,
    "--volume",
    `${bundle}:/probe:ro`,
    "--workdir",
    "/tmp",
    bunImage,
    "sleep",
    "3600",
  ];
}

async function setup() {
  const outdir = join(directory, "probe");
  const built = await Bun.build({
    entrypoints: [join(import.meta.dir, "edge-test/reload-race-probe.ts")],
    target: "bun",
    outdir,
  });
  if (!built.success) throw new Error(`Bundling the reload probe failed: ${built.logs.join("\n")}`);
  await chmod(outdir, 0o755);
  // As in infra/platform/docker-compose.yml (ark_haproxy_run) and the installer's tmp/edge-l4 modes.
  await docker(
    "volume",
    "create",
    ...label,
    "--driver",
    "local",
    "--opt",
    "type=tmpfs",
    "--opt",
    "device=tmpfs",
    "--opt",
    "o=uid=1000,gid=4400,mode=2750,size=16m",
    volumes.config,
  );
  await docker(
    "volume",
    "create",
    ...label,
    "--driver",
    "local",
    "--opt",
    "type=tmpfs",
    "--opt",
    "device=tmpfs",
    "--opt",
    "o=uid=99,gid=4400,mode=2770,size=1m",
    volumes.run,
  );
  for (const name of [publisher, reloader]) {
    runtime.containers.push(name);
    await docker("run", ...workerArgs(name, outdir));
  }
  const seeded = await probe<{ generation: string; marked: boolean }>(publisher, "seed");
  if (seeded.error || !seeded.marked) throw new Error(`seed failed: ${JSON.stringify(seeded)}`);
  runtime.containers.push(edgeL4);
  await docker(
    "run",
    "--detach",
    "--name",
    edgeL4,
    ...label,
    "--group-add",
    "4400",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges:true",
    // No peer is needed: HAProxy only has to bind and serve its master CLI. IPv6 for `:::443 v4v6`.
    "--network",
    "none",
    "--sysctl",
    "net.ipv6.conf.all.disable_ipv6=0",
    "--tmpfs",
    "/run/ark-l4:rw,noexec,nosuid,nodev,size=64k,uid=99,gid=99,mode=0700",
    "--env",
    "ARK_EDGE_L4_DIR=/usr/local/etc/haproxy",
    "--env",
    "ARK_HAPROXY_MASTER_SOCKET=/var/run/haproxy/master.sock",
    "--env",
    "ARK_EDGE_WATCHDOG_URL=http://127.0.0.1:9",
    "--volume",
    `${volumes.config}:/usr/local/etc/haproxy:ro`,
    "--volume",
    `${join(root, "infra/platform/edge-l4-launch-guard.sh")}:${guard}:ro`,
    "--volume",
    `${volumes.run}:/var/run/haproxy`,
    "--entrypoint",
    "/bin/sh",
    haproxyImage,
    guard,
  );
  const started = await waitFor("HAProxy's master CLI", async () => {
    const result = await probe<Proc>(publisher, "proc");
    return !result.error && result.serving.length ? result : undefined;
  });
  return { seeded, started };
}

/** The launch guard's locked reload, run by the shipped script itself, `count` times. */
async function guardReloads(count: number) {
  let succeeded = 0;
  const failures: string[] = [];
  for (let index = 0; index < count; index++) {
    const answer = await docker("exec", edgeL4, "/bin/sh", guard, "reload").catch(
      (error: Error) => `error: ${error.message}`,
    );
    if (/^Success=1$/m.test(answer)) succeeded++;
    else failures.push(answer.slice(0, 200));
  }
  return { succeeded, failures };
}

/** A reloader that ignores the lock (as both reloaders did before), until stopped. */
function startHammer() {
  const script = `rm -f ${hammerStop}; sent=0; lost=0
while [ ! -e ${hammerStop} ]; do
  answer="$(echo reload | socat -t 30 - UNIX-CONNECT:/var/run/haproxy/master.sock 2>&1 || true)"
  sent=$((sent + 1))
  case "$answer" in *Success=*) ;; *) lost=$((lost + 1)) ;; esac
done
echo "$sent $lost"`;
  const child = Bun.spawn(["docker", "exec", edgeL4, "/bin/sh", "-c", script], {
    stdout: "pipe",
    stderr: "pipe",
  });
  return async () => {
    await docker("exec", edgeL4, "touch", hammerStop);
    const [output] = await Promise.all([new Response(child.stdout).text(), child.exited]);
    const [sent = 0, lost = 0] = output.trim().split(/\s+/).map(Number);
    return { sent, lost };
  };
}

async function serialisedTest(report: Report) {
  const before = await proc();
  const started = Date.now();
  const [published, reloaded, guarded] = await Promise.all([
    probe<Publish>(publisher, "publish", String(rounds)),
    probe<Reload>(reloader, "reload", String(rounds)),
    guardReloads(rounds),
  ]);
  const seconds = ((Date.now() - started) / 1000).toFixed(1);
  const after = await proc();
  expect(
    report,
    !published.error && published.succeeded === rounds && published.failures.length === 0,
    `${rounds} publications racing a second reloader and the launch guard all succeed, each served with its version`,
    `${published.succeeded}/${rounds} in ${seconds} s, slowest ${published.maxMs} ms${published.failures.length ? `; ${JSON.stringify(published.failures.slice(0, 3))}` : ""}${published.error ? `; ${published.error}` : ""}`,
  );
  expect(
    report,
    !reloaded.error && reloaded.succeeded === rounds && reloaded.answered === rounds,
    `the second reloader's ${rounds} reloads are each answered Success=1`,
    `${reloaded.answered}/${rounds} answered${reloaded.error ? `; ${reloaded.error}` : ""}`,
  );
  expect(
    report,
    guarded.succeeded === rounds,
    `the launch guard's ${rounds} locked reloads are each answered Success=1`,
    `${guarded.succeeded}/${rounds}${guarded.failures.length ? `; ${guarded.failures.slice(0, 2).join(" | ")}` : ""}`,
  );
  const requests = published.requests + reloaded.requests + rounds;
  expect(
    report,
    published.confirmedByWorkers === 0 &&
      published.retried === 0 &&
      after.reloads - before.reloads === requests &&
      after.failed === before.failed,
    "under the shared lock no reply is lost: the master ran exactly one reload per request",
    `${after.reloads - before.reloads} master reloads for ${requests} requests; ${published.confirmedByWorkers} confirmed from workers; failed ${before.failed} -> ${after.failed}`,
  );
}

async function recoveredTest(report: Report) {
  const stop = startHammer();
  let published: Publish;
  let hammer = { sent: 0, lost: 0 };
  try {
    // Let the unlocked reloader get going before the publications start.
    await Bun.sleep(300);
    published = await probe<Publish>(publisher, "publish", String(rounds));
  } finally {
    hammer = await stop();
  }
  expect(
    report,
    !published.error && published.succeeded === rounds && published.failures.length === 0,
    `${rounds} publications against a reloader that ignores the lock all end confirmed and served, with no "did not answer" failure`,
    `${published.succeeded}/${rounds}, slowest ${published.maxMs} ms${published.failures.length ? `; ${JSON.stringify(published.failures.slice(0, 3))}` : ""}${published.error ? `; ${published.error}` : ""}`,
  );
  expect(
    report,
    hammer.lost > 0 || published.confirmedByWorkers > 0 || published.retried > 0,
    "the race was exercised: replies were lost and recovered by version confirmation or a resend",
    `unlocked reloader: ${hammer.lost}/${hammer.sent} unanswered; publisher: ${published.confirmedByWorkers} confirmed from the serving worker, ${published.retried} resent`,
  );
  // Settle: the hammer's last reload may still be starting its worker.
  await waitFor("the master CLI after the unlocked reloader", async () =>
    (await proc()).serving.length ? true : undefined,
  );
}

async function invalidTest(report: Report) {
  const alone = await probe<Invalid>(publisher, "invalid");
  const serving = alone.before.workers.find((worker) => worker.section === "current");
  const kept = alone.after.workers.find((worker) => worker.pid === serving?.pid);
  expect(
    report,
    !alone.installed &&
      /Success=0|old workers keep serving/.test(alone.error) &&
      alone.restored &&
      alone.after.failed === alone.before.failed + 1 &&
      Boolean(kept) &&
      kept?.version === alone.previousVersion,
    "an invalid configuration answers Success=0, is reported as failed and the old worker keeps serving the previous version",
    `${alone.error.slice(0, 90)}; failed reloads ${alone.before.failed} -> ${alone.after.failed}; worker ${serving?.pid} still ${kept?.section ?? "gone"}`,
  );
  const stop = startHammer();
  let raced: Invalid;
  let hammer = { sent: 0, lost: 0 };
  try {
    await Bun.sleep(300);
    raced = await probe<Invalid>(publisher, "invalid");
  } finally {
    hammer = await stop();
  }
  const settled = await waitFor("a serving worker after the unlocked reloader", async () => {
    const state = await proc();
    return state.serving.length ? state : undefined;
  });
  expect(
    report,
    !raced.installed &&
      raced.error.length > 0 &&
      raced.restored &&
      settled.serving.every((version) => version === raced.previousVersion),
    "racing an unlocked reloader, an invalid configuration is still reported as failed and the previous version keeps serving",
    `${raced.error.slice(0, 90)}; unlocked reloader ${hammer.lost}/${hammer.sent} unanswered; serving ${settled.serving.map((version) => version?.slice(0, 12)).join(",")}`,
  );
}

async function run(name: string, test: (report: Report) => Promise<void>) {
  const report: Report = { name, lines: [] };
  const started = Date.now();
  await test(report);
  console.log(`${name} (${((Date.now() - started) / 1000).toFixed(1)} s)\n${report.lines.join("\n")}`);
}

let failed = false;
try {
  console.log(`edge-l4 reload safety on ${haproxyImage.split("@")[0]}, ${rounds} rounds:`);
  const { started } = await setup();
  console.log(`  edge-l4 serving ${started.serving[0]?.slice(0, 12)} (master reloads ${started.reloads})`);
  await run("concurrent reloads under the shared lock", serialisedTest);
  await run("lost replies recovered from the serving worker", recoveredTest);
  await run("an invalid configuration still fails (FD-25)", invalidTest);
  console.log("\nAll edge-l4 reload safety tests passed.");
} catch (error) {
  failed = true;
  console.error(`\n${(error as Error).stack ?? error}`);
  await runtime.dumpLogs();
} finally {
  removeSignalHandlers();
  await runtime.cleanup();
}
process.exit(failed ? 1 : 0);
