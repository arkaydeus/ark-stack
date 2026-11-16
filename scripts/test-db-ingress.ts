// `mise run test:db-ingress`: runtime tests of the public database port ruleset, `inet
// ark_db_ingress` (docs/design/front-door.md §3.11, FD-18), in a privileged Linux container.
//
// 1. Renders the ruleset with the production renderer (`nftAllowlist`) at the defaults, at small
//    test limits, and with an allowlist, and checks every file with `nft -c`.
// 2. In the container, builds client, host and backend network namespaces and checks with real
//    TCP connections, on both the `input` hook (host listener) and the `forward` hook (DNAT):
//    the per-source concurrent-connection cap, the per-source new-connection rate, /64 grouping
//    for IPv6, the allowlist, and the named drop counters.
// 3. Feeds the kernel's counter JSON through `parseNftCounters` and `dbIngressCounterMetrics`,
//    the code behind /api/metrics/prometheus.
// 4. Runs the real `scripts/database-ingress.ts` reconciler against a rendered file and checks its
//    status file and counter snapshot.
// 5. Checks `infra/monitoring/alerts.yml` with promtool, including unit tests of the drop alert.
//
// Needs Docker with privileged containers (Docker Desktop or a Linux host). No Python.
import { randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import {
  DB_INGRESS_LIMIT_DEFAULTS,
  dbIngressCounterMetrics,
  nftAllowlist,
  parseNftCounters,
  type DbIngressCounterSnapshot,
} from "@ark-stack/shared";

// Same pin as the Dockerfile runtime stage, which the database-ingress image builds on.
const bunImage =
  "oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61";
// Same pin as infra/monitoring/docker-compose.yml.
const prometheusImage =
  "prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996";
const testImage = "ark-db-ingress-test:local";
const root = resolve(import.meta.dir, "..");
const fixtures = join(import.meta.dir, "db-ingress-test");

// Small limits make the behaviour observable with a handful of connections.
const TEST_CONN = 5;
const TEST_RATE = 2;
const TEST_BURST = 5;

const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const directory = await mkdtemp(join(tmpdir(), `ark-db-ingress-${suffix}-`));
const containers: string[] = [];
let failures = 0;

async function docker(args: string[], options: { stdin?: string; allowFailure?: boolean } = {}) {
  const child = Bun.spawn(["docker", ...args], {
    stdin: options.stdin === undefined ? "ignore" : new TextEncoder().encode(options.stdin),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (status !== 0 && !options.allowFailure) {
    throw new Error(`docker ${args[0]} failed (${status}): ${(stderr || stdout).trim().slice(-4000)}`);
  }
  return { status, stdout, stderr };
}

async function cleanup() {
  if (containers.length) await docker(["rm", "--force", ...containers], { allowFailure: true });
  await rm(directory, { recursive: true, force: true });
}

for (const [signal, code] of [
  ["SIGINT", 130],
  ["SIGTERM", 143],
] as const) {
  process.on(signal, () => void cleanup().finally(() => process.exit(code)));
}

function limits(conn: number, rate: number, burst: number) {
  return { maxConnectionsPerSource: conn, newConnectionsPerSecond: rate, newConnectionBurst: burst };
}

function check(condition: boolean, claim: string, observed: string) {
  if (!condition) failures++;
  console.log(`  ${condition ? "ok  " : "FAIL"}  ${claim} [${observed}]`);
}

function section(title: string) {
  console.log(`\n== ${title}`);
}

try {
  // ------------------------------------------------------------------ 1. render and check
  section("Rendered rulesets");
  const rules = join(directory, "rules");
  await mkdir(rules, { recursive: true });
  const files: Record<string, string> = {
    "defaults.nft": nftAllowlist([], 5432),
    "defaults-allowlist.nft": nftAllowlist(["198.51.100.0/24", "2001:db8:100::/48"], 5432),
    "conn.nft": nftAllowlist([], 5432, limits(TEST_CONN, 1000, 1000)),
    "rate.nft": nftAllowlist([], 5432, limits(1000, TEST_RATE, TEST_BURST)),
    "allowlist.nft": nftAllowlist(["10.10.0.3/32", "2001:db8:10:2::/64"], 5432, limits(1000, 1000, 1000)),
  };
  for (const [name, content] of Object.entries(files)) await writeFile(join(rules, name), content);
  console.log(
    `Default limits: ${DB_INGRESS_LIMIT_DEFAULTS.maxConnectionsPerSource} concurrent, ${DB_INGRESS_LIMIT_DEFAULTS.newConnectionsPerSecond}/second burst ${DB_INGRESS_LIMIT_DEFAULTS.newConnectionBurst}. Rendered defaults.nft:\n`,
  );
  console.log(files["defaults.nft"].trimEnd());

  // ------------------------------------------------------------------ 2. the container
  section(`Building ${testImage} (${bunImage.split("@")[0]} + nftables + iproute2)`);
  await docker(["build", "--quiet", "-t", testImage, "-"], {
    stdin: `FROM ${bunImage}
RUN apt-get update \\
  && apt-get install -y --no-install-recommends nftables iproute2 \\
  && rm -rf /var/lib/apt/lists/*
`,
  });
  console.log("  built");

  section("Runtime checks in a privileged container");
  const name = `ark-db-ingress-${suffix}`;
  containers.push(name);
  const run = await docker(
    [
      "run",
      "--name",
      name,
      "--privileged",
      "--network",
      "none",
      "-e",
      `ARK_DB_INGRESS_TEST_CONN=${TEST_CONN}`,
      "-e",
      `ARK_DB_INGRESS_TEST_BURST=${TEST_BURST}`,
      "-v",
      `${rules}:/rules:ro`,
      "-v",
      `${fixtures}:/t:ro`,
      testImage,
      "bun",
      "/t/inside.ts",
    ],
    { allowFailure: true },
  );
  const output = run.stdout.split("\n");
  for (const line of output) {
    if (!line.startsWith("@@counters ")) console.log(line);
  }
  if (run.stderr.trim()) console.error(run.stderr.trimEnd());
  check(run.status === 0, "every in-container check passed", `exit ${run.status}`);

  // ------------------------------------------------------------------ 3. counters -> metrics
  section("Kernel counters through parseNftCounters and dbIngressCounterMetrics");
  const expected: Record<string, string[]> = {
    "input-concurrent": ['reason="concurrent",family="ipv4"', 'reason="concurrent",family="ipv6"'],
    "input-rate": ['reason="rate",family="ipv4"', 'reason="rate",family="ipv6"'],
    "input-allowlist": ['chain="ark_db_allow",reason="allowlist",family="any"'],
    "forward-concurrent": ['reason="concurrent",family="ipv4"', 'reason="concurrent",family="ipv6"'],
    "forward-rate": ['reason="rate",family="ipv4"', 'reason="rate",family="ipv6"'],
  };
  const snapshots = new Map<string, DbIngressCounterSnapshot>();
  for (const line of output.filter((item) => item.startsWith("@@counters "))) {
    const [, label, ...json] = line.split(" ");
    snapshots.set(label, parseNftCounters(json.join(" ")));
  }
  for (const [label, needles] of Object.entries(expected)) {
    const snapshot = snapshots.get(label);
    check(Boolean(snapshot), `${label}: counter snapshot captured`, snapshot ? "present" : "missing");
    if (!snapshot) continue;
    const metrics = dbIngressCounterMetrics(snapshot);
    for (const needle of needles) {
      const line = metrics.find((item) => item.includes(needle));
      const value = Number(line?.split(" ").at(-1));
      check(value > 0, `${label}: ark_nft_drop_packets_total{${needle}} > 0`, line ?? "missing");
    }
  }
  const sample = snapshots.get("forward-concurrent");
  if (sample) {
    console.log("\nSample /api/metrics/prometheus lines (forward-concurrent):");
    for (const line of dbIngressCounterMetrics(sample)) console.log(`  ${line}`);
  }

  // ------------------------------------------------------------------ 4. the real reconciler
  section("scripts/database-ingress.ts applies the file and exports counters");
  const state = join(directory, "state");
  await mkdir(join(state, "pgbouncer"), { recursive: true });
  await mkdir(join(state, "metrics"), { recursive: true });
  await chmod(state, 0o777);
  await writeFile(join(state, "pgbouncer", "allowlist.nft"), files["defaults-allowlist.nft"]);
  await writeFile(join(state, "pgbouncer", "expose"), "0\n");
  // Bundle the reconciler with its @ark-stack/shared imports: host node_modules may link into a
  // global cache outside the repository, so it cannot simply be mounted into the container.
  const bundle = join(directory, "bundle");
  const built = await Bun.build({
    entrypoints: [join(root, "scripts", "database-ingress.ts")],
    outdir: bundle,
    target: "bun",
  });
  if (!built.success) throw new Error(`bundling database-ingress.ts failed: ${built.logs.join("\n")}`);
  const reconcilerName = `ark-db-ingress-reconciler-${suffix}`;
  containers.push(reconcilerName);
  const reconciler = await docker(
    [
      "run",
      "--name",
      reconcilerName,
      "--privileged",
      "--network",
      "none",
      "-e",
      "ARK_PGBOUNCER_DIR=/state/pgbouncer",
      "-e",
      "ARK_DB_INGRESS_METRICS_DIR=/state/metrics",
      "-e",
      "ARK_DB_INGRESS_COUNTER_INTERVAL_MS=500",
      "-v",
      `${bundle}:/bundle:ro`,
      "-v",
      `${state}:/state`,
      testImage,
      "sh",
      "-c",
      "timeout 4 bun /bundle/database-ingress.js; cat /state/pgbouncer/allowlist.status; echo '---'; cat /state/metrics/counters.json",
    ],
    { allowFailure: true },
  );
  const [statusText = "", countersText = ""] = reconciler.stdout.split("---\n");
  console.log(statusText.trimEnd().replace(/^/gm, "  "));
  check(
    statusText.includes("applied=true") && statusText.includes("enforced=true"),
    "status file reports applied=true, enforced=true for an allowlist",
    statusText.replace(/\n/g, " ").trim() || reconciler.stderr.trim().slice(-500),
  );
  let snapshot: unknown = null;
  try {
    snapshot = JSON.parse(countersText);
  } catch {
    snapshot = null;
  }
  const metrics = dbIngressCounterMetrics(snapshot);
  check(
    metrics.includes('ark_nft_counters_present{table="ark_db_ingress"} 1'),
    "counters.json is a readable snapshot of all five named counters",
    `${(snapshot as DbIngressCounterSnapshot | null)?.counters?.length ?? 0} counters`,
  );
  check(
    (snapshot as DbIngressCounterSnapshot | null)?.counters?.length === 5,
    "the snapshot includes drop_allowlist alongside the four limit counters",
    countersText.trim().slice(0, 300),
  );

  // ------------------------------------------------------------------ 5. alert rules
  section("infra/monitoring/alerts.yml (promtool)");
  for (const args of [
    ["check", "rules", "/monitoring/alerts.yml"],
    ["test", "rules", "/tests/alerts.test.yml"],
  ]) {
    const result = await docker(
      [
        "run",
        "--rm",
        "--entrypoint",
        "promtool",
        "-v",
        `${join(root, "infra", "monitoring")}:/monitoring:ro`,
        "-v",
        `${fixtures}:/tests:ro`,
        prometheusImage,
        ...args,
      ],
      { allowFailure: true },
    );
    check(
      result.status === 0,
      `promtool ${args.slice(0, 2).join(" ")}`,
      (result.stdout + result.stderr).trim().replace(/\s+/g, " ").slice(0, 400),
    );
  }
} finally {
  await cleanup();
}

console.log(failures ? `\n${failures} check(s) failed.` : "\nAll database ingress checks passed.");
process.exit(failures ? 1 : 0);
