// `mise run test:edge-tailnet`: the FD-05 checks that need a real tailnet (docs/design/front-door.md
// §5 FD-05). Opt-in, because CI has no tailnet; it skips cleanly without ARK_TEST_TS_EDGE_AUTHKEY.
// Setup and the expected policy are in docs/operating.md ("Edge Tailscale node").
//
//   ARK_TEST_TS_EDGE_AUTHKEY   required: pre-approved key tagged tag:ark-edge (ephemeral for tests)
//   ARK_TEST_TS_PEER_AUTHKEY   optional: pre-approved key for a test peer (ephemeral), allowed by the
//                              policy to reach tag:ark-edge:80, with no grant from tag:ark-edge to it
//   ARK_TEST_TS_GRANTED_PORT   optional: a TCP port on the test peer that the policy grants to
//                              tag:ark-edge (FD-06 probe pass); 8080 must stay ungranted
//   ARK_TEST_TS_UDP_PORT       optional: host port published for 41642/udp (default 41642)
//   ARK_TEST_TS_REQUIRE_DIRECT optional: 1 fails the run when only a DERP path is found
//
// It starts the shipped edge-ts and edge services (scripts/edge-test/stack.ts) with the real control
// plane and checks: the node joins as tag:ark-edge and tailscale0 is in the edge's namespace; with no
// grant the edge cannot open TCP to a tailnet peer; with --shields-up a peer cannot connect to the edge
// node; UDP 41642 is published and a direct path is reported when the network allows it. Every node it
// enrols is logged out at the end.
//
// FD-06 (edge observer): the production LocalAPI client reads a complete generation as the domain
// worker's uid through the read-only socket mount; a peer that appears in status (it may reach the
// edge) but whose port is not granted fails the edge-netns TCP probe, so its route would stay
// `awaiting_acl`; with ARK_TEST_TS_GRANTED_PORT, granting that exact port makes the probe pass.
import { randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { EdgeTestRuntime } from "./edge-test/runtime.ts";
import { startEdgeStack } from "./edge-test/stack.ts";
import { verifyShieldsUp } from "./edge-test/shields-up.ts";
import { bunImage } from "./test-images.ts";

const edgeKey = process.env.ARK_TEST_TS_EDGE_AUTHKEY?.trim() ?? "";
if (!edgeKey) {
  console.log(
    "SKIP test:edge-tailnet: ARK_TEST_TS_EDGE_AUTHKEY is not set. These checks need a real tailnet and a " +
      'pre-approved tag:ark-edge key; see docs/operating.md, "Edge Tailscale node". Everything that does ' +
      "not need a tailnet runs in `mise run test:edge`.",
  );
  process.exit(0);
}
const peerKey = process.env.ARK_TEST_TS_PEER_AUTHKEY?.trim() ?? "";
const grantedPort = Number(process.env.ARK_TEST_TS_GRANTED_PORT ?? "") || 0;
const udpPort = Number(process.env.ARK_TEST_TS_UDP_PORT ?? "41642");
const requireDirect = process.env.ARK_TEST_TS_REQUIRE_DIRECT === "1";

const root = resolve(import.meta.dir, "..");
const tailscaleImage =
  "tailscale/tailscale:v1.86.2@sha256:241d9518b7e0b6e533dbd0117fcea15acb4174249210837f52b71615949ce9d2";
const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const directory = await mkdtemp(join(tmpdir(), `ark-edge-tailnet-${suffix}-`));
const runtime = new EdgeTestRuntime(directory, `ark-edge-tailnet-${suffix}`);
const removeSignalHandlers = runtime.installSignalHandlers();
const docker = (...args: string[]) => runtime.docker(...args);
const enrolled: string[] = [];
const lines: string[] = [];
const warnings: string[] = [];

function check(condition: boolean, claim: string, observed: string) {
  if (!condition) throw new Error(`FAILED: ${claim} (observed: ${observed})`);
  lines.push(`  ok  ${claim} [${observed}]`);
  console.log(lines.at(-1));
}

function warn(claim: string, observed: string) {
  warnings.push(`  WARN ${claim} [${observed}]`);
  console.log(warnings.at(-1));
}

async function waitFor<T>(what: string, attempt: () => Promise<T | undefined>, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await attempt().catch(() => undefined);
    if (value !== undefined) return value;
    await Bun.sleep(1_000);
  }
  throw new Error(`Timed out after ${timeoutMs} ms waiting for ${what}.`);
}

type Status = {
  BackendState: string;
  Self: { HostName: string; DNSName: string; TailscaleIPs?: string[]; Tags?: string[]; ID: string };
  Peer?: Record<string, { HostName: string; TailscaleIPs?: string[]; CurAddr?: string; Relay?: string }>;
};

type Observation = {
  backendState?: string;
  statusError?: string;
  parsed?: {
    ok: boolean;
    reason?: string;
    self?: { tags: string[] };
    peers?: Array<{ stableId: string; ipv4: string | null }>;
  };
  probe?: { ok: boolean; detail: string };
};

let observeHarness: string | undefined;
/** The production LocalAPI client and parser, as uid 1000 through the read-only socket mount (FD-06). */
async function observeAndProbe(project: string, ip: string, port: number): Promise<Observation> {
  if (!observeHarness) {
    const outdir = join(directory, "observe-status");
    const built = await Bun.build({
      entrypoints: [join(import.meta.dir, "edge-test", "observe-status.ts")],
      target: "bun",
      outdir,
    });
    if (!built.success) throw new Error(`Bundling observe-status.ts failed: ${built.logs.join("\n")}`);
    await chmod(directory, 0o755);
    await chmod(outdir, 0o755);
    observeHarness = outdir;
  }
  const output = await docker(
    "run",
    "--rm",
    "--user",
    "1000:1000",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--volume",
    `${project}_ark_edge_ts_socket:/var/run/tailscale:ro`,
    "--volume",
    `${observeHarness}:/harness:ro`,
    bunImage,
    "bun",
    "/harness/observe-status.js",
    "/var/run/tailscale/tailscaled.sock",
    ip,
    String(port),
  );
  return JSON.parse(output.split("\n").at(-1)!) as Observation;
}

function tailscale(container: string, ...args: string[]) {
  return docker("exec", container, "tailscale", "--socket=/var/run/tailscale/tailscaled.sock", ...args);
}

async function running(container: string) {
  return waitFor(`${container} to join the tailnet`, async () => {
    const status = JSON.parse(await tailscale(container, "status", "--json")) as Status;
    return status.BackendState === "Running" && status.Self.TailscaleIPs?.length ? status : undefined;
  });
}

async function tcp(container: string, host: string, port: number) {
  return docker("exec", container, "nc", "-z", "-w", "5", host, String(port)).then(
    () => "connected",
    () => "no connection",
  );
}

function ipv4(status: Status) {
  return status.Self.TailscaleIPs!.find((ip) => ip.includes("."))!;
}

let failed = false;
try {
  const acme = join(directory, "acme");
  const certs = join(directory, "certs");
  await mkdir(join(acme, ".well-known", "acme-challenge"), { recursive: true });
  await mkdir(certs);
  await Bun.write(join(acme, ".well-known", "acme-challenge", "tailnet-token"), "tailnet-token.key-auth");
  const edgeDir = join(directory, "edge");
  await mkdir(edgeDir);
  await Bun.write(join(edgeDir, "Caddyfile"), await Bun.file(join(root, "infra/platform/Caddyfile")).text());

  // Compose interpolates TS_AUTHKEY from this process's environment; the key is never written to disk.
  process.env.TS_EDGE_AUTHKEY = edgeKey;
  const stack = await startEdgeStack({
    runtime,
    project: `ark-edge-tailnet-${suffix}`,
    directory,
    acmeDir: acme,
    certDir: certs,
    edgeDir,
    ports: ["127.0.0.1::80", "127.0.0.1::443", `${udpPort}:41642/udp`],
  });
  enrolled.push(stack.edgeTs);

  // 1. Enrolment and kernel mode.
  const edge = await running(stack.edgeTs);
  check(
    JSON.stringify(edge.Self.Tags ?? []) === '["tag:ark-edge"]',
    "edge-ts joins as tag:ark-edge and nothing else",
    `${edge.Self.DNSName} tags ${JSON.stringify(edge.Self.Tags)}`,
  );
  const edgeIp = ipv4(edge);
  const links = await docker("exec", stack.edge, "cat", "/proc/net/dev");
  const address = await docker("exec", stack.edgeTs, "ip", "-4", "-o", "addr", "show", "tailscale0");
  check(
    /^\s*tailscale0:/m.test(links) && address.includes(edgeIp),
    "tailscale0 carries the node's address in the namespace edge runs in",
    address.replace(/\s+/g, " ").trim(),
  );
  const netfilter = await docker("exec", stack.edgeTs, "iptables", "-S", "ts-input").then(
    (rules) => `${rules.split("\n").length} ts-input rules`,
    (error: Error) => `missing: ${error.message.split("\n")[0]}`,
  );
  const logs = await runtime.dockerOutput("logs", stack.edgeTs);
  check(
    netfilter.includes("rules") && !/can't initialize ip6?tables/.test(logs.stdout + logs.stderr),
    "tailscaled installed its netfilter rules (NET_ADMIN + NET_RAW suffice)",
    netfilter,
  );
  const prefs = JSON.parse(await tailscale(stack.edgeTs, "debug", "prefs")) as Record<string, unknown>;
  check(
    prefs.ShieldsUp === true && prefs.CorpDNS === false,
    "shields up, MagicDNS off",
    `ShieldsUp ${prefs.ShieldsUp}, CorpDNS ${prefs.CorpDNS}`,
  );
  const port80 = await stack.hostPort(80);
  const challenge = await fetch(`http://127.0.0.1:${port80}/.well-known/acme-challenge/tailnet-token`);
  check(
    challenge.status === 200 && (await challenge.text()) === "tailnet-token.key-auth",
    "edge serves the :80 ACME challenge from the edge-ts namespace",
    `HTTP ${challenge.status}`,
  );

  // FD-06: a complete generation through the read-only LocalAPI, as the domain worker reads it.
  const generation = await observeAndProbe(stack.project, "100.64.0.1", 9);
  check(
    generation.parsed?.ok === true && JSON.stringify(generation.parsed.self?.tags) === '["tag:ark-edge"]',
    "edge.observe's client reads a complete generation as uid 1000 through the :ro socket mount",
    `BackendState ${generation.backendState}; ${generation.parsed?.peers?.length ?? 0} peer(s); self tags ${JSON.stringify(generation.parsed?.self?.tags)}`,
  );

  // 2. UDP 41642.
  const mapping = await docker("port", stack.edgeTs, "41642/udp");
  const sockets = await docker("exec", stack.edgeTs, "ss", "-lunp");
  check(
    mapping.includes(`:${udpPort}`) && /:41642\s.*tailscaled/.test(sockets),
    "tailscaled listens on UDP 41642 and edge-ts publishes it",
    `${mapping.split("\n")[0]}`,
  );

  // 3. Grants and shields-up, against a peer this script enrols.
  if (!peerKey) {
    const peers = Object.values(edge.Peer ?? {});
    warn(
      "ARK_TEST_TS_PEER_AUTHKEY is not set: skipped the edge -> peer, peer -> edge and direct-path checks",
      `edge sees ${peers.length} peer(s)`,
    );
  } else {
    const peer = `ark-edge-tailnet-peer-${suffix}`;
    runtime.containers.push(peer);
    await docker(
      "run",
      "--detach",
      "--name",
      peer,
      "--hostname",
      `ark-edge-test-peer-${suffix.slice(-8)}`,
      "--cap-drop",
      "ALL",
      "--cap-add",
      "NET_ADMIN",
      "--cap-add",
      "NET_RAW",
      "--device",
      "/dev/net/tun:/dev/net/tun",
      "--env",
      "TS_USERSPACE=false",
      "--env",
      "TS_ACCEPT_DNS=false",
      "--env",
      "TS_STATE_DIR=/var/lib/tailscale",
      "--env",
      "TS_SOCKET=/var/run/tailscale/tailscaled.sock",
      "--env",
      `TS_AUTHKEY=${peerKey}`,
      tailscaleImage,
    );
    enrolled.push(peer);
    const peerStatus = await running(peer);
    const peerIp = ipv4(peerStatus);
    await docker("exec", "--detach", peer, "nc", "-lk", "-p", "8080", "-e", "/bin/echo", "peer-ok");

    const self = await tcp(peer, peerIp, 8080);
    check(self === "connected", "control: the peer's TCP 8080 listener answers on its tailnet address", self);
    const outbound = await tcp(stack.edgeTs, peerIp, 8080);
    check(
      outbound === "no connection",
      "with no grant, the edge namespace cannot open TCP to a tailnet peer",
      `edge -> ${peerIp}:8080 ${outbound}`,
    );

    // FD-06: present in status (the peer may reach the edge) but not granted on 8080, so the
    // edge-netns probe through LocalAPI dial fails and the route would stay awaiting_acl.
    const ungranted = await waitFor("the peer in the edge node's status", async () => {
      const observed = await observeAndProbe(stack.project, peerIp, 8080);
      return observed.parsed?.peers?.some((item) => item.ipv4 === peerIp) ? observed : undefined;
    });
    check(
      ungranted.probe?.ok === false,
      "a peer present in status whose port is not granted fails the edge-netns probe (route stays awaiting_acl)",
      `${peerIp}:8080 probe: ${ungranted.probe?.detail}`,
    );
    if (grantedPort) {
      await docker(
        "exec",
        "--detach",
        peer,
        "nc",
        "-lk",
        "-p",
        String(grantedPort),
        "-e",
        "/bin/echo",
        "peer-ok",
      );
      const granted = await waitFor(
        `the probe to ${peerIp}:${grantedPort}; grant tag:ark-edge tcp:${grantedPort} on the test peer`,
        async () => {
          const observed = await observeAndProbe(stack.project, peerIp, grantedPort);
          return observed.probe?.ok ? observed : undefined;
        },
        60_000,
      );
      check(
        true,
        "granting that exact port makes the edge-netns probe pass (route becomes ready)",
        `${peerIp}:${grantedPort} probe: ${granted.probe?.detail}`,
      );
    } else {
      warn(
        "ARK_TEST_TS_GRANTED_PORT is not set: skipped the granted-port probe pass",
        "probe pass UNVERIFIED",
      );
    }

    const local = await tcp(stack.edgeTs, edgeIp, 80);
    check(local === "connected", "control: Caddy listens on the edge node's tailnet address", local);
    await verifyShieldsUp({
      setShieldsUp: (enabled) => tailscale(stack.edgeTs, "set", `--shields-up=${enabled}`),
      connect: () => tcp(peer, edgeIp, 80),
      waitUntilConnected: () =>
        waitFor(
          "the peer to connect to edge TCP 80 with shields-up disabled; grant the peer tag:ark-edge:80",
          async () => ((await tcp(peer, edgeIp, 80)) === "connected" ? true : undefined),
          30_000,
        ),
    });
    check(
      true,
      "peer connects with shields-up disabled and is refused after shields-up is restored",
      `peer -> ${edgeIp}:80 positive and negative controls passed`,
    );
    const ping = await tailscale(peer, "ping", "-c", "30", "--until-direct", edgeIp).catch(
      (error: Error) => error.message,
    );
    const direct = /via (?!DERP)[^\s]+:\d+/.test(ping);
    const last = ping.trim().split("\n").findLast(Boolean) ?? ping;
    if (direct) check(true, "a direct WireGuard path to the edge node is reported", last);
    else if (requireDirect) check(false, "a direct WireGuard path to the edge node is reported", last);
    else warn("only a DERP path was found; the network may not allow a direct one", last);
  }
  console.log(
    `\n${peerKey ? "All tailnet checks passed" : "Partial tailnet checks passed; peer-dependent checks UNVERIFIED"}${warnings.length ? ` with ${warnings.length} warning(s)` : ""}.`,
  );
} catch (error) {
  failed = true;
  console.error(`\n${(error as Error).message}`);
  await runtime.dumpLogs();
} finally {
  for (const container of enrolled) {
    await tailscale(container, "logout").catch(() => undefined);
  }
  await runtime.cleanup();
  removeSignalHandlers();
}
if (failed) process.exit(1);
