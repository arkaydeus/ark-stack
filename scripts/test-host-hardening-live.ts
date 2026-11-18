// Run only with an explicitly supplied scratch VPS and an approved scratch-tailnet owner identity.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createSocket } from "node:dgram";
import { mkdtemp, stat } from "node:fs/promises";
import { isIP } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { EdgeTestRuntime } from "./edge-test/runtime.ts";
import { auditExternal, readExternalInventory } from "./host-audit-external.ts";

const required = [
  "ARK_TEST_VPS_IPV4",
  "ARK_TEST_VPS_IPV6",
  "ARK_TEST_VPS_INVENTORY",
  "ARK_TEST_VPS_SSH_ADDRESS",
  "ARK_TEST_VPS_SSH_USER",
  "ARK_TEST_VPS_TAILNET_OWNER",
  "ARK_TEST_VPS_TAILNET_STATE_FILE",
  "ARK_TEST_VPS_ROOT",
] as const;
const missing = required.filter((key) => !process.env[key]?.trim());
if (missing.length) {
  console.log(
    `test:host-hardening-live skipped. Supply scratch VPS and scratch-tailnet owner details via ${missing.join(", ")}.`,
  );
  process.exit(0);
}
const [ipv4, ipv6, inventory, sshAddress, sshUser, owner, stateFile, vpsRoot] = required.map((key) =>
  process.env[key]!.trim(),
) as [string, string, string, string, string, string, string, string];
assert.ok(isIP(ipv4) === 4 && isIP(ipv6) === 6, "Supply scratch public IPv4 and IPv6 literals.");
assert.match(sshAddress, /^[a-z0-9][a-z0-9.-]*\.ts\.net\.?$/i, "Use the scratch VPS's MagicDNS name.");
assert.match(sshUser, /^[a-z_][a-z0-9_-]*$/, "Use a local scratch VPS username.");
assert.ok(vpsRoot.startsWith("/"), "Use an absolute checkout path on the scratch VPS.");
assert.ok(
  stateFile.startsWith("/") && ((await stat(stateFile)).mode & 0o077) === 0,
  "The disposable owner state file must be private and use an absolute path.",
);
const config = await readExternalInventory(inventory);

const name = `ark-fd20-live-${crypto.randomUUID().slice(0, 12)}`;
const image = `${name}:client`;
const directory = await mkdtemp(join(tmpdir(), `${name}-`));
const runtime = new EdgeTestRuntime(directory, name);
const stopSignalHandlers = runtime.installSignalHandlers();
const docker = runtime.docker.bind(runtime);
const ts = (...args: string[]) =>
  docker("exec", name, "timeout", "45s", "tailscale", "--socket=/run/ark-test.sock", ...args);
const ssh = (command: string) => ts("ssh", `${sshUser}@${sshAddress}`, command);
const quote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";

async function observeUdp(address: string, ports: number[]) {
  const family = isIP(address);
  const cookie = randomBytes(4);
  const table = `ark_fd20_probe_${cookie.toString("hex")}`;
  const counters = ports.map((port) => `counter p${port} {}`);
  const rules = ports.map(
    (port) =>
      `meta nfproto ipv${family} udp dport ${port} @th,64,32 0x${cookie.toString("hex")} counter name p${port}`,
  );
  // Observe after the Ark and Docker filters, on input or through a Docker publication.
  const policy = `table inet ${table} {
${counters.join("\n")}
chain inbound { type filter hook input priority 300; policy accept;
${rules.join("\n")}
}
chain published { type filter hook forward priority 300; policy accept;
${rules.join("\n")}
}
}`;
  await ssh(`printf '%s\\n' ${quote(policy)} | sudo -n nft -f -`);
  let socket: ReturnType<typeof createSocket> | undefined;
  try {
    const probe = createSocket(family === 4 ? "udp4" : "udp6");
    socket = probe;
    let socketError: NodeJS.ErrnoException | undefined;
    probe.on("error", (error: NodeJS.ErrnoException) => {
      if (error.code !== "ECONNREFUSED") socketError = error;
    });
    for (let attempt = 0; attempt < 3; attempt++) {
      await Promise.all(
        ports.map(
          (port) =>
            new Promise<void>((resolve, reject) =>
              probe.send(cookie, port, address, (error: NodeJS.ErrnoException | null) =>
                error && error.code !== "ECONNREFUSED" ? reject(error) : resolve(),
              ),
            ),
        ),
      );
      await Bun.sleep(200);
    }
    if (socketError) throw socketError;
    const result = JSON.parse(await ssh(`sudo -n nft -j list table inet ${table}`)) as {
      nftables: { counter?: { name: string; packets?: number } }[];
    };
    return new Set(
      result.nftables.flatMap(({ counter }) => (counter?.packets ? [Number(counter.name.slice(1))] : [])),
    );
  } finally {
    try {
      socket?.close();
    } finally {
      await ssh(`sudo -n nft delete table inet ${table}`);
    }
  }
}
let builtImage = false;
try {
  await docker(
    "build",
    "--quiet",
    "--target",
    "live",
    "-t",
    image,
    join(import.meta.dir, "host-hardening-test"),
  );
  builtImage = true;
  runtime.containers.push(name);
  await docker("run", "-d", "--name", name, "--init", image, "sleep", "infinity");
  await docker("cp", stateFile, `${name}:/run/ark-test.state`);
  await docker("exec", name, "chmod", "600", "/run/ark-test.state");
  await docker(
    "exec",
    "-d",
    name,
    "tailscaled",
    "--tun=userspace-networking",
    "--state=/run/ark-test.state",
    "--socket=/run/ark-test.sock",
  );
  const deadline = Date.now() + 45_000;
  let identity: {
    BackendState?: string;
    Self?: { Tags?: string[]; UserID: number };
    User?: Record<string, { LoginName: string }>;
  } = {};
  do {
    identity = JSON.parse(await ts("status", "--json").catch(() => "{}"));
    if (identity.BackendState === "Running" && identity.Self) break;
    await Bun.sleep(500);
  } while (Date.now() < deadline);
  assert.equal(identity.BackendState, "Running", "The scratch owner node did not start.");
  assert.ok(!identity.Self?.Tags?.length, "The scratch SSH client must be a user device.");
  assert.equal(identity.User?.[String(identity.Self?.UserID)]?.LoginName, owner, "Scratch owner identity");
  assert.equal(await ts("ssh", `${sshUser}@${sshAddress}`, "id", "-un"), sshUser, "Owner Tailscale SSH");
  console.log("The scratch-tailnet owner authenticated to the VPS over Tailscale SSH.");
  console.log(await ssh(`cd ${quote(vpsRoot)} && sudo -n mise run host:audit`));
  const observations = await Promise.allSettled([
    auditExternal(config, ipv4, observeUdp),
    auditExternal(config, ipv6, observeUdp),
  ]);
  const failures = observations.flatMap((result) =>
    result.status === "rejected" ? [String(result.reason)] : [],
  );
  if (failures.length) throw new Error(failures.join("\n"));
} finally {
  await runtime.cleanup();
  if (builtImage) {
    const child = Bun.spawn(["docker", "image", "rm", image], { stdout: "ignore", stderr: "inherit" });
    await child.exited;
  }
  stopSignalHandlers();
}
