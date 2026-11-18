import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { MAIL_PUBLIC_TCP } from "@ark-stack/shared";
import { EdgeTestRuntime } from "./edge-test/runtime.ts";

const root = resolve(import.meta.dir, "..");
const suffix = crypto.randomUUID().slice(0, 12);
const name = `ark-fd20-${suffix}`;
const image = `${name}:vps`;
const vps = `${name}-vps`;
const scanner = `${name}-scanner`;
const directory = await mkdtemp(join(tmpdir(), `${name}-`));
const runtime = new EdgeTestRuntime(directory, `${name}-wan`);
const stopSignalHandlers = runtime.installSignalHandlers();
const docker = runtime.docker.bind(runtime);
const exec = (container: string, ...args: string[]) => docker("exec", container, ...args);
const host = (...args: string[]) => exec(vps, ...args);
const nested = (...args: string[]) => host("docker", ...args);
const scan = (...args: string[]) => exec(scanner, ...args);
const env = ["-e", "ARK_MAIL_ENABLED=1", "-e", "ARK_EDGE_SNI_PORTS=8883"];
const fixture = "/work/scripts/inside.js";
const audit = "/work/scripts/host-audit.js";
const ingress = "/work/scripts/database-ingress.js";

async function ready(check: () => Promise<unknown>, label: string, timeout = 30_000) {
  let error: unknown;
  const deadline = Date.now() + timeout;
  do {
    try {
      return await check();
    } catch (failure) {
      error = failure;
      await Bun.sleep(250);
    }
  } while (Date.now() < deadline);
  throw new Error(`${label} did not become ready.`, { cause: error });
}

async function applyPolicy(mode: "on" | "off") {
  const id = await host("bun", fixture, "policy", mode);
  await host("nft", "-c", "-f", "/tmp/ark-host.nft");
  await host("nft", "-f", "/tmp/ark-host.nft");
  await docker(
    "exec",
    "-d",
    ...env,
    "-e",
    `ARK_MAIL_ENABLED=${mode === "on" ? 1 : 0}`,
    "-e",
    "ARK_HOST_HARDENING=1",
    "-e",
    "ARK_FRONT_INGRESS_DIR=/work/tmp/edge-l4/front-ingress",
    "-w",
    "/work",
    vps,
    "bun",
    ingress,
  );
  await ready(async () => {
    const status = await host("cat", "/work/tmp/edge-l4/front-ingress/policy.status");
    assert.match(status, /applied=true/);
    assert.ok(status.includes(`request_id=${id}`), status);
  }, "Host firewall reconciliation");
}

async function externalAudit(addresses: string[], mailEnabled: boolean) {
  const args = ["-e", `ARK_MAIL_ENABLED=${mailEnabled ? 1 : 0}`, "-e", "ARK_EDGE_SNI_PORTS=8883"];
  const inventory = await docker("exec", ...args, vps, "bun", audit, "--inventory");
  const { providerRules } = JSON.parse(inventory);
  assert.deepEqual(providerRules, [
    {
      protocol: "tcp",
      ports: [...(mailEnabled ? MAIL_PUBLIC_TCP : []), 80, 443, 5432, 8883, 20001, 20007].toSorted(
        (a, b) => a - b,
      ),
      sourceCidrs: ["0.0.0.0/0", "::/0"],
    },
    { protocol: "udp", ports: [41641, 41642], sourceCidrs: ["0.0.0.0/0", "::/0"] },
  ]);
  await writeFile(join(directory, "inventory.json"), inventory);
  await docker("cp", join(directory, "inventory.json"), `${scanner}:/work/`);
  for (const address of addresses) {
    console.log(await ready(() => scan("bun", fixture, "udp", address), `UDP probe for ${address}`, 15_000));
  }
  console.log(await scan("bun", audit, "--external", "/work/inventory.json", ...addresses));
}

async function loadPinnedImage(pin: string) {
  await docker("image", "inspect", "--format", "{{.Id}}", pin).catch(() => docker("pull", pin));
  // Let the outer daemon handle registry auth and TLS. The nested daemon gets only the pinned image.
  const tag = `${name}:mail`;
  await docker("image", "tag", pin, tag);
  try {
    const archive = join(directory, "mail.tar");
    await docker("image", "save", "-o", archive, tag);
    await docker("cp", archive, `${vps}:/tmp/mail.tar`);
    await nested("image", "load", "-i", "/tmp/mail.tar");
    await host("rm", "/tmp/mail.tar");
    return tag;
  } finally {
    await docker("image", "rm", tag);
  }
}

let builtImage = false;
let upgrades: Promise<void> | undefined;
try {
  const result = await Bun.build({
    entrypoints: [
      join(import.meta.dir, "host-audit.ts"),
      join(import.meta.dir, "database-ingress.ts"),
      join(import.meta.dir, "host-hardening-test", "inside.ts"),
    ],
    naming: "[name].js",
    outdir: join(directory, "scripts"),
    target: "bun",
  });
  if (!result.success) throw new Error(result.logs.join("\n"));
  await docker(
    "build",
    "--quiet",
    "--target",
    "vps",
    "-t",
    image,
    join(import.meta.dir, "host-hardening-test"),
  );
  builtImage = true;
  // The scanner shares only the simulated VPS's WAN link. The nested daemon has its
  // own socket, data, bridges and nftables, and publishes no ports on the build machine.
  try {
    await docker("network", "create", "--ipv6", runtime.network);
  } catch (error) {
    if (!/ipv6.*(?:disabled|not supported|unavailable)/i.test(String(error))) throw error;
    console.log("Local IPv6 probes skipped. Docker reports IPv6 is unavailable.");
    await docker("network", "create", runtime.network);
  }
  runtime.networkCreated = true;
  for (const container of [vps, scanner]) {
    runtime.containers.push(container);
    await docker(
      "run",
      "-d",
      "--init",
      "--name",
      container,
      "--network",
      runtime.network,
      ...(container === vps ? ["--privileged"] : []),
      image,
      "sleep",
      "infinity",
    );
    await exec(container, "mkdir", "-p", "/work");
    await docker("cp", join(directory, "scripts"), `${container}:/work/`);
  }
  const wan = JSON.parse(await docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", vps))[
    runtime.network
  ];
  const addresses: string[] = [wan.IPAddress, wan.GlobalIPv6Address].filter(Boolean);
  assert.ok(wan.IPAddress);
  if (!wan.GlobalIPv6Address) console.log("Local IPv6 probes skipped. The test WAN has no IPv6 address.");

  console.log("Starting isolated Docker daemon and unattended-upgrades check.");
  await docker("exec", "-d", vps, "dockerd", "--storage-driver=vfs", "--userland-proxy=false");
  upgrades = host("bun", fixture, "updates").then((output) => {
    console.log(output);
  });
  // Capture early failures here and still await the check below.
  void upgrades.catch(() => undefined);
  await ready(() => nested("info"), "Nested Docker daemon");
  await nested("network", "create", ...(addresses.length > 1 ? ["--ipv6"] : []), "mail");
  const mailCompose = await readFile(join(root, "infra/mail/docker-compose.yml"), "utf8");
  const mailImage = /^    image: (\S+)$/m.exec(mailCompose)?.[1];
  assert.ok(mailImage?.startsWith("stalwartlabs/stalwart@sha256:"));
  const mailImageId = await loadPinnedImage(mailImage!);
  const published = /ports: \[([^\]]+)\]/.exec(mailCompose)?.[1]?.match(/\d+:\d+/g);
  assert.deepEqual(
    published,
    MAIL_PUBLIC_TCP.map((port) => `${port}:${port}`),
  );
  await docker("cp", join(root, "infra/mail/config.json"), `${vps}:/tmp/stalwart.json`);
  const mailPassword = crypto.randomUUID();
  const mailArgs = [
    "run",
    "-d",
    "--name",
    "mail",
    "--network",
    "mail",
    "--cap-drop",
    "ALL",
    "--cap-add",
    "NET_BIND_SERVICE",
    "--security-opt",
    "no-new-privileges=true",
    "-e",
    `STALWART_RECOVERY_ADMIN=admin:${mailPassword}`,
    "-v",
    "/tmp/stalwart.json:/etc/stalwart/config.json:ro",
    ...published!.flatMap((port) => ["-p", port]),
  ];
  await nested(...mailArgs, "-p", "24444:8080", mailImageId);
  await ready(
    async () => {
      await scan("nmap", "-n", "-Pn", "-p", "24444", wan.IPAddress).then((out) =>
        assert.match(out, /24444\/tcp open/),
      );
      await host("docker", "exec", "mail", "curl", "-fsS", "http://127.0.0.1:8080/");
    },
    "Stalwart and unexpected Docker publication",
    60_000,
  );
  const configureMail = () =>
    docker(
      "exec",
      "-e",
      `ARK_FD20_TEST_MAIL_PASSWORD=${mailPassword}`,
      vps,
      "bun",
      fixture,
      "configure-mail",
    );
  await configureMail();
  await docker(
    "exec",
    "-d",
    vps,
    "bun",
    "-e",
    `const child = Bun.spawn(["bun", "${fixture}", "listen"], { stderr: Bun.file("/tmp/listeners.log") });
     process.exit(await child.exited);`,
  );
  await docker("exec", "-d", vps, "bun", fixture, "listen", "22");
  await ready(async () => {
    assert.match(
      await scan("nmap", "-n", "-Pn", "-p", "22,80", wan.IPAddress),
      /22\/tcp\s+open[\s\S]+80\/tcp\s+open/,
    );
  }, "Simulated VPS listeners");
  await applyPolicy("on");
  await assert.rejects(
    docker("exec", ...env, vps, "bun", audit),
    /Unexpected TCP .*24444 published[\s\S]+Unexpected TCP .*22 listening/,
  );
  console.log(
    "Local audit rejected both the unexpected Docker publication and the host's public SSH listener.",
  );
  await externalAudit(addresses, true);
  await Promise.all(
    addresses.map(async (address) => console.log(await scan("bun", fixture, "mail", address))),
  );

  await nested("rm", "-f", "-v", "mail");
  await nested(...mailArgs, mailImageId);
  await ready(
    () => nested("exec", "mail", "curl", "-fsS", "http://127.0.0.1:8080/"),
    "Stalwart after withdrawal",
  );
  await configureMail();
  const sshPid = /:22\s[^\n]*pid=(\d+)/.exec(await host("ss", "-H", "-lntp", "sport", "=", ":22"))?.[1];
  assert.ok(sshPid);
  await host("kill", sshPid);
  console.log(await docker("exec", ...env, vps, "bun", audit));

  await host("pkill", "-f", `^bun ${ingress}$`);
  await applyPolicy("off");
  // Leave Stalwart listening during the negative test so firewall closure is proved.
  await externalAudit(addresses, false);
  await assert.rejects(
    docker("exec", "-e", "ARK_MAIL_ENABLED=0", "-e", "ARK_EDGE_SNI_PORTS=8883", vps, "bun", audit),
    /Unexpected TCP .*:25 published/,
  );
  await nested("stop", "mail");
  console.log(
    await docker("exec", "-e", "ARK_MAIL_ENABLED=0", "-e", "ARK_EDGE_SNI_PORTS=8883", vps, "bun", audit),
  );
  await upgrades;

  const monitoring = await readFile(join(root, "infra/monitoring/docker-compose.yml"), "utf8");
  const promImage = /^    image: (\S+)$/m.exec(monitoring)?.[1];
  assert.ok(promImage);
  console.log(
    await docker(
      "run",
      "--rm",
      "--network",
      "none",
      "--entrypoint",
      "promtool",
      "-v",
      `${join(root, "infra/monitoring/alerts.yml")}:/alerts.yml:ro`,
      "-v",
      `${join(import.meta.dir, "host-hardening-test/reboot-alert.test.yml")}:/test.yml:ro`,
      promImage,
      "test",
      "rules",
      "/test.yml",
    ),
  );
} catch (error) {
  if (builtImage) {
    const logs = await nested("logs", "--tail", "30", "mail").catch(() => "");
    if (logs) console.error(logs);
    const listenerLogs = await host("cat", "/tmp/listeners.log").catch(() => "");
    if (listenerLogs) console.error(listenerLogs);
    const status = await host("ss", "-H", "-lntup").catch(() => "");
    if (status) console.error(status);
  }
  throw error;
} finally {
  await runtime.cleanup();
  if (builtImage) await hostImageRemove();
  stopSignalHandlers();
}

async function hostImageRemove() {
  const child = Bun.spawn(["docker", "image", "rm", image], { stdout: "ignore", stderr: "inherit" });
  if (await child.exited) console.error(`Unable to remove disposable test image ${image}.`);
}
