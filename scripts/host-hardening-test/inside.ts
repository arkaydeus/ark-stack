import assert from "node:assert/strict";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { createSocket } from "node:dgram";
import { isIP, createConnection, createServer } from "node:net";
import { connect } from "node:tls";
import { join } from "node:path";

import {
  HOST_TAILSCALE_UDP,
  EDGE_TAILSCALE_UDP,
  DB_INGRESS_LIMIT_DEFAULTS,
  rebootRequiredMetrics,
  renderHostFirewall,
  sha256Hex,
} from "@ark-stack/shared";
import { frontIngressRules } from "../../server/src/modules/front-ingress.ts";
import { automaticUpdatesConfig, hostCommand, rebootMetricCommands } from "../install-host-hardening.ts";
import { ensureMailSubmission } from "../install-mail-submission.ts";

const front = "/work/tmp/edge-l4/front-ingress";
const sni = [8883];
const raw = [20001, 20007];

async function makePolicy(mailEnabled: boolean) {
  await mkdir(front, { recursive: true });
  const target = {
    hostname: "route.example.test",
    stableId: "test",
    ip: "100.64.0.1",
    port: 5432,
    sourceCidrs: [],
    allowInternet: true,
  };
  const rules = frontIngressRules(
    {
      httpHostnames: [],
      sniPorts: sni,
      tcpRoutes: [{ ...target, id: "rt_raw", listenPort: raw[0]! }],
      postgresRoutes: [{ ...target, id: "rt_compat", compatPort: raw[1]! }],
    },
    DB_INGRESS_LIMIT_DEFAULTS,
  );
  const id = crypto.randomUUID();
  await writeFile(join(front, "policy.nft.tmp"), rules);
  await rename(join(front, "policy.nft.tmp"), join(front, "policy.nft"));
  await writeFile(join(front, "policy.request.tmp"), JSON.stringify({ id, hash: sha256Hex(rules) }));
  await rename(join(front, "policy.request.tmp"), join(front, "policy.request"));
  await writeFile("/tmp/ark-host.nft", renderHostFirewall({ mailEnabled, sniPorts: sni }));
  console.log(id);
}

function listen(ports: number[], withUdp: boolean) {
  for (const port of ports) {
    createServer((socket) => {
      socket.on("error", () => socket.destroy());
      socket.end();
    }).listen(port, "::");
  }
  if (withUdp) {
    for (const port of [HOST_TAILSCALE_UDP, EDGE_TAILSCALE_UDP]) {
      const socket = createSocket("udp6");
      socket.on("error", (error) => console.error(error));
      socket.on("message", (data, address) => {
        // Echo a real protocol probe. Nmap's empty datagrams get no reply, as with WireGuard.
        if (data.length) socket.send(data, address.port, address.address);
      });
      socket.bind(port, "::");
    }
  }
}

function greeting(host: string, port: number, tls: boolean) {
  return new Promise<string>((resolve, reject) => {
    const socket = tls
      ? connect({ host, port, servername: "mail.example.test", rejectUnauthorized: false })
      : createConnection({ host, port });
    socket.setTimeout(3000, () => socket.destroy(new Error(`TCP ${host}:${port} timed out.`)));
    socket.once("error", reject);
    socket.once("data", (data) => {
      resolve(data.toString());
      socket.destroy();
    });
    socket.once("end", () => reject(new Error(`TCP ${host}:${port} closed without a greeting.`)));
  });
}

async function mail(host: string) {
  for (const [port, tls, banner] of [
    [25, false, /^220 /],
    [465, true, /^220 /],
    [587, false, /^220 /],
    [993, true, /^\* OK /],
  ] as const) {
    assert.match(await greeting(host, port, tls), banner, `Stalwart greeting on ${host}:${port}`);
  }
  console.log(`Stalwart SMTP, submission (including implicit TLS) and IMAPS answered at ${host}.`);
}

async function udp(host: string) {
  for (const port of [HOST_TAILSCALE_UDP, EDGE_TAILSCALE_UDP]) {
    const socket = createSocket(isIP(host) === 6 ? "udp6" : "udp4");
    const nonce = crypto.randomUUID();
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error(`No UDP reply from ${host}:${port}.`)), 3000);
      socket.once("error", reject);
      socket.once("message", (data) => {
        clearTimeout(timeout);
        if (data.toString() === nonce) resolve();
        else reject(new Error(`Wrong UDP response from ${host}:${port}.`));
      });
      socket.send(nonce, port, host);
    }).finally(() => socket.close());
  }
  console.log(`UDP 41641 and 41642 acknowledged both probes at ${host}.`);
}

async function updates() {
  const directory = "/var/lib/ark/host-metrics";
  await mkdir(directory, { recursive: true });
  await writeFile("/etc/apt/apt.conf.d/52ark-unattended-upgrades", automaticUpdatesConfig("04:00"));
  const apt = await hostCommand("apt-config", ["dump"]);
  assert.match(
    apt,
    /Unattended-Upgrade::Allowed-Origins:: "\$\{distro_id\}:\$\{distro_codename\}-security";/,
  );
  assert.match(apt, /Unattended-Upgrade::Automatic-Reboot "true";/);
  assert.match(apt, /Unattended-Upgrade::Automatic-Reboot-Time "04:00";/);
  await hostCommand("unattended-upgrades", ["--dry-run"]);
  console.log("Ubuntu security origin and scheduled reboot configured. Unattended upgrade dry-run passed.");
  await rm("/run/reboot-required", { force: true });
  for (const expected of [0, 1, 0]) {
    if (expected) await writeFile("/run/reboot-required", "test\n");
    else await rm("/run/reboot-required", { force: true });
    for (const [command, ...args] of rebootMetricCommands(directory)) await hostCommand(command!, args);
    const gauge = rebootRequiredMetrics(await readFile(join(directory, "reboot-required"), "utf8"));
    assert.deepEqual(gauge, [
      "# TYPE ark_host_reboot_required gauge",
      `ark_host_reboot_required ${expected}`,
    ]);
  }
  console.log("Production reboot metric exporter reports 0, 1 and 0 as the marker changes.");
}

const [mode, value] = process.argv.slice(2);
switch (mode) {
  case "policy":
    await makePolicy(value === "on");
    break;
  case "listen":
    listen(value ? [Number(value)] : [80, 443, 5432, ...sni, ...raw], !value);
    break;
  case "mail":
    await mail(value!);
    break;
  case "configure-mail":
    for (let attempt = 0; attempt < 2; attempt++) {
      await ensureMailSubmission(
        ["exec", "-i", "mail"],
        {
          user: "admin",
          password: process.env.ARK_FD20_TEST_MAIL_PASSWORD!,
        },
        () => hostCommand("docker", ["restart", "mail"]),
      );
    }
    break;
  case "udp":
    await udp(value!);
    break;
  case "updates":
    await updates();
    break;
  default:
    throw new Error(`Unknown fixture ${mode}`);
}
