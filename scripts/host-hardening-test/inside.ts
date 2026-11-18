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
  jmapCall,
  rebootRequiredMetrics,
  renderEdgeL4Generation,
  sha256Hex,
} from "@ark-stack/shared";
import { frontIngressRules } from "../../server/src/modules/front-ingress.ts";
import { enrollVps, hostCommand, installHostHardening } from "../install-host-hardening.ts";
import { appliedHostConfig } from "../host-inventory.ts";
import { auditExternal, readExternalInventory } from "../host-audit-external.ts";
import { ensureMailSubmission } from "../install-mail-submission.ts";

const front = "/work/tmp/edge-l4/front-ingress";
const sni = [8883];
const raw = [20001, 20007];

async function makePolicy() {
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
  console.log(id);
}

function listen(ports: number[], withUdp: boolean) {
  for (const port of ports) {
    createServer((socket) => {
      socket.on("error", () => socket.destroy());
      socket.end();
    }).listen(port, "::");
  }
  if (withUdp) udpEcho(HOST_TAILSCALE_UDP);
}

function udpEcho(port: number) {
  const socket = createSocket("udp6");
  // Respond only to the fixture's application probe. Nmap traffic is ignored like WireGuard.
  socket.on("message", (data, address) => {
    if (/^[a-f0-9-]{36}$/.test(data.toString())) socket.send(data, address.port, address.address);
  });
  socket.on("error", (error: NodeJS.ErrnoException) => {
    if (error.code !== "ECONNREFUSED") throw error;
  });
  socket.bind(port, "::");
}

function unexpectedUdp() {
  const socket = createSocket("udp6");
  socket.on("message", (_data, peer) => socket.send("unexpected", peer.port, peer.address, () => {}));
  socket.on("error", (error: NodeJS.ErrnoException) => {
    if (error.code !== "ECONNREFUSED") throw error;
  });
  socket.bind(161, "::");
}

async function edgeGeneration(active: boolean) {
  const { files } = renderEdgeL4Generation({
    httpHostnames: [],
    sniPorts: sni,
    pooler: active ? { hostname: null, sourceCidrs: [], allowInternet: true } : null,
  });
  for (const [name, content] of Object.entries(files)) {
    const path = join("/work/test-haproxy", name);
    await mkdir(join(path, ".."), { recursive: true });
    await writeFile(path, content);
  }
}

async function pgProbe(host: string, active: boolean) {
  const reply: string[] = [];
  await new Promise<void>((resolve, reject) => {
    const socket = createConnection({ host, port: 5432 });
    let connected = false;
    socket.setTimeout(5000, () => socket.destroy(new Error("Timed out waiting for the 5432 router.")));
    socket.once("connect", () => {
      connected = true;
      socket.write(Buffer.from("0000000804d2162f", "hex"));
    });
    socket.on("data", (chunk) => reply.push(chunk.toString()));
    socket.once("end", resolve);
    socket.once("error", (error: NodeJS.ErrnoException) => {
      if (!active && connected && error.code === "ECONNRESET") resolve();
      else reject(error);
    });
  });
  assert.equal(reply.join(""), active ? "S" : "");
}

function postgresTarget() {
  createServer((socket) => socket.once("data", () => socket.end("S"))).listen(5432, "::");
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

async function udp(host: string, ports: number[]) {
  const responsive: number[] = [];
  for (const port of ports) {
    const socket = createSocket(isIP(host) === 6 ? "udp6" : "udp4");
    const nonce = crypto.randomUUID();
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => resolve(), 1500);
      socket.once("error", (error: NodeJS.ErrnoException) => {
        clearTimeout(timeout);
        if (error.code === "ECONNREFUSED") resolve();
        else reject(error);
      });
      socket.once("message", (data) => {
        clearTimeout(timeout);
        if (data.toString() === nonce) {
          responsive.push(port);
          resolve();
        } else reject(new Error(`Wrong UDP response from ${host}:${port}.`));
      });
      socket.send(nonce, port, host);
    }).finally(() => socket.close());
  }
  return new Set(responsive);
}

async function rebootMetric() {
  const directory = "/var/lib/ark/host-metrics";
  await hostCommand("systemctl", ["is-active", "ark-host-reboot-metric.timer"]);
  await rm("/run/reboot-required", { force: true });
  for (const expected of [0, 1, 0]) {
    if (expected) await writeFile("/run/reboot-required", "test\n");
    else await rm("/run/reboot-required", { force: true });
    await hostCommand("systemctl", ["start", "ark-host-reboot-metric.service"]);
    const gauge = rebootRequiredMetrics(await readFile(join(directory, "reboot-required"), "utf8"));
    assert.deepEqual(gauge, [
      "# TYPE ark_host_reboot_required gauge",
      `ark_host_reboot_required ${expected}`,
    ]);
  }
  console.log("Production reboot metric exporter reports 0, 1 and 0 as the marker changes.");
}

async function loopbackSubmission() {
  const auth = Buffer.from(`admin:${process.env.ARK_FD20_TEST_MAIL_PASSWORD!}`).toString("base64");
  async function set(args: Record<string, unknown>) {
    const body = JSON.stringify(jmapCall("x:NetworkListener/set", args));
    const response = JSON.parse(
      await hostCommand(
        "docker",
        ["exec", "-i", "mail", "curl", "-fsS", "--config", "-"],
        `url = "http://127.0.0.1:8080/jmap"\nheader = "Authorization: Basic ${auth}"\nheader = "Content-Type: application/json"\ndata = ${JSON.stringify(body)}\n`,
      ),
    );
    assert.equal(response.methodResponses[0][0], "x:NetworkListener/set");
    return response.methodResponses[0][1];
  }
  const { created } = await set({
    create: {
      test: {
        name: "submission-test",
        protocol: "smtp",
        bind: { "127.0.0.1:587": true },
        useTls: true,
        tlsImplicit: false,
      },
    },
  });
  assert.ok(created.test.id);
  try {
    await assert.rejects(configureMail(), /loopback-only bind/);
  } finally {
    const { destroyed } = await set({ destroy: [created.test.id] });
    assert.deepEqual(destroyed, [created.test.id]);
  }
}

function configureMail() {
  return ensureMailSubmission(
    "mail",
    { user: "admin", password: process.env.ARK_FD20_TEST_MAIL_PASSWORD! },
    () => hostCommand("docker", ["restart", "mail"]),
  );
}

const [mode, value] = process.argv.slice(2);
switch (mode) {
  case "policy":
    await makePolicy();
    break;
  case "listen":
    listen(value ? [Number(value)] : [80, 443, ...sni, ...raw], !value);
    break;
  case "unexpected-udp":
    unexpectedUdp();
    break;
  case "udp-echo":
    udpEcho(EDGE_TAILSCALE_UDP);
    break;
  case "mail":
    await mail(value!);
    break;
  case "configure-mail":
    await configureMail();
    await configureMail();
    break;
  case "mail-loopback":
    await loopbackSubmission();
    break;
  case "audit-external": {
    const config = await readExternalInventory(value!);
    await Promise.all(process.argv.slice(4).map((address) => auditExternal(config, address, udp)));
    break;
  }
  case "harden":
    await installHostHardening(() => appliedHostConfig("/work"));
    break;
  case "enroll":
    await enrollVps();
    break;
  case "reboot-metric":
    await rebootMetric();
    break;
  case "edge-generation":
    await edgeGeneration(value === "active");
    break;
  case "pg-fresh":
  case "pg-active":
    await pgProbe(value!, mode === "pg-active");
    break;
  case "pg-target":
    postgresTarget();
    break;
  default:
    throw new Error(`Unknown fixture ${mode}`);
}
