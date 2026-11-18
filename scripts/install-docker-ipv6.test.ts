import { expect, test } from "bun:test";
import { mkdir, mkdtemp, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { dockerIpv6Ready, IPV6_HOST_SAMPLE_MS, type Ipv6DockerState } from "@ark-stack/shared";

import {
  configureDockerIpv6,
  installIpv6Observer,
  migratePublishedNetwork,
  verifyOtherIpv6Publications,
} from "./install-docker-ipv6.ts";
import { parseIpv6EdgeLogs } from "./observe-docker-ipv6.ts";

test.each([null, '{ "log-driver": "local" }\n'])(
  "rolls back the daemon file and restarts Docker when new settings do not load (%p)",
  async (original) => {
    const dir = await mkdtemp(join(tmpdir(), "ark-ipv6-daemon-"));
    const path = join(dir, "daemon.json");
    try {
      if (original) await writeFile(path, original, { mode: 0o640 });
      const applied: (string | null)[] = [];
      let validated = false;
      await expect(
        configureDockerIpv6(true, {
          path,
          command: async (command, args) => {
            if (command === "dockerd") {
              expect(args.slice(0, 2)).toEqual(["--validate", "--config-file"]);
              expect(await Bun.file(args[2]!).json()).toMatchObject({
                ipv6: true,
                ip6tables: true,
                "live-restore": true,
                "userland-proxy": false,
              });
              validated = true;
            }
            if (command === "systemctl") {
              expect(validated).toBe(true);
              expect(args).toEqual(["restart", "docker.service"]);
              applied.push((await Bun.file(path).exists()) ? await Bun.file(path).text() : null);
            }
            return args[0] === "network" ? '[{"EnableIPv6":false}]' : "";
          },
        }),
      ).rejects.toThrow("Docker did not start");
      expect(applied).toHaveLength(2);
      expect(applied[0]).toContain('"userland-proxy": false');
      expect(applied[1]).toBe(original);
      expect(await readdir(dir)).toEqual(original ? ["daemon.json"] : []);
      if (original) expect((await stat(path)).mode & 0o777).toBe(0o640);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  },
);

test("a foreign attachment stops migration before any Docker mutation", async () => {
  const calls: string[][] = [];
  const labels = { "com.docker.compose.project": "ark-platform", "com.docker.compose.network": "admin" };
  await expect(
    migratePublishedNetwork(
      {
        project: "ark-platform",
        network: "admin",
        service: "edge-ts",
        compose: ["compose"],
      },
      async (command, args) => {
        calls.push([command, ...args]);
        if (args[1] === "ls") return "legacy-id";
        if (args[1] === "inspect") return JSON.stringify([{ Labels: labels, Containers: { foreign: {} } }]);
        return '{"com.docker.compose.project":"other","com.docker.compose.service":"foreign"}';
      },
    ),
  ).rejects.toThrow("attachment outside the Compose project");
  expect(calls.map((args) => args.slice(0, 3))).toEqual([
    ["docker", "network", "ls"],
    ["docker", "network", "inspect"],
    ["docker", "inspect", "--format"],
  ]);
});

test.each([
  ["", "", true],
  ["::", "", true],
  ["0.0.0.0", "", false],
  ["127.0.0.1", "", false],
  ["", "fd00::2", false],
] as const)(
  "third-party publication %p with endpoint %p has blocking status %p",
  async (HostIp, address, blocked) => {
    const calls: string[][] = [];
    const verify = verifyOtherIpv6Publications(async (name, args) => {
      calls.push([name, ...args]);
      if (args[0] === "ps") return "third-party";
      return JSON.stringify([
        {
          Name: "/third-party",
          HostConfig: { PortBindings: { "25/tcp": [{ HostIp }] } },
          NetworkSettings: { Networks: { external: { GlobalIPv6Address: address } } },
        },
      ]);
    });
    if (blocked) await expect(verify).rejects.toThrow("Give /third-party an IPv6 Docker network");
    else await expect(verify).resolves.toBeUndefined();
    expect(calls).toEqual([
      ["docker", "ps", "-q"],
      ["docker", "inspect", "third-party"],
    ]);
  },
);

test("installs a standalone observer and enables and starts its systemd units in order", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ark-ipv6-observer-"));
  try {
    const executable = join(dir, "bin", "observe-docker-ipv6");
    const directory = join(dir, "state");
    const unit = join(dir, "systemd", "ark-docker-ipv6");
    await mkdir(join(dir, "systemd"));
    const calls: string[][] = [];
    await installIpv6Observer(dir, {
      executable,
      directory,
      unit,
      command: async (command, args) => {
        calls.push([command, ...args]);
        if (command === process.execPath) {
          expect(args.slice(0, 4)).toEqual([
            "build",
            "--compile",
            join(dir, "scripts/observe-docker-ipv6.ts"),
            "--outfile",
          ]);
          await Bun.write(args[4]!, "compiled observer");
        }
        return "";
      },
    });
    expect(await Bun.file(executable).text()).toBe("compiled observer");
    expect(await readdir(join(dir, "bin"))).toEqual(["observe-docker-ipv6"]);
    expect((await stat(directory)).isDirectory()).toBe(true);
    expect(await Bun.file(unit + ".service").text()).toContain("ExecStart=" + executable + " " + directory);
    expect(await Bun.file(unit + ".timer").text()).toContain("OnUnitInactiveSec=5s");
    expect(calls.slice(1)).toEqual([
      ["systemctl", "daemon-reload"],
      ["systemctl", "enable", "--now", "ark-docker-ipv6.timer"],
      ["systemctl", "start", "ark-docker-ipv6.service"],
    ]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("only fresh, current Docker snapshots are ready", () => {
  const now = 100_000;
  const state: Ipv6DockerState = {
    at: now,
    daemon: "daemon",
    edge: "edge",
    ipv6: true,
    ip6tables: true,
    liveRestore: true,
    userlandProxy: false,
    networkIpv6: true,
    edgeAddress: "fd00::1",
  };
  expect(dockerIpv6Ready({ ...state, at: now - IPV6_HOST_SAMPLE_MS }, now)).toBe(true);
  expect(dockerIpv6Ready({ ...state, at: now - IPV6_HOST_SAMPLE_MS - 1 }, now)).toBe(false);
  expect(dockerIpv6Ready({ ...state, at: now + 1 }, now)).toBe(false);
  expect(dockerIpv6Ready(undefined, now)).toBe(false);
});

test("HAProxy evidence rejects malformed and mapped peers and records only real backend connections", () => {
  const at = "2026-11-18T12:00:00.000Z";
  const event = (source: string, server: string, timing: string) =>
    `${at} ${source}:41234 [18/Nov/2026:12:00:00.000] fe_tls~ be/${server} ${timing} 0 --`;
  const logs = parseIpv6EdgeLogs(
    [
      event("[2001:4860:0::12]", "target", "0/0/1"),
      event("2001:4860::12", "<NOSRV>", "0/0/1"),
      event("2001:4860::12", "target", "0/-1/1"),
      event("::ffff:192.0.2.1", "target", "0/0/1"),
      event("2001:4860::12", "target", "invalid"),
      "bad timestamp",
    ].join("\n"),
    "edge-l4",
  );
  expect(logs).toEqual(
    ["target", "<NOSRV>", "target"].map((server, i) => ({
      protocol: "haproxy",
      at: Date.parse(at),
      source: "2001:4860::12",
      sourcePort: 41234,
      frontend: "fe_tls",
      backend: "be",
      server,
      connected: i === 0,
    })),
  );
});

test("HTTP evidence requires a structured Caddy record with a native IPv6 peer", () => {
  const at = "2026-11-18T12:00:00.000Z";
  const path = "/.well-known/ark-ipv6-preflight/op_example";
  const entry = (remote_ip: string) =>
    JSON.stringify({
      status: 404,
      request: { remote_ip, remote_port: "41234", uri: path, host: "app.example" },
    });
  expect(
    parseIpv6EdgeLogs(
      [
        `${at} ${path} invalid json`,
        `${at} ${entry("::ffff:192.0.2.1")}`,
        `${at} ${entry("2001:4860::12")}`,
      ].join("\n"),
      "edge",
    ),
  ).toEqual([
    {
      protocol: "http",
      at: Date.parse(at),
      source: "2001:4860::12",
      sourcePort: 41234,
      path,
      hostname: "app.example",
    },
  ]);
});
