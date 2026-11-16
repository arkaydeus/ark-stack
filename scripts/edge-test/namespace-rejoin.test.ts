import { expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import { projectContainers, rejoinNamespaceDependents } from "../edge-namespace.ts";

test("real rejoin excludes stopped optional profiles and refuses a stopped edge owner", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ark-rejoin-"));
  const project = basename(directory).toLowerCase();
  const compose = join(directory, "compose.yml");
  const release = await Bun.file(new URL("../../infra/platform/release.json", import.meta.url)).json();
  const image = release.images.find((pin: string) => pin.startsWith("caddy:"));
  await Bun.write(
    compose,
    `
x-idle: &idle
  image: ${image}
  entrypoint: ["/bin/sh", "-c", "sleep 3600"]
services:
  edge-ts:
    <<: *idle
  edge:
    <<: *idle
    network_mode: service:edge-ts
  tailscale:
    <<: *idle
    profiles: [tailnet]
  tailnet-gateway:
    <<: *idle
    profiles: [tailnet]
    network_mode: service:tailscale
`,
  );
  const composeArgs = ["-p", project, "-f", compose];
  const run = async (...args: string[]) => {
    const child = Bun.spawn(["docker", "compose", ...composeArgs, ...args], {
      stdout: "pipe",
      stderr: "pipe",
    });
    const [code, stderr] = await Promise.all([
      child.exited,
      new Response(child.stderr).text(),
      new Response(child.stdout).text(),
    ]);
    if (code !== 0) throw new Error(stderr);
  };
  const rejoin = () => rejoinNamespaceDependents({ project, composeArgs, log: () => {} });
  try {
    await run("--profile", "tailnet", "up", "-d", "--wait");
    await run("stop", "tailnet-gateway", "tailscale");
    const before = await projectContainers(project);
    await expect(rejoin()).resolves.toEqual([]);
    expect(await projectContainers(project)).toEqual(before);

    await run("stop", "edge-ts");
    await expect(rejoin()).rejects.toThrow(/edge-ts is not running/);

    await run("start", "edge-ts");
    const oldEdge = before.find((container) => container.service === "edge")!;
    const repaired = await rejoin();
    expect(repaired.map((item) => item.service)).toEqual(["edge"]);
    const after = await projectContainers(project);
    expect(after.find((container) => container.service === "edge")!.id).not.toBe(oldEdge.id);
    expect(after.filter((container) => ["tailscale", "tailnet-gateway"].includes(container.service))).toEqual(
      before.filter((container) => ["tailscale", "tailnet-gateway"].includes(container.service)),
    );
    await expect(rejoin()).resolves.toEqual([]);

    // A stopped gateway must also stay stopped when its owner is running.
    await run("start", "tailscale");
    await expect(rejoin()).resolves.toEqual([]);
    expect(
      (await projectContainers(project)).find((container) => container.service === "tailnet-gateway")!
        .running,
    ).toBe(false);
  } finally {
    await run("--profile", "tailnet", "down", "--volumes", "--remove-orphans");
    await rm(directory, { recursive: true, force: true });
  }
}, 90_000);
