import { expect, test } from "bun:test";
import type { NamespaceContainer } from "@ark-stack/shared";

import { rejoinNamespaceDependents } from "./edge-namespace.ts";

const owner: NamespaceContainer = {
  service: "edge-ts",
  id: "owner",
  networkMode: "admin",
  running: true,
  startedAt: "2026-11-16T10:00:00Z",
};
const edge: NamespaceContainer = {
  service: "edge",
  id: "edge",
  networkMode: "container:owner",
  running: true,
  startedAt: "2026-11-16T10:01:00Z",
};
const options = { project: "test", composeArgs: ["-p", "test"], log: () => {} };
const optional = (gatewayRunning = false): NamespaceContainer[] => [
  { ...owner, service: "tailscale", id: "admin-ts", running: false },
  { ...edge, service: "tailnet-gateway", networkMode: "container:admin-ts", running: gatewayRunning },
];

test("healthy edge leaves stopped optional services alone, including a stopped gateway with a running owner", async () => {
  for (const running of [false, true]) {
    const containers = optional();
    containers[0]!.running = running;
    await expect(
      rejoinNamespaceDependents(options, {
        projectContainers: async () => [owner, edge, ...containers],
        recreate: async () => {
          throw new Error("must not recreate inactive optional services");
        },
      }),
    ).resolves.toEqual([]);
  }
});

test("a stopped edge owner fails rather than reporting a running dependent healthy", async () => {
  const logs: string[] = [];
  await expect(
    rejoinNamespaceDependents(
      { ...options, log: (line) => logs.push(line) },
      {
        projectContainers: async () => [{ ...owner, running: false }, edge, ...optional()],
        recreate: async () => {
          throw new Error("must start the owner first");
        },
      },
    ),
  ).rejects.toThrow(/edge-ts is not running. Start it first/);
  expect(logs).toEqual([]);
});

test("repairs a stopped edge and ignores optional services during post-repair verification", async () => {
  let repaired = false;
  await expect(
    rejoinNamespaceDependents(options, {
      projectContainers: async () => [owner, { ...edge, running: repaired }, ...optional()],
      recreate: async (args, services) => {
        expect(args).toEqual(options.composeArgs);
        expect(services).toEqual(["edge"]);
        repaired = true;
      },
    }),
  ).resolves.toEqual([{ service: "edge", parent: "edge-ts", reason: "not-running" }]);
});

test("fails if a managed dependent remains stale after recreation", async () => {
  await expect(
    rejoinNamespaceDependents(options, {
      projectContainers: async () => [owner, { ...edge, running: false }],
      recreate: async () => {},
    }),
  ).rejects.toThrow(/Still outside their owner's namespace: edge/);
});

test("propagates recreation failures without claiming success", async () => {
  await expect(
    rejoinNamespaceDependents(options, {
      projectContainers: async () => [owner, { ...edge, running: false }],
      recreate: async () => {
        throw new Error("docker compose exited 1");
      },
    }),
  ).rejects.toThrow(/docker compose exited 1/);
});
