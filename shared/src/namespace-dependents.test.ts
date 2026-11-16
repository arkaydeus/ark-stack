import { describe, expect, test } from "bun:test";

import { type NamespaceContainer, staleNamespaceDependents } from "./maintenance.ts";

const owner: NamespaceContainer = {
  service: "edge-ts",
  id: "a".repeat(64),
  networkMode: "ark-platform_admin",
  running: true,
  startedAt: "2026-11-16T10:00:00.000000000Z",
};
const edge: NamespaceContainer = {
  service: "edge",
  id: "b".repeat(64),
  networkMode: `container:${"a".repeat(64)}`,
  running: true,
  startedAt: "2026-11-16T10:00:01.000000000Z",
};
const api: NamespaceContainer = {
  service: "api",
  id: "c".repeat(64),
  networkMode: "ark-platform_control",
  running: true,
  startedAt: "2026-11-16T09:00:00Z",
};

describe("network_mode: service: dependents", () => {
  test("a dependent that joined the live owner is left alone", () => {
    expect(staleNamespaceDependents([owner, edge, api])).toEqual([]);
  });

  test("an owner recreated with a new id strands the dependent", () => {
    const replaced = { ...owner, id: "d".repeat(64), startedAt: "2026-11-16T11:00:00Z" };
    expect(staleNamespaceDependents([replaced, edge, api])).toEqual([
      { service: "edge", reason: "owner-replaced" },
    ]);
  });

  test("an owner restarted in place after the dependent started strands it", () => {
    const restarted = { ...owner, startedAt: "2026-11-16T10:30:00.5Z" };
    expect(staleNamespaceDependents([restarted, edge])).toEqual([
      { service: "edge", parent: "edge-ts", reason: "owner-restarted" },
    ]);
  });

  test("a stopped dependent is rejoined too", () => {
    expect(staleNamespaceDependents([owner, { ...edge, running: false }])).toEqual([
      { service: "edge", parent: "edge-ts", reason: "not-running" },
    ]);
  });

  test("a stopped owner is unhealthy even while its dependent runs", () => {
    expect(staleNamespaceDependents([{ ...owner, running: false }, edge])).toEqual([
      { service: "edge", parent: "edge-ts", reason: "owner-stopped" },
    ]);
  });

  test("only container: network modes are considered", () => {
    expect(
      staleNamespaceDependents([
        { ...api, networkMode: "host" },
        { ...api, networkMode: "none" },
      ]),
    ).toEqual([]);
  });
});
