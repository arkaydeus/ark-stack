import { expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { eq } from "drizzle-orm";
import {
  createId,
  HaproxyMaster,
  installEdgeL4Generation,
  currentGeneration,
  renderEdgeL4Generation,
} from "@ark-stack/shared";
import { drainHaproxy, withEdgeLock, enqueue, processQueued } from "./coordinator.ts";
import { db } from "./db.ts";
import { operations } from "./schema.ts";

const validate = async (_socket: string, generation: string) => ({
  ok: true,
  generation,
  hash: generation,
  diagnostics: "",
});

test("the real transaction advisory lock serializes contenders and releases after errors", async () => {
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  let entered!: () => void;
  const started = new Promise<void>((resolve) => {
    entered = resolve;
  });
  let secondEntered = false;
  const first = withEdgeLock(async () => {
    entered();
    await held;
    throw new Error("apply failed");
  });
  const rejected = first.catch((error: Error) => error);
  await started;
  const second = withEdgeLock(async () => {
    secondEntered = true;
  });
  await Bun.sleep(100);
  expect(secondEntered).toBe(false);
  release();
  expect(((await rejected) as Error).message).toBe("apply failed");
  await second;
  expect(secondEntered).toBe(true);
});

test("a rejected reload restores current within the coordinator edge lock", async () => {
  const root = await mkdtemp(join(tmpdir(), "ark-edge-lock-"));

  const first = renderEdgeL4Generation({ httpHostnames: [] });
  try {
    await installEdgeL4Generation({ root, generation: first, validatorSocket: "/v", validate });
    await expect(
      withEdgeLock(() =>
        installEdgeL4Generation({
          root,
          generation: renderEdgeL4Generation({ httpHostnames: ["new.example.com"] }),
          validatorSocket: "/v",
          validate,
          master: new HaproxyMaster("/fake", async () => "Success=0\n--\nrefused"),
        }),
      ),
    ).rejects.toThrow("reload failed");
    expect(await currentGeneration(root)).toBe(first.id);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test.each([false, true])(
  "drain failure stops under the lock and raises a critical alert (stop fails=%s)",
  async (stopFails) => {
    const calls: string[] = [];
    await expect(
      drainHaproxy(
        new Set(),
        {
          proxy: "haproxy",
          enforce: async () => ({
            proxy: "haproxy",
            active: ["100.64.1.2:443"],
            withdrawn: [],
            error: "CLI failed",
          }),
          stop: async () => {
            calls.push("stop");
            if (stopFails) throw new Error("stop unavailable");
          },
        },
        async (alert) => {
          expect(alert.severity).toBe("critical");
          expect(alert.title).toContain(stopFails ? "stop failed" : "backends were fenced");
          calls.push("alert");
          return undefined;
        },
      ),
    ).rejects.toThrow("CLI failed");
    expect(calls).toEqual(["stop", "alert"]);
    expect(await withEdgeLock(async () => "released")).toBe("released");
  },
);

test("edge.l4_apply configuration errors are recorded by coordinator operation handling", async () => {
  const old = process.env.ARK_EDGE_L4_DIR;
  process.env.ARK_EDGE_L4_DIR = join(tmpdir(), createId("missing"));
  const socket = process.env.ARK_HAPROXY_VALIDATOR_SOCKET;
  delete process.env.ARK_HAPROXY_VALIDATOR_SOCKET;
  const operation = await enqueue({ kind: "edge.l4_apply", targetIds: [createId("edge")], payload: {} });
  try {
    await processQueued(100, "edge.l4_apply");
    const [row] = await db.select().from(operations).where(eq(operations.id, operation.id));
    expect(row?.status).toBe("failed");
    expect(row?.error).toContain("ARK_HAPROXY_VALIDATOR_SOCKET");
  } finally {
    if (old === undefined) delete process.env.ARK_EDGE_L4_DIR;
    else process.env.ARK_EDGE_L4_DIR = old;
    if (socket === undefined) delete process.env.ARK_HAPROXY_VALIDATOR_SOCKET;
    else process.env.ARK_HAPROXY_VALIDATOR_SOCKET = socket;
    await db.delete(operations).where(eq(operations.id, operation.id));
  }
});
