import { afterEach, expect, spyOn, test } from "bun:test";
import * as fs from "node:fs/promises";

import { EdgeTestRuntime } from "./runtime.ts";

const spies: { mockRestore(): void }[] = [];
afterEach(() => {
  for (const spy of spies.splice(0)) spy.mockRestore();
});

for (const code of ["EACCES", "EPERM"])
  test(`${code} restores host ownership in a networkless container and retries removal once`, async () => {
    const denied = Object.assign(new Error("denied"), { code });
    const remove = spyOn(fs, "rm").mockRejectedValueOnce(denied).mockResolvedValue(undefined);
    spies.push(remove);
    const spawn = spyOn(Bun, "spawn").mockReturnValue({
      exited: Promise.resolve(0),
      stdout: new Blob([""]).stream(),
      stderr: new Blob([""]).stream(),
    } as unknown as ReturnType<typeof Bun.spawn>);
    spies.push(spawn);
    const runtime = new EdgeTestRuntime("/tmp/fixture with spaces", "test-network", "already-pinned-image");
    const first = runtime.cleanup();
    expect(runtime.cleanup()).toBe(first);
    await first;
    expect(remove.mock.calls).toEqual([
      [runtime.directory, { recursive: true, force: true }],
      [runtime.directory, { recursive: true, force: true }],
    ]);
    expect(spawn.mock.calls[0]?.[0]).toEqual([
      "docker",
      "run",
      "--rm",
      "--network",
      "none",
      "--user",
      "0:0",
      "--entrypoint",
      "chown",
      "--volume",
      `${runtime.directory}:/work`,
      "already-pinned-image",
      "-R",
      `${process.getuid!()}:${process.getgid!()}`,
      "/work",
    ]);
    await expect(runtime.docker("run", "foreign")).rejects.toThrow("shutting down");
  });

for (const [code, image] of [
  ["EIO", "image"],
  ["EACCES", undefined],
] as const)
  test(`cleanup propagates ${code} with image ${image} without Docker fallback`, async () => {
    const denied = Object.assign(new Error("denied"), { code });
    const remove = spyOn(fs, "rm").mockRejectedValue(denied);
    const spawn = spyOn(Bun, "spawn");
    spies.push(remove, spawn);
    await expect(new EdgeTestRuntime("/fixture", "network", image).cleanup()).rejects.toBe(denied);
    expect(remove).toHaveBeenCalledTimes(1);
    expect(spawn).not.toHaveBeenCalled();
  });

test("cleanup propagates a failed ownership repair rather than claiming removal", async () => {
  const remove = spyOn(fs, "rm").mockRejectedValue(Object.assign(new Error("denied"), { code: "EPERM" }));
  const spawn = spyOn(Bun, "spawn").mockReturnValue({
    exited: Promise.resolve(1),
    stdout: new Blob([""]).stream(),
    stderr: new Blob(["chown denied"]).stream(),
  } as unknown as ReturnType<typeof Bun.spawn>);
  spies.push(remove, spawn);
  await expect(new EdgeTestRuntime("/fixture", "network", "image").cleanup()).rejects.toThrow("chown denied");
  expect(remove).toHaveBeenCalledTimes(1);
});
