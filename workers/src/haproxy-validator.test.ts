import { expect, test } from "bun:test";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { renderEdgeL4Generation, validateGeneration, writeGeneration } from "@ark-stack/shared";

test("the validator kills a hung haproxy -c and returns bounded timeout diagnostics", async () => {
  const root = await mkdtemp(join(tmpdir(), "ark-validator-hang-"));
  const socket = join(root, "validate.sock");
  const binary = join(root, "haproxy-check");
  const generation = renderEdgeL4Generation({ httpHostnames: [] });
  await writeGeneration(root, generation);
  await writeFile(binary, "#!/bin/sh\nexec sleep 60\n");
  await chmod(binary, 0o755);
  const child = Bun.spawn([process.execPath, join(import.meta.dir, "haproxy-validator.ts")], {
    env: {
      ...process.env,
      ARK_EDGE_L4_DIR: root,
      ARK_HAPROXY_VALIDATOR_SOCKET: socket,
      ARK_HAPROXY_BIN: binary,
    },
    stdout: "ignore",
    stderr: "pipe",
  });
  try {
    const until = Date.now() + 3_000;
    while (!(await Bun.file(socket).exists()) && Date.now() < until) await Bun.sleep(20);
    const started = performance.now();
    const answer = await validateGeneration(socket, generation.id);
    expect(answer.ok).toBe(false);
    expect(answer.diagnostics).toContain("haproxy -c timed out");
    expect(answer.diagnostics.length).toBeLessThanOrEqual(4_000);
    expect(performance.now() - started).toBeLessThan(12_000);
  } finally {
    child.kill("SIGTERM");
    await child.exited;
    await rm(root, { recursive: true, force: true });
  }
}, 16_000);
