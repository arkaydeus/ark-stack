import { expect, test } from "bun:test";
import { resolve } from "node:path";

test("database-backed edge planning, ACME selection and safe admin mode changes", async () => {
  // Separate process/database because a successful mode change revokes every session.
  const child = Bun.spawn(["bun", "server/src/edge-test-fixture.ts"], {
    cwd: resolve(import.meta.dir, "../.."),
    env: process.env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  expect(code, `${stdout}\n${stderr}`).toBe(0);
}, 30_000);
