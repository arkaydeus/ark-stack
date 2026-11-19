// Run the HTTP route controls against a database owned only by this suite.
import { expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";

import postgres from "postgres";

const root = resolve(import.meta.dir, "../..");

test("HTTP route controls apply safely in an isolated database", async () => {
  const source = process.env.DATABASE_URL;
  if (!source) throw new Error("Run with mise run test:db.");
  const url = new URL(source);
  expect(["localhost", "127.0.0.1", "[::1]"]).toContain(url.hostname);
  const admin = postgres(source, { max: 1 });
  const name = `ark_fd23_${randomUUID().replaceAll("-", "")}`;
  let created = false;
  try {
    await admin.unsafe(`CREATE DATABASE "${name}"`);
    created = true;
    url.pathname = `/${name}`;
    const env = { ...process.env, DATABASE_URL: url.toString() };
    for (const args of [["server/src/migrate.ts"], ["test", "./server/src/http-route-controls.suite.ts"]]) {
      const child = Bun.spawn([process.execPath, "--no-env-file", ...args], {
        cwd: root,
        env,
        stdout: "pipe",
        stderr: "pipe",
      });
      const [code, stdout, stderr] = await Promise.all([
        child.exited,
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
      ]);
      expect(code, `${stdout}\n${stderr}`).toBe(0);
      if (args[0] === "test") expect(stderr).toMatch(/\b0 fail\b/);
    }
  } finally {
    try {
      if (created) await admin.unsafe(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
    } finally {
      await admin.end();
    }
  }
}, 120_000);
