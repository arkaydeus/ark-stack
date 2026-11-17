// FD-10: gate login origin and session separation (docs/design/front-door.md §3.5, §3.9.1).
//
// The suite (`gate-login.suite.ts`) runs in its own process and database: Better Auth is configured
// once per process from the environment (HTTPS admin and login origins, `__Host-` cookies, the edge
// token and the recorded edge peer), and its admin mode change revokes every session.

import { expect, test } from "bun:test";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import postgres from "postgres";

const root = resolve(import.meta.dir, "../..");

async function run(args: string[], env: Record<string, string | undefined>) {
  const child = Bun.spawn(args, { cwd: root, env, stdout: "pipe", stderr: "pipe" });
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { code, output: `${stdout}\n${stderr}` };
}

test("gate login origin and session separation (FD-10), in an isolated database and process", async () => {
  const source = process.env.DATABASE_URL;
  expect(source, "DATABASE_URL must name a disposable local PostgreSQL").toBeTruthy();
  expect(["localhost", "127.0.0.1", "::1", "[::1]"]).toContain(new URL(source!).hostname);
  const admin = postgres(source!, { max: 1 });
  const name = `ark_gate_${randomUUID().replaceAll("-", "")}`;
  const directory = await mkdtemp(join(tmpdir(), "ark-gate-login-"));
  await admin.unsafe(`CREATE DATABASE "${name}"`);
  try {
    const url = new URL(source!);
    url.pathname = `/${name}`;
    const env = {
      ...process.env,
      DATABASE_URL: url.toString(),
      BETTER_AUTH_URL: "https://admin.gate.example.com",
      BETTER_AUTH_TRUSTED_ORIGINS: "https://admin.gate.example.com",
      ARK_EDGE_GATE_TOKEN: randomBytes(32).toString("base64url"),
      // The edge-ts admin-network address in production; here the loopback peer.
      ARK_EDGE_PEER_ADDRESSES: "127.0.0.1",
      ARK_TAILNET_AUTH_ORIGIN: "https://admin.gate.example.com",
      ARK_EDGE_DIR: join(directory, "edge"),
      ARK_EMBEDDED_WORKERS: "0",
      ARK_EDGE_RELOAD_URL: "",
    };
    const migrated = await run(["bun", "server/src/migrate.ts"], env);
    expect(migrated.code, migrated.output).toBe(0);
    const suite = await run(["bun", "test", "./server/src/gate-login.suite.ts"], env);
    if (suite.code !== 0 || process.env.ARK_GATE_SUITE_VERBOSE) console.error(suite.output);
    expect(suite.code, suite.output.slice(-6000)).toBe(0);
    expect(suite.output).toMatch(/\b0 fail\b/);
  } finally {
    await admin.unsafe(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
    await admin.end();
    await rm(directory, { recursive: true, force: true });
  }
}, 180_000);
