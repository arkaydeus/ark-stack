import { afterAll, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const directory = await mkdtemp(join(tmpdir(), "ark-executor-"));
const previous = process.env.ARK_PG_STAGING_DIR;
process.env.ARK_PG_STAGING_DIR = directory;
const { executorHandler, pruneStages, stageRepository } = await import("./pg-executor.ts");
afterAll(async () => {
  if (previous === undefined) delete process.env.ARK_PG_STAGING_DIR;
  else process.env.ARK_PG_STAGING_DIR = previous;
  await rm(directory, { recursive: true, force: true });
});
const token = "executor-token-0123456789abcdef";
const handle = executorHandler(token);
const request = (action: string, body: unknown, auth = token) =>
  handle(
    new Request(`http://localhost/v1/${action}`, {
      method: "POST",
      headers: { authorization: `Bearer ${auth}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
  );

test("HTTP rejects unauthenticated, arbitrary actions, malformed bodies and invalid parameters", async () => {
  expect((await request("stage", {}, "bad")).status).toBe(401);
  expect((await request("shell", { command: "echo unsafe" })).status).toBe(404);
  for (const [action, body] of [
    ["backup", { type: "expire" }],
    ["stage", { maxAgeSeconds: -1 }],
    ["stage", { maxAgeSeconds: 86401 }],
    ["prune-stages", { keep: 0 }],
    ["prune-stages", { keep: 11 }],
    ["stage", []],
  ] as const)
    expect((await request(action, body)).status).toBe(400);
  expect(
    (
      await handle(
        new Request("http://localhost/v1/stage", {
          method: "POST",
          headers: { authorization: `Bearer ${token}` },
          body: "{",
        }),
      )
    ).status,
  ).toBe(400);
});

test("stage reuses a fresh complete manifest and prune removes only old stages and stale partials", async () => {
  const ids = ["20261117T100000Z-aaaaaa", "20261117T110000Z-bbbbbb", "20261117T120000Z-cccccc"];
  for (const id of ids) {
    await mkdir(join(directory, id));
    await writeFile(
      join(directory, id, "manifest.json"),
      JSON.stringify({ stageId: id, createdAt: new Date().toISOString() }),
    );
  }
  const fresh = await stageRepository(240);
  expect(fresh.reused).toBe(true);
  expect(fresh.manifest.stageId).toBe(ids[2]!);
  const stale = join(directory, ".20261117T080000Z-dddddd.partial");
  const recent = join(directory, ".20261117T120000Z-eeeeee.partial");
  await mkdir(stale);
  await mkdir(recent);
  await utimes(stale, new Date(0), new Date(0));
  const pruned = await pruneStages(2);
  expect(pruned.removed).toContain(ids[0]!);
  expect(pruned.removed).toContain(stale.split("/").at(-1)!);
  expect(pruned.removed).not.toContain(recent.split("/").at(-1)!);
  expect(pruned.kept).toBe(2);
});

test("persisted leases protect a stalled export until release", async () => {
  const id = "20261117T090000Z-ffffff";
  const lease = "a".repeat(32);
  await mkdir(join(directory, id));
  await writeFile(join(directory, id, "manifest.json"), "{}");
  await mkdir(join(directory, ".leases"), { recursive: true });
  await writeFile(join(directory, ".leases", `${id}.${lease}`), String(Date.now() + 3600000));
  expect((await pruneStages(2)).removed).not.toContain(id);
  expect((await request("release-stage", { stageId: id, leaseId: "../../unsafe" })).status).toBe(400);
  expect((await request("release-stage", { stageId: id, leaseId: lease })).status).toBe(200);
  expect((await pruneStages(2)).removed).toContain(id);
});

test("entrypoint leaves archiving off for missing or short executor tokens", async () => {
  const bin = join(directory, "bin");
  await mkdir(bin);
  await writeFile(join(bin, "id"), "#!/bin/sh\necho 1000\n", { mode: 0o755 });
  await writeFile(join(bin, "docker-entrypoint.sh"), '#!/bin/sh\nprintf "%s\\n" "$@"\n', { mode: 0o755 });
  for (const invalidToken of ["", "too-short"]) {
    const child = Bun.spawn(
      ["sh", new URL("../../infra/backup/ark-postgres-entrypoint.sh", import.meta.url).pathname, "postgres"],
      {
        env: {
          ...process.env,
          PATH: `${bin}:/usr/bin:/bin`,
          ARK_PG_STANZA: "ark-platform",
          PGBACKREST_REPO2_CIPHER_PASS: "cipher",
          ARK_PG_EXECUTOR_TOKEN: invalidToken,
        },
        stdout: "pipe",
        stderr: "pipe",
      },
    );
    const [status, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    expect(status, stderr).toBe(0);
    expect(stdout.trim()).toBe("postgres");
    expect(stderr).toContain("WAL archiving and backups are disabled");
  }
});
