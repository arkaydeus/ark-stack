import { afterEach, expect, test } from "bun:test";
import { chmod, cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const source = resolve(import.meta.dir, "test-db.ts");
const fixtures: string[] = [];
const processes = new Set<ReturnType<typeof Bun.spawn>>();
afterEach(async () => {
  for (const child of processes) {
    if (child.exitCode === null) child.kill("SIGKILL");
    await child.exited;
  }
  processes.clear();
  for (const directory of fixtures.splice(0)) await rm(directory, { recursive: true, force: true });
});

async function fixture(mode = "ok") {
  // Exercise decoding as well as shell quoting; these are real subprocesses in a copied tree.
  const directory = await mkdtemp(join(tmpdir(), "ark test é'"));
  fixtures.push(directory);
  for (const path of ["scripts", "server/src", "node_modules/postgres", "bin"])
    await mkdir(join(directory, path), { recursive: true });
  await cp(source, join(directory, "scripts/test-db.ts"));
  await writeFile(join(directory, "package.json"), '{"type":"module"}');
  await writeFile(
    join(directory, "node_modules/postgres/package.json"),
    '{"type":"module","main":"index.js"}',
  );
  await writeFile(
    join(directory, "node_modules/postgres/index.js"),
    `
    export default function () {
      const sql = async () => { ${mode === "readiness-signal" ? "await Bun.write(" + JSON.stringify(join(directory, "ready")) + ', "1"); await Bun.sleep(500);' : ""} return []; };
      sql.end = async () => {};
      return sql;
    }
  `,
  );
  const checkEnv = `
    if (process.env.ARK_ALERT_WEBHOOK) await fetch(process.env.ARK_ALERT_WEBHOOK);
    const forbidden = ["ARK_ALERT_WEBHOOK", "ARK_BACKUP_EXECUTE", "RESTIC_REPOSITORY", "AWS_SECRET_ACCESS_KEY", "DNS_API_TOKEN", "STALWART_URL", "DOTENV_SENTINEL", "ARK_EMBEDDED_WORKERS", "BUN_OPTIONS"];
    if (forbidden.some(key => process.env[key] !== undefined)) throw new Error("provider environment leaked");
    if (!process.env.DATABASE_URL?.includes("127.0.0.1:15432")) throw new Error("wrong database");
    if (!process.env.ARK_ROOT_KEY?.startsWith("test-db-")) throw new Error("wrong test secrets");
  `;
  const hold = `await Bun.write(${JSON.stringify(join(directory, "child.pid"))}, String(process.pid)); setInterval(() => {}, 1000); await new Promise(() => {});`;
  await writeFile(
    join(directory, "server/src/migrate.ts"),
    checkEnv +
      (mode === "migration-signal"
        ? hold
        : mode === "migration-fail"
          ? 'throw new Error("migration fixture failure");'
          : ""),
  );
  await writeFile(
    join(directory, "server/src/safe.test.ts"),
    `
    import { test, expect } from "bun:test";
    ${checkEnv}
    ${mode === "test-signal" || mode === "stubborn-child" ? (mode === "stubborn-child" ? 'process.on("SIGTERM", () => {});' : "") + hold : 'test("isolated fixture", () => expect(true).toBe(' + (mode === "test-fail" ? "false" : "true") + "));"}
  `,
  );
  await writeFile(join(directory, ".env"), "DOTENV_SENTINEL=loaded\nARK_BACKUP_EXECUTE=1\n");
  // A fake CLI records operations on disk so parent-signal and retry assertions cover the
  // actual entrypoint, rather than a mocked cleanup implementation.
  await writeFile(
    join(directory, "bin/docker"),
    `#!${process.execPath} --no-env-file
    import { existsSync, appendFileSync, readFileSync, writeFileSync, unlinkSync } from "node:fs";
    const dir = ${JSON.stringify(directory)}, mode = ${JSON.stringify(mode)};
    const args = process.argv.slice(2), command = args[0];
    appendFileSync(dir + "/calls", JSON.stringify(args) + "\\n");
    const state = dir + "/container";
    if (command === "run") {
      writeFileSync(state, args[args.indexOf("--name") + 1]);
      if (mode === "startup-signal") { writeFileSync(dir + "/ready", "1"); await Bun.sleep(500); }
      if (mode === "startup-fail") { console.error("creation fixture failure"); process.exit(1); }
      console.log("id");
    } else if (command === "port") console.log("127.0.0.1:15432");
    else if (command === "inspect") {
      if (mode === "cleanup-signal") { writeFileSync(dir + "/ready", "1"); await Bun.sleep(500); }
      if (mode === "inspect-fail") { console.error("Cannot connect to Docker daemon"); process.exit(1); }
      if (mode === "inspect-retry" && !existsSync(dir + "/retried")) { writeFileSync(dir + "/retried", "1"); console.error("daemon restarting"); process.exit(1); }
      if (!existsSync(state) || mode === "missing") { console.error("Error: No such object: " + args.at(-1)); process.exit(1); }
      console.log(mode === "foreign" ? "0" : "1");
    } else if (command === "rm") {
      if (mode === "rm-fail") { console.error("removal fixture failure"); process.exit(1); }
      if (existsSync(state)) unlinkSync(state);
      console.log("removed");
    } else { console.error("unexpected command " + args); process.exit(1); }
  `,
  );
  await chmod(join(directory, "bin/docker"), 0o755);
  const env = {
    ...process.env,
    PATH: join(directory, "bin") + ":" + process.env.PATH,
    ARK_ALERT_WEBHOOK: process.env.ARK_ALERT_WEBHOOK ?? "http://127.0.0.1:1",
    ARK_BACKUP_EXECUTE: "1",
    RESTIC_REPOSITORY: "live",
    AWS_SECRET_ACCESS_KEY: "live",
    DNS_API_TOKEN: "live",
    STALWART_URL: "http://example.invalid",
    ARK_EMBEDDED_WORKERS: "1",
    BUN_OPTIONS: "",
  };
  function start(args: string[] = []) {
    const child = Bun.spawn(
      [process.execPath, "--no-env-file", join(directory, "scripts/test-db.ts"), ...args],
      { cwd: directory, env, stdout: "pipe", stderr: "pipe" },
    );
    processes.add(child);
    const output = Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text()]);
    return {
      child,
      done: async () => {
        const code = await child.exited;
        const [stdout, stderr] = await output;
        return { code, stdout, stderr };
      },
    };
  }
  return {
    directory,
    start,
    calls: async () =>
      (await readFile(join(directory, "calls"), "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as string[]),
  };
}

async function waitFile(path: string) {
  const deadline = Date.now() + 6000;
  while (!(await Bun.file(path).exists())) {
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${path}`);
    await Bun.sleep(20);
  }
}

test("filters inherited providers and dotenv, and removes the DB in a path with spaces and Unicode", async () => {
  let requests = 0;
  const server = Bun.serve({
    port: 0,
    fetch() {
      requests++;
      return new Response("ok");
    },
  });
  const old = process.env.ARK_ALERT_WEBHOOK;
  process.env.ARK_ALERT_WEBHOOK = server.url.href;
  try {
    const f = await fixture();
    const result = await f.start().done();
    expect(result.code).toBe(0);
    expect(result.stderr).toContain("test-db: removed");
    expect((await f.calls()).filter((args) => args[0] === "rm")).toHaveLength(1);
    expect(requests).toBe(0);
  } finally {
    server.stop(true);
    if (old === undefined) delete process.env.ARK_ALERT_WEBHOOK;
    else process.env.ARK_ALERT_WEBHOOK = old;
  }
});

for (const mode of ["test-fail", "migration-fail", "startup-fail"])
  test(`${mode} preserves failure and cleans the created container`, async () => {
    const f = await fixture(mode);
    expect((await f.start().done()).code).not.toBe(0);
    expect((await f.calls()).filter((args) => args[0] === "rm")).toHaveLength(1);
  });

for (const mode of ["inspect-fail", "rm-fail"])
  test(`${mode} retries boundedly and never claims removal`, async () => {
    const f = await fixture(mode);
    const result = await f.start().done();
    expect(result.code).not.toBe(0);
    expect(result.stderr).toContain("cleanup failed");
    expect(result.stderr).not.toContain("test-db: removed");
    expect(
      (await f.calls()).filter((args) => args[0] === (mode === "inspect-fail" ? "inspect" : "rm")),
    ).toHaveLength(3);
  });

test("transient inspect failure is retried successfully", async () => {
  const f = await fixture("inspect-retry");
  expect((await f.start().done()).code).toBe(0);
  expect((await f.calls()).filter((args) => args[0] === "inspect")).toHaveLength(2);
});

for (const mode of [
  "startup-signal",
  "readiness-signal",
  "migration-signal",
  "test-signal",
  "stubborn-child",
  "cleanup-signal",
])
  test(`${mode} waits for cleanup and stops children`, async () => {
    const f = await fixture(mode);
    const run = f.start();
    await waitFile(
      join(
        f.directory,
        mode.includes("child") || mode === "migration-signal" || mode === "test-signal"
          ? "child.pid"
          : "ready",
      ),
    );
    run.child.kill("SIGTERM");
    const result = await run.done();
    expect(result.code).toBe(143);
    expect(result.stderr).toContain("test-db: removed");
    expect((await f.calls()).filter((args) => args[0] === "rm")).toHaveLength(1);
    if (await Bun.file(join(f.directory, "child.pid")).exists()) {
      const pid = Number(await Bun.file(join(f.directory, "child.pid")).text());
      expect(() => process.kill(pid, 0)).toThrow();
    }
    if (mode !== "test-signal" && mode !== "stubborn-child" && mode !== "cleanup-signal")
      expect(result.stderr).not.toContain("running bun test");
  }, 12_000);

for (const [signal, status] of [
  ["SIGINT", 130],
  ["SIGHUP", 129],
] as const)
  test(`${signal} stops the active child and removes its database`, async () => {
    const f = await fixture("test-signal");
    const run = f.start();
    await waitFile(join(f.directory, "child.pid"));
    run.child.kill(signal);
    expect((await run.done()).code).toBe(status);
    expect((await f.calls()).filter((args) => args[0] === "rm")).toHaveLength(1);
    const pid = Number(await Bun.file(join(f.directory, "child.pid")).text());
    expect(() => process.kill(pid, 0)).toThrow();
  });

test("up emits eval-safe exports and an isolated helper; down rejects a second removal", async () => {
  const f = await fixture();
  const result = await f.start(["up"]).done();
  expect(result.code).toBe(0);
  expect((await f.calls()).some((args) => args[0] === "rm")).toBe(false);
  const shell = Bun.spawn(["/bin/sh", "-c", result.stdout + "\nark_test_db server/src/safe.test.ts"], {
    env: { ...process.env, ARK_BACKUP_EXECUTE: "1", ARK_ALERT_WEBHOOK: "http://127.0.0.1:1" },
    stdout: "pipe",
    stderr: "pipe",
  });
  const shellOutput = new Response(shell.stderr).text();
  expect(await shell.exited, await shellOutput).toBe(0);
  const name = await Bun.file(join(f.directory, "container")).text();
  expect((await f.start(["down", name]).done()).code).toBe(0);
  const missing = await f.start(["down", name]).done();
  expect(missing.code).not.toBe(0);
  expect(missing.stderr).toContain("No such test-db container");
  expect(missing.stdout).not.toContain("Removed");
});

for (const mode of ["foreign", "ok"])
  test(`down refuses ${mode === "foreign" ? "a missing ownership label" : "an arbitrary name"}`, async () => {
    const f = await fixture(mode);
    const name = "ark-test-db-0123456789ab";
    await writeFile(join(f.directory, "container"), name);
    const result = await f.start(["down", mode === "foreign" ? name : "platform-postgres"]).done();
    expect(result.code).not.toBe(0);
    expect(result.stderr).toContain("Refusing to remove");
    if (mode === "foreign") expect((await f.calls()).some((args) => args[0] === "rm")).toBe(false);
  });

// CI enables this bounded integration check. It uses only the runner's own labelled resources.
test.skipIf(process.env.ARK_TEST_DB_DOCKER !== "1")(
  "two real concurrent databases have distinct ports/data and are both removed",
  async () => {
    const names: string[] = [];
    const children: ReturnType<typeof Bun.spawn>[] = [];
    try {
      const runs = [0, 1].map(() => {
        const child = Bun.spawn([process.execPath, "--no-env-file", source, "up"], {
          stdout: "pipe",
          stderr: "pipe",
        });
        children.push(child);
        return Promise.all([
          child.exited,
          new Response(child.stdout).text(),
          new Response(child.stderr).text(),
        ]);
      });
      const results = await Promise.all(runs);
      const urls: string[] = [];
      for (const [code, stdout, stderr] of results) {
        const name = /Started and migrated (ark-test-db-[a-f0-9]{12})/.exec(stdout)?.[1];
        if (name) names.push(name);
        expect(code, stderr).toBe(0);
        urls.push(/export DATABASE_URL='([^']+)'/.exec(stdout)![1]!);
      }
      expect(new Set(names).size).toBe(2);
      expect(new Set(urls.map((url) => new URL(url).port)).size).toBe(2);
      const { default: postgres } = await import("postgres");
      const databases = urls.map((url) => postgres(url, { max: 1 }));
      try {
        await databases[0]!`CREATE TABLE isolation_marker (id int)`;
        const rows = await databases[1]!`SELECT to_regclass('public.isolation_marker') AS marker`;
        expect(rows[0]!.marker).toBeNull();
      } finally {
        await Promise.all(databases.map((sql) => sql.end({ timeout: 2 })));
      }
    } finally {
      await Promise.all(children.map((child) => child.exited));
      for (const name of names) {
        const child = Bun.spawn([process.execPath, "--no-env-file", source, "down", name], {
          stdout: "pipe",
          stderr: "pipe",
        });
        const stderr = new Response(child.stderr).text();
        expect(await child.exited, await stderr).toBe(0);
        const inspect = Bun.spawn(["docker", "inspect", name], { stdout: "ignore", stderr: "ignore" });
        expect(await inspect.exited).not.toBe(0);
      }
    }
  },
  120_000,
);

test.skipIf(process.env.ARK_TEST_DB_DOCKER !== "1")(
  "real alerts and backup tests cannot use inherited providers or native tools",
  async () => {
    let requests = 0;
    const recorder = Bun.serve({
      port: 0,
      fetch() {
        requests++;
        return new Response("ok");
      },
    });
    const directory = await mkdtemp(join(tmpdir(), "ark-provider-test-"));
    fixtures.push(directory);
    const marker = join(directory, "native-call");
    for (const tool of ["restic", "pgbackrest", "pg_dump"]) {
      const path = join(directory, tool);
      await writeFile(path, '#!/bin/sh\ntouch "' + marker + '"\nexit 1\n');
      await chmod(path, 0o755);
    }
    try {
      const child = Bun.spawn(
        [
          process.execPath,
          "--no-env-file",
          source,
          "server/src/modules/alerts.test.ts",
          "server/src/modules/backups.test.ts",
          "--test-name-pattern",
          "does not re-raise|disabled execution",
        ],
        {
          cwd: resolve(import.meta.dir, ".."),
          env: {
            ...process.env,
            PATH: directory + ":" + process.env.PATH,
            ARK_ALERT_WEBHOOK: recorder.url.href,
            ARK_BACKUP_EXECUTE: "1",
            RESTIC_REPOSITORY: "live",
            STALWART_URL: "http://example.invalid",
            AWS_SECRET_ACCESS_KEY: "live",
            DNS_API_TOKEN: "live",
          },
          stdout: "pipe",
          stderr: "pipe",
        },
      );
      processes.add(child);
      const output = Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text()]);
      const code = await child.exited;
      expect(code, (await output).join("\n")).toBe(0);
      expect(requests).toBe(0);
      expect(await Bun.file(marker).exists()).toBe(false);
    } finally {
      recorder.stop(true);
    }
  },
  120_000,
);
