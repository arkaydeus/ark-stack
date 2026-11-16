import { expect, test } from "bun:test";
import { chmod, copyFile, mkdir, mkdtemp, rm, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { EventEmitter } from "node:events";

import { configureEdgeAuthKey, promptHidden } from "./install-edge-auth.ts";

const root = resolve(import.meta.dir, "..");
const installedKey = "tskey-auth-installed-secret";

test("preserved key configuration leaves the env file byte-for-byte unchanged and does not prompt", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ark-auth-preserved-"));
  try {
    const envPath = join(directory, ".env");
    const source = `# Keep operator comments\nTS_EDGE_AUTHKEY=${installedKey}\nOTHER=value\n`;
    await Bun.write(envPath, source);
    const env = { TS_EDGE_AUTHKEY: "tskey-auth-inherited-other" };
    expect(
      await configureEdgeAuthKey(envPath, {
        env,
        interactive: true,
        log: () => {},
        prompt: async () => {
          throw new Error("a preserved key must not prompt");
        },
      }),
    ).toBe("kept");
    expect(env.TS_EDGE_AUTHKEY).toBe(installedKey);
    expect(await Bun.file(envPath).text()).toBe(source);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "ark-install-auth-"));
  for (const path of ["scripts", "bin", "infra/platform", "tmp/certs/database"]) {
    await mkdir(join(directory, path), { recursive: true });
  }
  for (const name of ["install.ts", "install-edge-auth.ts", "edge-namespace.ts", "pgbouncer-bootstrap.ts"]) {
    await copyFile(join(root, "scripts", name), join(directory, "scripts", name));
  }
  await symlink(join(root, "node_modules"), join(directory, "node_modules"));
  // The PgBouncer bootstrap uses the worker renderer and its X.509 helpers.
  await symlink(join(root, "server"), join(directory, "server"));
  for (const name of ["Caddyfile", "serve.json"]) {
    await copyFile(join(root, "infra/platform", name), join(directory, "infra/platform", name));
  }
  // Existing certs avoid invoking openssl; Docker is replaced only inside this disposable install.
  for (const name of ["fullchain.pem", "privkey.pem"]) {
    await Bun.write(join(directory, "tmp/certs/database", name), "fixture");
  }
  await Bun.write(
    join(directory, "bin/docker"),
    `#!${process.execPath}
import { appendFileSync } from "node:fs";
appendFileSync(process.env.INSTALL_CALLS, JSON.stringify({args:process.argv.slice(2), key:process.env.TS_EDGE_AUTHKEY}) + "\\n");
`,
  );
  await chmod(join(directory, "bin/docker"), 0o700);
  return directory;
}

for (const inherited of ["tskey-auth-inherited-other", ""]) {
  test(`installer Docker children receive the installed key over ${inherited ? "another key" : "an empty export"}`, async () => {
    const directory = await fixture();
    try {
      const envPath = join(directory, ".env");
      await Bun.write(envPath, `TS_EDGE_AUTHKEY=${installedKey}\n`);
      const child = Bun.spawn([process.execPath, "scripts/install.ts"], {
        cwd: directory,
        env: {
          ...process.env,
          PATH: `${directory}/bin:${process.env.PATH}`,
          TS_EDGE_AUTHKEY: inherited,
          ARK_INSTALL_NONINTERACTIVE: "1",
          ARK_INSTALL_SKIP_DOCKER: "0",
          INSTALL_CALLS: join(directory, "calls"),
        },
        stdout: "pipe",
        stderr: "pipe",
      });
      const [code, stdout, stderr] = await Promise.all([
        child.exited,
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
      ]);
      expect(code, stderr).toBe(0);
      const calls = (await Bun.file(join(directory, "calls")).text())
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      expect(calls.some((call) => call.args.includes("compose"))).toBe(true);
      expect(calls.map((call) => ({ args: call.args, key: call.key }))).toEqual(
        calls.map((call) => ({ args: call.args, key: installedKey })),
      );
      expect(
        (await Bun.file(envPath).text()).split("\n").filter((line) => line.startsWith("TS_EDGE_AUTHKEY=")),
      ).toEqual([`TS_EDGE_AUTHKEY=${installedKey}`]);
      expect(stdout + stderr).not.toContain(installedKey);
      expect((await stat(envPath)).mode & 0o777).toBe(0o600);
      expect((await stat(join(directory, "tmp/db-ingress"))).isDirectory()).toBe(true);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
}

test("prompt selection writes a normalized key without echoing it", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ark-auth-prompt-"));
  try {
    const envPath = join(directory, ".env");
    await Bun.write(envPath, "TS_EDGE_AUTHKEY=\n");
    const env: Record<string, string | undefined> = {};
    const logs: string[] = [];
    let prompts = 0;
    expect(
      await configureEdgeAuthKey(envPath, {
        env,
        interactive: true,
        log: (line) => logs.push(line),
        prompt: async (question) => {
          expect(question).toContain("Tailscale auth key");
          prompts++;
          return ` ${installedKey} `;
        },
      }),
    ).toBe("set");
    expect(prompts).toBe(1);
    expect(env.TS_EDGE_AUTHKEY).toBe(installedKey);
    expect(await Bun.file(envPath).text()).toBe(`TS_EDGE_AUTHKEY=${installedKey}\n`);
    expect(logs.join("\n")).not.toContain(installedKey);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("invalid inherited key aborts the installer after secret merge and before any Docker command", async () => {
  const directory = await fixture();
  try {
    await Bun.write(join(directory, ".env"), "TS_EDGE_AUTHKEY=\n");
    const child = Bun.spawn([process.execPath, "scripts/install.ts"], {
      cwd: directory,
      env: {
        ...process.env,
        PATH: `${directory}/bin:${process.env.PATH}`,
        TS_EDGE_AUTHKEY: "invalid-key",
        ARK_INSTALL_NONINTERACTIVE: "1",
        ARK_INSTALL_SKIP_DOCKER: "0",
        INSTALL_CALLS: join(directory, "calls"),
      },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [code, stderr] = await Promise.all([
      child.exited,
      new Response(child.stderr).text(),
      new Response(child.stdout).text(),
    ]);
    expect(code).not.toBe(0);
    expect(stderr).toContain("must be a Tailscale auth key");
    expect(await Bun.file(join(directory, "calls")).exists()).toBe(false);
    const merged = await Bun.file(join(directory, ".env")).text();
    expect(merged).toContain("ARK_EDGE_GATE_TOKEN=");
    expect(merged).toContain("TS_EDGE_AUTHKEY=\n");
    expect(merged).not.toContain("invalid-key");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("skipping the prompt leaves the key absent and never prompts in noninteractive mode", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ark-auth-skip-"));
  try {
    const envPath = join(directory, ".env");
    await Bun.write(envPath, "A=1\n");
    const env: Record<string, string | undefined> = { ARK_INSTALL_NONINTERACTIVE: "1" };
    expect(
      await configureEdgeAuthKey(envPath, {
        env,
        prompt: async () => {
          throw new Error("must not prompt");
        },
      }),
    ).toBe("missing");
    expect(env.TS_EDGE_AUTHKEY).toBe("");
    expect(await Bun.file(envPath).text()).toBe("A=1\n");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("hidden prompt uses raw mode, handles erase and restores input without echoing the key", async () => {
  class Input extends EventEmitter {
    modes: boolean[] = [];
    paused = false;
    setRawMode(enabled: boolean) {
      this.modes.push(enabled);
    }
    resume() {}
    pause() {
      this.paused = true;
    }
    setEncoding() {}
  }
  const input = new Input();
  const output: string[] = [];
  const result = promptHidden("Key: ", input, { write: (value) => output.push(value) });
  input.emit("data", "tskey-auth-typo\u007f\u007f\u007f\u007fsecret\r");
  expect(await result).toBe("tskey-auth-secret");
  expect(output).toEqual(["Key: ", "\n"]);
  expect(input.modes).toEqual([true, false]);
  expect(input.paused).toBe(true);
  expect(input.listenerCount("data")).toBe(0);
});
