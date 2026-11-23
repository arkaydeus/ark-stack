import { expect, test } from "bun:test";
import { chmod, copyFile, mkdir, mkdtemp, realpath, rm, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { EventEmitter } from "node:events";

import { configureEdgeAuthKey, promptHidden, readHidden } from "./install-edge-auth.ts";
import { composeBuiltImages } from "./install-images.ts";

const root = resolve(import.meta.dir, "..");
const installedKey = "tskey-auth-installed-secret";
const revision = "a".repeat(40);
// A full installer run spawns dozens of fake `docker` processes (each a Bun startup); the
// published-image path alone pulls, inspects and tags twelve images. That takes 1-3 s on a quiet
// runner, so Bun's 5 s default leaves no headroom on a loaded one.
const installerTimeout = 30_000;

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
  for (const path of ["scripts", "bin", "infra/platform", "infra/mail", "tmp/certs/database"]) {
    await mkdir(join(directory, path), { recursive: true });
  }
  for (const name of [
    "install.ts",
    "install-edge-auth.ts",
    "install-docker-ipv6.ts",
    "install-edge-l4.ts",
    "install-images.ts",
    "install-host-hardening.ts",
    "install-mail-submission.ts",
    "host-inventory.ts",
    "host-deployment-lock.ts",
    "edge-namespace.ts",
    "pgbouncer-bootstrap.ts",
  ]) {
    await copyFile(join(root, "scripts", name), join(directory, "scripts", name));
  }
  await symlink(join(root, "node_modules"), join(directory, "node_modules"));
  // The PgBouncer bootstrap uses the worker renderer and its X.509 helpers.
  await symlink(join(root, "server"), join(directory, "server"));
  for (const name of ["Caddyfile", "serve.json"]) {
    await copyFile(join(root, "infra/platform", name), join(directory, "infra/platform", name));
  }
  await copyFile(join(root, "Dockerfile"), join(directory, "Dockerfile"));
  await copyFile(
    join(root, "infra/platform/docker-compose.yml"),
    join(directory, "infra/platform/docker-compose.yml"),
  );
  await copyFile(
    join(root, "infra/mail/docker-compose.yml"),
    join(directory, "infra/mail/docker-compose.yml"),
  );
  // Existing certs avoid invoking openssl; Docker is replaced only inside this disposable install.
  for (const name of ["fullchain.pem", "privkey.pem"]) {
    await Bun.write(join(directory, "tmp/certs/database", name), "fixture");
  }
  await Bun.write(
    join(directory, "bin/docker"),
    `#!${process.execPath}
import { appendFileSync } from "node:fs";
if (process.argv.includes("ps") && process.argv.includes("stalwart")) console.log("stalwart-id");
if (process.argv.includes("{{json .NetworkSettings.Networks}}")) console.log(JSON.stringify({
  "mail-public": { IPAddress: "172.16.0.3", GlobalIPv6Address: "" },
}));
if (process.argv.includes("--config")) console.log(JSON.stringify({
  methodResponses: [["x:NetworkListener/get", {
    list: [{ protocol: "smtp", bind: { "[::]:587": true }, useTls: true, tlsImplicit: false }],
  }, "op"]],
}));
if (process.argv.some((arg) => arg.includes("id -u"))) console.log(process.argv.some((arg) => arg.startsWith("haproxy:")) ? "99\\n---" : "1000\\n---");
if (process.argv.some((arg) => arg.includes("org.opencontainers.image.revision"))) console.log("${revision}");
appendFileSync(process.env.INSTALL_CALLS, JSON.stringify({args:process.argv.slice(2), key:process.env.TS_EDGE_AUTHKEY}) + "\\n");
if (process.env.INSTALL_FAIL_BUILD === "1" && process.argv.includes("build")) process.exit(42);
`,
  );
  await chmod(join(directory, "bin/docker"), 0o700);
  return directory;
}

async function runInstaller(directory: string, args: string[], env: Record<string, string>) {
  const child = Bun.spawn([process.execPath, "scripts/install.ts", ...args], {
    cwd: directory,
    env: {
      ...process.env,
      PATH: `${directory}/bin:${process.env.PATH}`,
      ARK_INSTALL_NONINTERACTIVE: "1",
      ARK_INSTALL_SKIP_DOCKER: "0",
      INSTALL_CALLS: join(directory, "calls"),
      ...env,
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
  return stdout;
}

test.each(["0", "1"])(
  "hardening-only keeps the running API and reconciler in place (mail=%s)",
  async (mail) => {
    const directory = await fixture();
    try {
      await Bun.write(join(directory, ".env"), `TS_EDGE_AUTHKEY=${installedKey}\nARK_MAIL_ENABLED=${mail}\n`);
      await Bun.write(
        join(directory, "scripts/install-host-hardening.ts"),
        `
export const hostFirewallPath = "/fixture/ark-host.nft";
export const hostMetricsPath = "/fixture/host-metrics";
export const enrollVps = () => { throw new Error("unexpected enrolment"); };
export const hostCommand = () => { throw new Error("unexpected host command"); };
export async function installHostHardening(configure) {
  const config = await configure({ ports: [22] });
  console.log("Fixture hardening applied", config.mailEnabled);
}
`,
      );
      const stdout = await runInstaller(directory, ["--harden-vps"], {
        ARK_INSTALL_HARDEN_ONLY: "1",
        ARK_SETUP_DEFER_EDGE_ENROLMENT: "1",
      });
      expect(stdout).toContain(`Fixture hardening applied ${mail === "1"}`);
      expect(await Bun.file(join(directory, "calls")).exists()).toBe(false);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test.each([false, true])(
  "installer resolves Compose image tags and rejects tracked changes (dirty=%s)",
  async (dirty) => {
    const directory = await fixture();
    try {
      const envPath = join(directory, ".env");
      const composePath = join(directory, "infra/platform/docker-compose.yml");
      const gitPath = join(directory, "bin/git");
      await Bun.write(envPath, `TS_EDGE_AUTHKEY=${installedKey}\nARK_VERSION=v2\nARK_MAIL_ENABLED=0\n`);
      await Bun.write(
        gitPath,
        `#!/bin/sh
case "$*" in
  *rev-parse*) printf '%s\\n' '${revision}' ;;
  *status*) ${dirty ? "{ sleep 0.05; printf ' M Dockerfile\\n'; } &" : ":"} ;;
esac
`,
      );
      await chmod(gitPath, 0o700);
      const stdout = await runInstaller(directory, [], { ARK_VERSION: "", ARK_INSTALL_BUILD_IMAGES: "0" });
      const calls = (await Bun.file(join(directory, "calls")).text())
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line).args as string[]);
      const tags = calls.filter(([command]) => command === "tag").map((args) => args[2]!);
      if (dirty) {
        expect(stdout).toContain("the checkout has local changes");
        expect(tags).toEqual([]);
        expect(calls.some((args) => args.includes("build"))).toBe(true);
      } else {
        const local = composeBuiltImages(await Bun.file(composePath).text()).map((name) => `${name}:local`);
        expect(stdout).toContain("skipping the local build");
        expect(tags).toEqual(local);
        expect(calls.some((args) => args.includes("build"))).toBe(false);
        expect(calls.some((args) => args.includes("--wait") && args.includes("api"))).toBe(true);
        const docker = Bun.which("docker");
        if (docker && Bun.spawnSync([docker, "compose", "version"]).exitCode === 0) {
          const config = Bun.spawnSync(
            [docker, "compose", "--env-file", envPath, "-f", composePath, "config", "--images"],
            {
              cwd: directory,
              env: { ...process.env, ARK_VERSION: "" },
            },
          );
          expect(config.exitCode, config.stderr.toString()).toBe(0);
          expect(config.stdout.toString().trim().split("\n")).toEqual(expect.arrayContaining(tags));
        }
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
  installerTimeout,
);

for (const inherited of ["tskey-auth-inherited-other", ""]) {
  test(
    `installer Docker children receive the installed key over ${inherited ? "another key" : "an empty export"}`,
    async () => {
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
        const composeCalls = calls.filter((call) => call.args[0] === "compose");
        expect(composeCalls.length).toBeGreaterThan(0);
        const generatedEnv = await realpath(envPath);
        for (const { args } of composeCalls) {
          const envFlag = args.indexOf("--env-file");
          expect(envFlag).toBeGreaterThan(0);
          expect(args[envFlag + 1]).toBe(generatedEnv);
        }
        expect(stdout).toContain("Setup URL: http://localhost:3000");
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
    },
    installerTimeout,
  );
}

test(
  "the first install passes its generated environment to Compose",
  async () => {
    const directory = await fixture();
    try {
      await copyFile(join(root, ".env.example"), join(directory, ".env.example"));
      const child = Bun.spawn([process.execPath, "scripts/install.ts"], {
        cwd: directory,
        env: {
          ...process.env,
          PATH: `${directory}/bin:${process.env.PATH}`,
          TS_EDGE_AUTHKEY: "",
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
      const envPath = await realpath(join(directory, ".env"));
      const calls = (await Bun.file(join(directory, "calls")).text()).trim().split("\n");
      const build = calls
        .map((line) => JSON.parse(line).args as string[])
        .find((args) => args.includes("build"));
      expect(build?.slice(0, 3)).toEqual(["compose", "--env-file", envPath]);
      expect(await Bun.file(envPath).text()).toContain("BETTER_AUTH_URL=http://localhost:3000");
      expect(stdout).toContain("Setup URL: http://localhost:3000");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
  installerTimeout,
);

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

test.each([false, true])(
  "mail-off install stops prior mail services before build, build fails=%s",
  async (fail) => {
    const directory = await fixture();
    try {
      const envPath = join(directory, ".env");
      await Bun.write(envPath, `TS_EDGE_AUTHKEY=${installedKey}\nARK_MAIL_ENABLED=1\n`);
      const child = Bun.spawn([process.execPath, "scripts/install.ts"], {
        cwd: directory,
        env: {
          ...process.env,
          PATH: `${directory}/bin:${process.env.PATH}`,
          ARK_MAIL_ENABLED: "0",
          ARK_INSTALL_SKIP_DOCKER: "0",
          INSTALL_CALLS: join(directory, "calls"),
          INSTALL_FAIL_BUILD: fail ? "1" : "0",
        },
        stdout: "ignore",
        stderr: "pipe",
      });
      const [code, stderr] = await Promise.all([child.exited, new Response(child.stderr).text()]);
      expect(code, stderr).toBe(fail ? 1 : 0);
      const calls = (await Bun.file(join(directory, "calls")).text())
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line).args as string[]);
      const build = calls.findIndex((args) => args.includes("build"));
      for (const service of ["stalwart", "mail-worker", "api"]) {
        const stop = calls.findIndex((args) => args.includes("stop") && args.includes(service));
        expect(stop).toBeGreaterThanOrEqual(0);
        expect(stop).toBeLessThan(build);
      }
      expect(calls.filter((args) => args.includes("up") || args.includes("build")).flat()).not.toContain(
        "mail-worker",
      );
      expect(await Bun.file(envPath).text()).toMatch(/^ARK_MAIL_ENABLED=0$/m);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
  installerTimeout,
);

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

test.each([
  { prompt: promptHidden, expected: "tskey-auth-secret" },
  { prompt: readHidden, expected: "  tskey-auth-secret  " },
])("hidden input restores raw mode without echoing and returns $expected", async ({ prompt, expected }) => {
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
  const result = prompt("Secret: ", input, { write: (value) => output.push(value) });
  input.emit("data", "  tskey-auth-typo\u007f\u007f\u007f\u007fsecret  \r");
  expect(await result).toBe(expected);
  expect(output).toEqual(["Secret: ", "\n"]);
  expect(input.modes).toEqual([true, false]);
  expect(input.paused).toBe(true);
  expect(input.listenerCount("data")).toBe(0);
});
