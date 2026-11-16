// Docker-backed regression tests for the harness itself, separate from the 80-second behaviour run.
import { expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

const runtimePath = new URL("./runtime.ts", import.meta.url).pathname;
const release = await Bun.file(new URL("../../infra/platform/release.json", import.meta.url)).json();
const image = release.images.find((pin: string) => pin.startsWith("caddy:"));

async function docker(...args: string[]) {
  const child = Bun.spawn(["docker", ...args], { stdout: "pipe", stderr: "pipe" });
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (status !== 0) throw new Error(stderr);
  return stdout.trim();
}

async function exercise(mode: "failure" | "SIGINT" | "SIGTERM" | "startup-interrupt") {
  const directory = await mkdtemp(join(tmpdir(), "ark-edge-runtime-"));
  const network = basename(directory).toLowerCase();
  const container = `${network}-caddy`;
  const source = `
    import { EdgeTestRuntime } from ${JSON.stringify(runtimePath)};
    const runtime = new EdgeTestRuntime(${JSON.stringify(directory)}, ${JSON.stringify(network)});
    runtime.installSignalHandlers();
    try {
      runtime.networkCreated = true;
      await runtime.docker("network", "create", runtime.network);
      runtime.containers.push(${JSON.stringify(container)});
      const args = ["run", "--detach", "--name", ${JSON.stringify(container)}, "--network", runtime.network];
      if (${JSON.stringify(mode)} === "failure") {
        const file = runtime.directory + "/Caddyfile";
        await Bun.write(file, ${JSON.stringify(":8080 {\ninvalid_edge_test_directive\n}\n")});
        args.push("--volume", file + ":/etc/caddy/Caddyfile:ro");
      }
      const starting = runtime.docker(...args, ${JSON.stringify(image)});
      if (${JSON.stringify(mode)} === "startup-interrupt") console.log("READY");
      await starting;
      if (${JSON.stringify(mode)} === "failure") {
        await runtime.docker("wait", ${JSON.stringify(container)});
        await runtime.dumpLogs();
      } else {
        console.log("READY");
        await Bun.sleep(60_000);
      }
    } finally { await runtime.cleanup(); }
  `;
  const child = Bun.spawn([process.execPath, "--eval", source], { stdout: "pipe", stderr: "pipe" });
  const stderr = new Response(child.stderr).text();
  let output = "";
  let ready!: () => void;
  const readyPromise = new Promise<void>((resolve) => {
    ready = resolve;
  });
  const stdout = (async () => {
    for await (const chunk of child.stdout) {
      output += new TextDecoder().decode(chunk);
      if (output.includes("READY")) ready();
    }
  })();
  try {
    if (mode !== "failure") {
      await Promise.race([
        readyPromise,
        child.exited.then(async () => {
          throw new Error(`Child exited before ready: ${await stderr}`);
        }),
      ]);
      child.kill(mode === "SIGTERM" ? "SIGTERM" : "SIGINT");
    }
    expect(await child.exited).toBe(mode === "failure" ? 0 : mode === "SIGTERM" ? 143 : 130);
    await stdout;
    const logs = await stderr;
    if (mode === "failure") expect(logs).toContain("unrecognized directive: invalid_edge_test_directive");
    expect(await docker("ps", "--all", "--quiet", "--filter", `name=^/${container}$`)).toBe("");
    expect(await docker("network", "ls", "--quiet", "--filter", `name=^${network}$`)).toBe("");
    expect(existsSync(directory)).toBe(false);
  } finally {
    if (child.exitCode === null) child.kill("SIGKILL");
    await child.exited;
    await docker("rm", "--force", "--volumes", container).catch(() => undefined);
    await docker("network", "rm", network).catch(() => undefined);
    await rm(directory, { recursive: true, force: true });
  }
}

test(
  "prints actual Caddy startup stderr before removing the failed container",
  () => exercise("failure"),
  30_000,
);
test("SIGINT removes containers, network and temporary files", () => exercise("SIGINT"), 30_000);
test("SIGTERM removes containers, network and temporary files", () => exercise("SIGTERM"), 30_000);
test(
  "interrupt during docker run waits for creation before removing the container",
  () => exercise("startup-interrupt"),
  30_000,
);
