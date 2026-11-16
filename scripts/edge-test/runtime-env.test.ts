import { expect, test } from "bun:test";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("Docker receives the edge enrollment key assigned after the runtime process starts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ark-edge-runtime-env-"));
  try {
    const docker = join(directory, "docker");
    await Bun.write(docker, `#!${process.execPath}\nconsole.log(process.env.TS_EDGE_AUTHKEY);\n`);
    await chmod(docker, 0o700);
    const runtimePath = new URL("./runtime.ts", import.meta.url).pathname;
    const child = Bun.spawn(
      [
        process.execPath,
        "--eval",
        `
      import { EdgeTestRuntime } from ${JSON.stringify(runtimePath)};
      process.env.TS_EDGE_AUTHKEY = "tskey-auth-runtime-value";
      const runtime = new EdgeTestRuntime(${JSON.stringify(directory)}, "unused");
      console.log(await runtime.docker("version"));
    `,
      ],
      {
        env: {
          ...process.env,
          PATH: `${directory}:${process.env.PATH}`,
          TS_EDGE_AUTHKEY: "tskey-auth-launch-value",
        },
        stdout: "pipe",
        stderr: "pipe",
      },
    );
    const [code, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    expect(code, stderr).toBe(0);
    expect(stdout.trim()).toBe("tskey-auth-runtime-value");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
