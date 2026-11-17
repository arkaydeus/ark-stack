import { expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

// Execute the shipped shell state machine with deterministic CLI/HTTP transport faults.
test.each(["Success=0", "disconnect"])(
  "closed-to-full retries a %s reply before committing mode",
  async (failure) => {
    const root = await mkdtemp(join(tmpdir(), "ark-guard-fault-"));
    let child: ReturnType<typeof Bun.spawn> | undefined;
    try {
      for (const dir of ["bin", "launch", "current"]) await mkdir(join(root, dir));
      await writeFile(join(root, "current/haproxy.cfg"), "# ark-tailnet-route test 100.64.1.1:443\n");
      await writeFile(join(root, "current/haproxy.closed.cfg"), "closed\n");
      await writeFile(join(root, "decision"), "closed");
      const scripts = {
        haproxy:
          '#!/bin/sh\necho $$ > "$TEST_ROOT/pid"\ntrap "exit 0" USR1 TERM INT\nwhile :; do sleep 0.1; done\n',
        wget: '#!/bin/sh\ncase "$*" in *supervise*) echo ok;; *) cat "$TEST_ROOT/decision";; esac\n',
        // The guard bounds each request with `timeout`, which stock macOS lacks; pass through.
        timeout: '#!/bin/sh\nshift\nexec "$@"\n',
        socat: `#!/bin/sh\ncat >/dev/null\nif [ ! -f "$TEST_ROOT/attempt" ]; then\n touch "$TEST_ROOT/attempt"\n ${failure === "disconnect" ? "exit 1" : "echo Success=0"}\nelse\n echo Success=1\n touch "$TEST_ROOT/succeeded"\nfi\n`,
        pkill: '#!/bin/sh\nkill -KILL "$(cat "$TEST_ROOT/pid")" 2>/dev/null || true\n',
      };
      for (const [name, script] of Object.entries(scripts)) {
        const path = join(root, "bin", name);
        await writeFile(path, script);
        await chmod(path, 0o755);
      }
      child = Bun.spawn(["sh", join(import.meta.dir, "../infra/platform/edge-l4-launch-guard.sh")], {
        env: {
          ...process.env,
          PATH: `${root}/bin:${process.env.PATH}`,
          TEST_ROOT: root,
          ARK_EDGE_L4_DIR: root,
          ARK_EDGE_L4_LAUNCH_DIR: join(root, "launch"),
        },
        stdout: "ignore",
        stderr: "pipe",
      });
      const deadline = Date.now() + 7_000;
      while (!(await Bun.file(join(root, "pid")).exists()) && Date.now() < deadline) await Bun.sleep(20);
      await writeFile(join(root, "decision"), "open");
      while (!(await Bun.file(join(root, "succeeded")).exists()) && Date.now() < deadline)
        await Bun.sleep(20);
      expect(await Bun.file(join(root, "attempt")).exists()).toBe(true);
      expect(await Bun.file(join(root, "succeeded")).exists()).toBe(true);
      const { readlink } = await import("node:fs/promises");
      expect(await readlink(join(root, "launch/haproxy.cfg"))).toBe(join(root, "current/haproxy.cfg"));
    } finally {
      child?.kill("SIGTERM");
      if (child) await child.exited;
      const pid = Number(await readFile(join(root, "pid"), "utf8").catch(() => "0"));
      if (pid > 0) {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          /* already exited */
        }
      }
      await rm(root, { recursive: true, force: true });
    }
  },
  10_000,
);
