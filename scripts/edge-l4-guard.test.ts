import { expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, readFile, readlink, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { acquireReloadLock } from "@ark-stack/shared";

const guard = join(import.meta.dir, "../infra/platform/edge-l4-launch-guard.sh");
// The edge-l4 image has BusyBox `flock`; a host without one gets a pass-through for the state machine.
const hostFlock = Bun.which("flock");

// Execute the shipped shell state machine with deterministic CLI/HTTP transport faults.
test.each(["Success=0", "disconnect", "ln", "mv", "busy"])(
  "closed-to-full preserves the selector until it can recover from %s",
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
          '#!/bin/sh\necho $$ > "$TEST_ROOT/pid"\ntrap "exit 0" USR1 TERM INT\nwhile :; do /bin/sleep 0.1; done\n',
        wget: '#!/bin/sh\ncase "$*" in *supervise*) echo ok;; *) cat "$TEST_ROOT/decision";; esac\n',
        // The guard bounds each request with `timeout`, which stock macOS lacks; pass through.
        timeout:
          failure === "busy"
            ? '#!/bin/sh\nif [ "$1" = 60 ] && [ "$2" = flock ]; then exit 124; fi\nshift\nexec "$@"\n'
            : '#!/bin/sh\nshift\nexec "$@"\n',
        socat: `#!/bin/sh
read -r command
[ "$command" = reload ] || exit 0
target="$(readlink "$TEST_ROOT/launch/haproxy.cfg")"
if [ "$target" = "$TEST_ROOT/current/haproxy.closed.cfg" ]; then
  touch "$TEST_ROOT/recovered-closed"
  echo Success=1
elif [ ! -f "$TEST_ROOT/attempt" ]; then
  touch "$TEST_ROOT/attempt"
  ${failure === "disconnect" ? "exit 1" : "echo Success=0"}
else
  echo Success=1
fi
`,
        pkill: '#!/bin/sh\nkill -KILL "$(cat "$TEST_ROOT/pid")" 2>/dev/null || true\n',
        ...(hostFlock ? {} : { flock: "#!/bin/sh\nexit 0\n" }),
        ...(failure === "ln"
          ? {
              ln: '#!/bin/sh\ncase "$2" in */haproxy.cfg) exit 1;; esac\nexec /bin/ln "$@"\n',
            }
          : {}),
        ...(failure === "mv"
          ? {
              mv: '#!/bin/sh\ncase "$(readlink "$2")" in */haproxy.cfg) exit 1;; esac\nexec /bin/mv "$@"\n',
            }
          : {}),
      };
      for (const [name, script] of Object.entries(scripts)) {
        const path = join(root, "bin", name);
        await writeFile(path, script);
        await chmod(path, 0o755);
      }
      const logPath = join(root, "guard.log");
      child = Bun.spawn(["sh", guard], {
        env: {
          ...process.env,
          PATH: `${root}/bin:${process.env.PATH}`,
          TEST_ROOT: root,
          ARK_EDGE_L4_DIR: root,
          ARK_EDGE_L4_LAUNCH_DIR: join(root, "launch"),
          ARK_HAPROXY_RELOAD_LOCK: join(root, "reload.lock"),
        },
        stdout: "ignore",
        stderr: Bun.file(logPath),
      });
      const deadline = Date.now() + 7_000;
      while (!(await Bun.file(join(root, "pid")).exists()) && Date.now() < deadline) await Bun.sleep(20);
      await writeFile(join(root, "decision"), "open");
      const succeeds = failure === "Success=0" || failure === "disconnect";
      const link = join(root, "launch/haproxy.cfg");
      const expectedLog = succeeds
        ? "switched to the full configuration"
        : failure === "busy"
          ? "reload.lock is busy"
          : "could not select";
      let output = "";
      while (Date.now() < deadline) {
        output = await readFile(logPath, "utf8");
        if (output.includes(expectedLog)) break;
        await Bun.sleep(20);
      }
      expect(output).toInclude(expectedLog);
      expect(await Bun.file(join(root, "attempt")).exists()).toBe(succeeds);
      expect(await Bun.file(join(root, "recovered-closed")).exists()).toBe(failure === "disconnect");
      expect(await readlink(link)).toBe(
        join(root, succeeds ? "current/haproxy.cfg" : "current/haproxy.closed.cfg"),
      );
      expect(output.includes("switched to the full configuration")).toBe(succeeds);
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

// The guard's reload and the domain worker's (HaproxyMaster.reload) share one flock(2) lock file.
test.skipIf(!hostFlock)(
  "the guard sends reload only while it holds the shared reload lock",
  async () => {
    const root = await mkdtemp(join(tmpdir(), "ark-guard-lock-"));
    try {
      await mkdir(join(root, "bin"));
      await writeFile(join(root, "bin/timeout"), '#!/bin/sh\nshift\nexec "$@"\n', { mode: 0o755 });
      // Records when the master CLI is reached; the worker side holds the lock meanwhile.
      await writeFile(
        join(root, "bin/socat"),
        '#!/bin/sh\ncat >/dev/null\ndate +%s%N > "$TEST_ROOT/reached" 2>/dev/null || touch "$TEST_ROOT/reached"\necho Success=1\n',
      );
      await chmod(join(root, "bin/socat"), 0o755);
      const lock = join(root, "reload.lock");
      const release = await acquireReloadLock(lock);
      const child = Bun.spawn(["sh", guard, "reload"], {
        env: {
          ...process.env,
          PATH: `${root}/bin:${process.env.PATH}`,
          TEST_ROOT: root,
          ARK_HAPROXY_RELOAD_LOCK: lock,
        },
        stdout: "pipe",
        stderr: "pipe",
      });
      await Bun.sleep(600);
      expect(await Bun.file(join(root, "reached")).exists()).toBe(false);
      release();
      const [status, output] = await Promise.all([child.exited, new Response(child.stdout).text()]);
      expect(status).toBe(0);
      expect(output.trim()).toBe("Success=1");
      expect(await Bun.file(join(root, "reached")).exists()).toBe(true);
      // And the worker side waits for the guard: the lock is free again once the guard has finished.
      (await acquireReloadLock(lock, 0))();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
  10_000,
);
