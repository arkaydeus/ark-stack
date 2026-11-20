import { mkdir } from "node:fs/promises";
import { join } from "node:path";

// Reject overlapping runs. A waiting process could otherwise inherit stale settings from .env.
export async function lockHostDeployment(root: string, holderEnv?: Record<string, string | undefined>) {
  if (process.platform !== "linux" || process.env.ARK_HOST_DEPLOYMENT_LOCK_HELD === "1") return;
  const directory = join(root, "tmp");
  await mkdir(directory, { recursive: true });
  const checkoutLock = join(directory, "host-deployment.lock");
  const flock = (file: string) => ["flock", "--no-fork", "--nonblock", "--conflict-exit-code", "75", file];
  let hostLock: string[] = [];
  if (process.getuid?.() === 0) {
    await mkdir("/run/ark-stack", { recursive: true, mode: 0o700 });
    hostLock = flock("/run/ark-stack/deployment.lock");
  }
  const locks = [...hostLock, ...flock(checkoutLock)];
  if (holderEnv) {
    // Guided setup keeps credentials and its terminal in this process. The helper only holds
    // the locks, and exits on EOF when this process exits, including on interruption.
    const holder = Bun.spawn([...locks, "sh", "-c", "printf 'ready\\n'; exec cat >/dev/null"], {
      env: holderEnv,
      stdin: "pipe",
      stdout: "pipe",
      stderr: "inherit",
    });
    const reader = holder.stdout.getReader();
    const { done } = await reader.read();
    reader.releaseLock();
    if (done) {
      const code = await holder.exited;
      if (code === 75)
        throw new Error("Another Ark host setup, install or signed maintenance run is in progress.");
      throw new Error(`Could not acquire the Ark host deployment lock (exit ${code}).`);
    }
    process.once("exit", () => holder.stdin.end());
    process.env.ARK_HOST_DEPLOYMENT_LOCK_HELD = "1";
    return;
  }
  const child = Bun.spawn([...locks, process.execPath, ...process.argv.slice(1)], {
    env: { ...process.env, ARK_HOST_DEPLOYMENT_LOCK_HELD: "1" },
    stdio: ["inherit", "inherit", "inherit"],
  });
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
    process.once(signal, () => child.kill(signal));
  }
  const code = await child.exited;
  if (code === 75)
    throw new Error("Another Ark host setup, install or signed maintenance run is in progress.");
  process.exit(code);
}
