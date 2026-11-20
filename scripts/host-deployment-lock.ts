import { mkdir } from "node:fs/promises";
import { join } from "node:path";

// Reject overlapping runs. A waiting process could otherwise inherit stale settings from .env.
export async function lockHostDeployment(root: string) {
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
  const child = Bun.spawn([...hostLock, ...flock(checkoutLock), process.execPath, ...process.argv.slice(1)], {
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
