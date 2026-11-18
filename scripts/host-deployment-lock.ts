import { mkdir } from "node:fs/promises";
import { join } from "node:path";

// Reject overlapping runs. A waiting process could otherwise inherit stale settings from .env.
export async function lockHostDeployment(root: string) {
  if (process.platform !== "linux" || process.env.ARK_HOST_DEPLOYMENT_LOCK_HELD === "1") return;
  const directory = join(root, "tmp");
  await mkdir(directory, { recursive: true });
  const child = Bun.spawn(
    [
      "flock",
      "--no-fork",
      "--nonblock",
      "--conflict-exit-code",
      "75",
      join(directory, "host-deployment.lock"),
      process.execPath,
      ...process.argv.slice(1),
    ],
    {
      env: { ...process.env, ARK_HOST_DEPLOYMENT_LOCK_HELD: "1" },
      stdio: ["inherit", "inherit", "inherit"],
    },
  );
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
    process.once(signal, () => child.kill(signal));
  }
  const code = await child.exited;
  if (code === 75) throw new Error("Another Ark host install or signed maintenance run is in progress.");
  process.exit(code);
}
