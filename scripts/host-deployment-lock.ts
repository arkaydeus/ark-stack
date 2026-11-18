import { mkdir } from "node:fs/promises";
import { join } from "node:path";

// Run host install and signed maintenance serially, including across failures and process exits.
export async function lockHostDeployment(root: string) {
  if (process.platform !== "linux" || process.env.ARK_HOST_DEPLOYMENT_LOCK_HELD === "1") return;
  const directory = join(root, "tmp");
  await mkdir(directory, { recursive: true });
  const child = Bun.spawn(
    [
      "flock",
      "--no-fork",
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
  process.exit(await child.exited);
}
