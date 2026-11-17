import { rm } from "node:fs/promises";

// Owns the resources of one harness run, including commands still creating resources at shutdown.
export class EdgeTestRuntime {
  readonly containers: string[] = [];
  /** Compose projects started by the run; their containers, networks and volumes are removed by label. */
  readonly composeProjects: string[] = [];
  networkCreated = false;
  private stopping = false;
  private pending = new Set<Promise<{ stdout: string; stderr: string }>>();
  private cleanupPromise?: Promise<void>;

  constructor(
    readonly directory: string,
    readonly network: string,
    /**
     * An image the run already uses (with `chown`), for handing the work directory back to the
     * host user at cleanup. The harnesses chown fixtures to uid 1000 as the installer does; on a
     * Linux host whose user is not uid 1000 (a CI runner is 1001) those files cannot be removed
     * otherwise. Docker Desktop's file sharing hides this.
     */
    readonly ownershipImage?: string,
  ) {}

  private async execute(args: string[]) {
    // The live-tailnet runner sets TS_EDGE_AUTHKEY after startup. Pass the current environment,
    // rather than Bun.spawn's launch-time default, so Compose receives the accepted key.
    const child = Bun.spawn(["docker", ...args], {
      env: process.env,
      stdout: "pipe",
      stderr: "pipe",
    });
    const [status, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    if (status !== 0) throw new Error(`docker ${args[0]} failed: ${stderr.trim().slice(0, 2000)}`);
    return { stdout, stderr };
  }

  async dockerOutput(...args: string[]) {
    if (this.stopping) throw new Error("Edge test is shutting down.");
    const command = this.execute(args);
    this.pending.add(command);
    try {
      return await command;
    } finally {
      this.pending.delete(command);
    }
  }

  async docker(...args: string[]) {
    return (await this.dockerOutput(...args)).stdout.trim();
  }

  async dumpLogs() {
    for (const container of this.containers) {
      try {
        const { stdout, stderr } = await this.dockerOutput("logs", "--tail", "40", container);
        if (stdout || stderr) {
          console.error(`\n--- ${container} (last 40 lines) ---`);
          if (stdout) process.stderr.write(stdout);
          if (stderr) process.stderr.write(stderr);
        }
      } catch (error) {
        console.error(`Unable to collect logs for ${container}: ${(error as Error).message}`);
      }
    }
  }

  cleanup() {
    this.stopping = true;
    this.cleanupPromise ??= (async () => {
      // A signal can arrive while docker run/network create is still in flight. Let it finish
      // before removal, and reject subsequent commands so fixtures cannot start after cleanup.
      await Promise.allSettled(this.pending);
      if (this.containers.length) {
        await this.execute(["rm", "--force", "--volumes", ...this.containers]).catch(() => undefined);
      }
      for (const project of this.composeProjects) await this.removeComposeProject(project);
      if (this.networkCreated) {
        await this.execute(["network", "rm", this.network]).catch(() => undefined);
      }
      await rm(this.directory, { recursive: true, force: true }).catch(
        async (error: NodeJS.ErrnoException) => {
          if (
            (error.code !== "EACCES" && error.code !== "EPERM") ||
            !this.ownershipImage ||
            !process.getuid
          ) {
            throw error;
          }
          await this.execute([
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "0:0",
            "--entrypoint",
            "chown",
            "--volume",
            `${this.directory}:/work`,
            this.ownershipImage,
            "-R",
            `${process.getuid()}:${process.getgid?.() ?? process.getuid()}`,
            "/work",
          ]);
          await rm(this.directory, { recursive: true, force: true });
        },
      );
    })();
    return this.cleanupPromise;
  }

  private async removeComposeProject(project: string) {
    const label = `label=com.docker.compose.project=${project}`;
    const list = async (...args: string[]) =>
      (await this.execute(args).catch(() => ({ stdout: "" }))).stdout.split("\n").filter(Boolean);
    // Containers first: networks and volumes in use cannot be removed.
    const containers = await list("ps", "--all", "--quiet", "--filter", label);
    if (containers.length) {
      await this.execute(["rm", "--force", "--volumes", ...containers]).catch(() => undefined);
    }
    const networks = await list("network", "ls", "--quiet", "--filter", label);
    if (networks.length) await this.execute(["network", "rm", ...networks]).catch(() => undefined);
    const volumes = await list("volume", "ls", "--quiet", "--filter", label);
    if (volumes.length) await this.execute(["volume", "rm", "--force", ...volumes]).catch(() => undefined);
  }

  installSignalHandlers() {
    let exitCode = 0;
    const interrupt = (code: number) => {
      exitCode ||= code;
      void this.cleanup().then(
        () => process.exit(exitCode),
        (error) => {
          console.error(error);
          process.exit(exitCode);
        },
      );
    };
    const sigint = () => interrupt(130);
    const sigterm = () => interrupt(143);
    process.on("SIGINT", sigint);
    process.on("SIGTERM", sigterm);
    return () => {
      process.off("SIGINT", sigint);
      process.off("SIGTERM", sigterm);
    };
  }
}
