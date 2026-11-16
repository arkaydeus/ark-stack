import { rm } from "node:fs/promises";

// Owns the resources of one harness run, including commands still creating resources at shutdown.
export class EdgeTestRuntime {
  readonly containers: string[] = [];
  networkCreated = false;
  private stopping = false;
  private pending = new Set<Promise<{ stdout: string; stderr: string }>>();
  private cleanupPromise?: Promise<void>;

  constructor(
    readonly directory: string,
    readonly network: string,
  ) {}

  private async execute(args: string[]) {
    const child = Bun.spawn(["docker", ...args], { stdout: "pipe", stderr: "pipe" });
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
      if (this.networkCreated) {
        await this.execute(["network", "rm", this.network]).catch(() => undefined);
      }
      await rm(this.directory, { recursive: true, force: true });
    })();
    return this.cleanupPromise;
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
