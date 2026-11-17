import { describe, expect, test } from "bun:test";
import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runBackup, runRestoreTest } from "./backups.ts";

describe("backup execution evidence", () => {
  test("disabled execution does not create uploaded or restore-verified proof", async () => {
    const previous = process.env.ARK_BACKUP_EXECUTE;
    const required = process.env.ARK_BACKUP_REQUIRED;
    process.env.ARK_BACKUP_EXECUTE = "0";
    delete process.env.ARK_BACKUP_REQUIRED;
    try {
      const backup = await runBackup("platform-postgres", "platform");
      const restore = await runRestoreTest("platform-postgres", "platform");
      expect(backup.executed).toBe(false);
      expect(backup.status).toBe("planned");
      expect(restore.executed).toBe(false);
      expect(restore.status).toBe("planned");
    } finally {
      if (previous === undefined) delete process.env.ARK_BACKUP_EXECUTE;
      else process.env.ARK_BACKUP_EXECUTE = previous;
      if (required === undefined) delete process.env.ARK_BACKUP_REQUIRED;
      else process.env.ARK_BACKUP_REQUIRED = required;
    }
  });

  test("restore execution uses the native snapshot id, not a control-plane row id", async () => {
    // FD-21: the backup itself runs in the cluster's executor; a fake executor answers here.
    const requests: Array<{ path: string; auth: string | null; body: unknown }> = [];
    const executor = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch(request) {
        requests.push({
          path: new URL(request.url).pathname,
          auth: request.headers.get("authorization"),
          body: await request.json(),
        });
        return Response.json({ label: "snap-123", type: "full", output: "" });
      },
    });
    const previousUrl = process.env.ARK_PLATFORM_PG_EXECUTOR_URL;
    const previousToken = process.env.ARK_PLATFORM_PG_EXECUTOR_TOKEN;
    process.env.ARK_PLATFORM_PG_EXECUTOR_URL = `http://127.0.0.1:${executor.port}`;
    process.env.ARK_PLATFORM_PG_EXECUTOR_TOKEN = "executor-token-0123456789-abcdef";
    const directory = await mkdtemp(join(tmpdir(), "ark-backup-"));
    const binary = join(directory, "pgbackrest");
    const argsFile = join(directory, "restore.args");
    await writeFile(
      binary,
      `#!/bin/sh
echo "$@" > "${argsFile}"
exit 0
`,
      { mode: 0o755 },
    );
    await chmod(binary, 0o755);
    const previousPath = process.env.PATH;
    const previousExecute = process.env.ARK_BACKUP_EXECUTE;
    const previousRunner = process.env.ARK_RESTORE_RUNNER;
    process.env.PATH = `${directory}:${previousPath ?? ""}`;
    process.env.ARK_BACKUP_EXECUTE = "1";
    process.env.ARK_RESTORE_RUNNER = "1";
    try {
      const backup = await runBackup("platform-postgres", "platform");
      expect(backup.snapshotId).toBe("snap-123");
      // Local until a stage containing it reaches an off-VPS target.
      expect(backup.status).toBe("local");
      expect(requests).toEqual([
        { path: "/v1/backup", auth: "Bearer executor-token-0123456789-abcdef", body: { type: "full" } },
      ]);
      await expect(runRestoreTest("platform-postgres", "platform", "snap-123")).rejects.toThrow(
        /off-VPS recovery host/,
      );
      expect(await Bun.file(argsFile).exists()).toBe(false);
    } finally {
      executor.stop(true);
      if (previousUrl === undefined) delete process.env.ARK_PLATFORM_PG_EXECUTOR_URL;
      else process.env.ARK_PLATFORM_PG_EXECUTOR_URL = previousUrl;
      if (previousToken === undefined) delete process.env.ARK_PLATFORM_PG_EXECUTOR_TOKEN;
      else process.env.ARK_PLATFORM_PG_EXECUTOR_TOKEN = previousToken;
      process.env.PATH = previousPath;
      if (previousExecute === undefined) delete process.env.ARK_BACKUP_EXECUTE;
      else process.env.ARK_BACKUP_EXECUTE = previousExecute;
      if (previousRunner === undefined) delete process.env.ARK_RESTORE_RUNNER;
      else process.env.ARK_RESTORE_RUNNER = previousRunner;
    }
  });
});
