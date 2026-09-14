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
    const directory = await mkdtemp(join(tmpdir(), "ark-backup-"));
    const binary = join(directory, "pgbackrest");
    const argsFile = join(directory, "restore.args");
    await writeFile(
      binary,
      `#!/bin/sh
if echo "$@" | grep -q ' backup'; then
  echo "backup label: snap-123"
  exit 0
fi
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
      const restore = await runRestoreTest("platform-postgres", "platform", "snap-123");
      expect(restore.executed).toBe(true);
      expect(restore.argv).toContain("--set=snap-123");
      expect(restore.argv.some((item) => item.startsWith("bak_"))).toBe(false);
      const args = await Bun.file(argsFile).text();
      expect(args).toContain("--set=snap-123");
      expect(args).not.toContain("bak_");
    } finally {
      process.env.PATH = previousPath;
      if (previousExecute === undefined) delete process.env.ARK_BACKUP_EXECUTE;
      else process.env.ARK_BACKUP_EXECUTE = previousExecute;
      if (previousRunner === undefined) delete process.env.ARK_RESTORE_RUNNER;
      else process.env.ARK_RESTORE_RUNNER = previousRunner;
    }
  });
});
