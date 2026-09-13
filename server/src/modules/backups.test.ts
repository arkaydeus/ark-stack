import { describe, expect, test } from "bun:test";

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
});
