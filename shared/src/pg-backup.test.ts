import { describe, expect, test } from "bun:test";

import {
  PG_EXECUTOR_ACTIONS,
  archiveCommand,
  assertExecutorArgv,
  dueBackupType,
  parsePgbackrestInfo,
  pgSnapshotTags,
  pgbackrestArgv,
  stageId,
  stageRecoverableAt,
} from "./pg-backup.ts";

const info = JSON.stringify([
  {
    name: "ark-platform",
    status: { code: 0, message: "ok" },
    archive: [{ id: "17-1", min: "000000010000000000000001", max: "000000010000000000000009" }],
    backup: [
      {
        label: "20261110-010000F",
        type: "full",
        error: false,
        timestamp: { start: 1_794_000_000, stop: 1_794_000_010 },
        archive: { start: "000000010000000000000003", stop: "000000010000000000000004" },
        backrest: { version: "2.60.0" },
      },
      { label: "broken", type: "diff", error: true, timestamp: { start: 1, stop: 2 } },
      {
        label: "20261110-010000F_20261111-010000D",
        type: "diff",
        error: false,
        timestamp: { start: 1_794_086_400, stop: 1_794_086_405 },
        archive: { start: "000000010000000000000007", stop: "000000010000000000000007" },
        backrest: { version: "2.60.0" },
      },
    ],
  },
]);

describe("pgBackRest executor contract (FD-21)", () => {
  test("backup, info and restore select repo2 explicitly; check and stanza-create act on the only repo", () => {
    expect(pgbackrestArgv("backup", "ark-app", { type: "diff" })).toEqual([
      "pgbackrest",
      "--stanza=ark-app",
      "--repo=2",
      "--type=diff",
      "--no-expire-auto",
      "backup",
    ]);
    expect(pgbackrestArgv("info", "ark-app", { repoPath: "/stage/repo2" })).toEqual([
      "pgbackrest",
      "--stanza=ark-app",
      "--repo=2",
      "--repo2-path=/stage/repo2",
      "--output=json",
      "info",
    ]);
    // pgBackRest rejects --repo for check and stanza-create (verified with 2.60.0).
    expect(pgbackrestArgv("check", "ark-app")).toEqual(["pgbackrest", "--stanza=ark-app", "check"]);
    expect(() => pgbackrestArgv("backup", "Bad Stanza")).toThrow(/stanza/);
  });

  test("expire and stanza-delete are refused and are not executor actions", () => {
    expect(() => assertExecutorArgv(["pgbackrest", "--stanza=ark-app", "expire"])).toThrow(
      /never run from the VPS/,
    );
    expect(() => assertExecutorArgv(["pgbackrest", "--stanza=ark-app", "stanza-delete"])).toThrow();
    expect(() => assertExecutorArgv(["pgbackrest", "--expire-auto=y", "backup"])).toThrow();
    expect(() => assertExecutorArgv(["sh", "-c", "pgbackrest backup"])).toThrow(/only runs pgBackRest/);
    expect(PG_EXECUTOR_ACTIONS as readonly string[]).not.toContain("expire");
  });

  test("archive_command contains pgbackrest (pgBackRest requires it) under the shared executor lock", () => {
    expect(archiveCommand("ark-platform")).toBe(
      "flock -s -w 60 /var/lib/pgbackrest/ark-executor.lock pgbackrest --stanza=ark-platform archive-push %p",
    );
  });

  test("info parsing skips errored backups and keeps the archive range", () => {
    const parsed = parsePgbackrestInfo(info, "ark-platform");
    expect(parsed.backups.map((item) => item.label)).toEqual([
      "20261110-010000F",
      "20261110-010000F_20261111-010000D",
    ]);
    expect(parsed.archive).toEqual({ min: "000000010000000000000001", max: "000000010000000000000009" });
    expect(parsed.version).toBe("2.60.0");
    expect(parsePgbackrestInfo(info, "ark-app").backups).toEqual([]);
  });

  test("a stage claims a recovery point only when the switched WAL is staged and a backup finished first", () => {
    const parsed = parsePgbackrestInfo(info, "ark-platform");
    const after = new Date(1_794_086_410 * 1000);
    expect(
      stageRecoverableAt({ switchedAt: after, walSegment: "000000010000000000000009", info: parsed }),
    ).toBe(after.toISOString());
    // The switched segment is newer than the staged archive: no claim.
    expect(
      stageRecoverableAt({ switchedAt: after, walSegment: "00000001000000000000000A", info: parsed }),
    ).toBeNull();
    // Within the same second as the only backup's stop: pgBackRest could not restore to it.
    const first = parsePgbackrestInfo(info, "ark-platform");
    first.backups = first.backups.slice(0, 1);
    expect(
      stageRecoverableAt({
        switchedAt: new Date(1_794_000_010_500),
        walSegment: "000000010000000000000009",
        info: first,
      }),
    ).toBeNull();
  });

  test("weekly full, daily differential", () => {
    const parsed = parsePgbackrestInfo(info, "ark-platform").backups;
    expect(dueBackupType([], new Date())).toBe("full");
    const lastStop = new Date(parsed.at(-1)!.stoppedAt).getTime();
    expect(dueBackupType(parsed, new Date(lastStop + 60_000))).toBeNull();
    expect(dueBackupType(parsed, new Date(lastStop + 25 * 3_600_000))).toBe("diff");
    expect(dueBackupType(parsed, new Date(new Date(parsed[0]!.stoppedAt).getTime() + 8 * 86_400_000))).toBe(
      "full",
    );
  });

  test("stage IDs sort by time and restic tags identify the stanza and stage", () => {
    const id = stageId(new Date("2026-11-17T10:32:44.123Z"), "ab12cd");
    expect(id).toBe("20261117T103244Z-ab12cd");
    expect(pgSnapshotTags("ark-app", id)).toEqual(["ark", "source=pg:ark-app", `stage=${id}`]);
    expect(() => pgSnapshotTags("ark-app", "../escape")).toThrow();
  });
});
