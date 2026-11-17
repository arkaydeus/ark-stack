// FD-21 acceptance: `pgbackrest expire` is never run from the VPS (docs/design/front-door.md §3.18.2).
//
// Static check over everything that runs on the VPS: the server, workers, shared code, the Dockerfile,
// Compose files and infra scripts. Expiry belongs to an off-host admin working on a restored copy
// (docs/guides/backups.md). The executor's allowlist and argv guard are checked too.
import { describe, expect, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";

import { PG_EXECUTOR_ACTIONS, assertExecutorArgv } from "@ark-stack/shared";

const root = join(import.meta.dir, "..", "..");
const VPS_SOURCES = ["server/src", "workers/src", "shared/src", "infra", "Dockerfile"];
const SKIP = /(\.test\.ts|\/testdata\/|\.md)$/;

async function files(path: string): Promise<string[]> {
  const full = join(root, path);
  const entries = await readdir(full, { withFileTypes: true }).catch(() => null);
  if (!entries) return [full];
  const nested = await Promise.all(
    entries.map((entry) =>
      entry.isDirectory() ? files(join(path, entry.name)) : Promise.resolve([join(full, entry.name)]),
    ),
  );
  return nested.flat();
}

/** True when a source line would run pgBackRest expire/stanza-delete or enable automatic expiry. */
export function offendingLine(line: string) {
  // Comments may name the command; the argv guard in shared/src/pg-backup.ts must name it to refuse it.
  const code = line.replace(/\/\/.*$|^\s*#.*$|^\s*\/?\*.*$/, "");
  if (/if \(arg === "expire"/.test(code)) return false;
  return (
    /\bpgbackrest\b.*\b(expire|stanza-delete)\b(?!-)/i.test(code) ||
    /["'](expire|stanza-delete)["']/.test(code) ||
    /expire-auto=y|EXPIRE_AUTO=y/i.test(code)
  );
}

describe("pgBackRest expire never runs from the VPS", () => {
  test("the matcher catches real invocations and ignores comments and expire-auto=n", () => {
    for (const line of [
      'const argv = ["pgbackrest", `--stanza=${stanza}`, "expire"];',
      "pgbackrest --stanza=ark-app expire --set=x",
      "  PGBACKREST_EXPIRE_AUTO=y \\",
      'await callExecutor(cluster, "stanza-delete");',
    ]) {
      expect(offendingLine(line)).toBe(true);
    }
    for (const line of [
      "// never run pgbackrest expire here",
      "  PGBACKREST_EXPIRE_AUTO=n \\",
      '"--no-expire-auto",',
    ]) {
      expect(offendingLine(line)).toBe(false);
    }
  });

  test("no VPS-side source invokes pgbackrest expire or stanza-delete, or turns expire-auto on", async () => {
    const offenders: string[] = [];
    for (const file of (await Promise.all(VPS_SOURCES.map(files))).flat()) {
      if (SKIP.test(file)) continue;
      const text = await readFile(file, "utf8");
      text.split("\n").forEach((line, index) => {
        if (offendingLine(line)) offenders.push(`${relative(root, file)}:${index + 1}: ${line.trim()}`);
      });
    }
    expect(offenders).toEqual([]);
  });

  test("the images disable automatic expiry", async () => {
    const dockerfile = await readFile(join(root, "Dockerfile"), "utf8");
    expect(dockerfile.match(/PGBACKREST_EXPIRE_AUTO=n/g)?.length).toBe(2);
  });

  test("the executor has no expire action and its argv guard refuses it", () => {
    expect(PG_EXECUTOR_ACTIONS as readonly string[]).not.toContain("expire");
    expect(() => assertExecutorArgv(["pgbackrest", "--stanza=ark-platform", "expire"])).toThrow();
  });
});
