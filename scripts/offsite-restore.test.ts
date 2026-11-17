import { describe, expect, test } from "bun:test";
import {
  offsiteRestore,
  pgbackrestTime,
  recoveryMicros,
  type OffsiteRestoreOptions,
} from "./offsite-restore.ts";

const options: OffsiteRestoreOptions = {
  endpoint: "http://localhost:9000",
  region: "auto",
  bucket: "fixture",
  prefix: "ark",
  pathStyle: true,
  accessKeyId: "reader",
  secretAccessKey: "read-only",
  resticPassword: "password",
  cluster: "platform",
  cipherPass: "cipher",
  image: "fixture",
  name: "owned-restore",
};

describe("offsite restore safety", () => {
  test("preserves microseconds and timezone offsets without rounding forward", () => {
    expect(pgbackrestTime("2026-11-17T12:34:56.123001Z")).toBe("2026-11-17 12:34:56.123001+00:00");
    expect(pgbackrestTime("2026-11-17T12:34:56.123999+01:00")).toBe("2026-11-17 12:34:56.123999+01:00");
    expect(pgbackrestTime("2026-11-17T12:34:56Z")).toBe("2026-11-17 12:34:56+00:00");
    expect(
      recoveryMicros("2026-11-17T12:34:56.123999Z") - recoveryMicros("2026-11-17T12:34:56.123001Z"),
    ).toBe(998n);
    for (const invalid of [
      "2026-02-30T12:00:00Z",
      "bad",
      "2026-01-01",
      "2026-01-01T00:00:00.1234567Z",
      "2026-01-01T00:00:00Z'; rm -rf /",
    ])
      expect(() => pgbackrestTime(invalid)).toThrow();
  });

  for (const collision of ["owned-restore-pg", "owned-restore-repo", "owned-restore-pgdata"]) {
    test(`rejects existing ${collision} without deleting anything`, async () => {
      const calls: string[][] = [];
      await expect(
        offsiteRestore(options, async (argv) => {
          calls.push(argv);
          return argv.at(-1) === collision
            ? { status: 0, stdout: "[]", stderr: "" }
            : { status: 1, stdout: "", stderr: "Error: No such object" };
        }),
      ).rejects.toThrow(/already exists/);
      expect(calls.every((argv) => argv.includes("inspect"))).toBe(true);
    });
  }

  test("failed snapshot selection performs no resource cleanup", async () => {
    const calls: string[][] = [];
    await expect(
      offsiteRestore(options, async (argv) => {
        calls.push(argv);
        return argv.includes("inspect")
          ? { status: 1, stdout: "", stderr: "Error: No such volume" }
          : { status: 0, stdout: "[]", stderr: "" };
      }),
    ).rejects.toThrow(/No restic snapshot/);
    expect(calls.some((argv) => argv.includes("--force"))).toBe(false);
  });

  test("startup failure cleans only volumes carrying this attempt's label", async () => {
    const labels = new Map<string, string>();
    const removed: string[] = [];
    const manifest = { stageId: "stage", lastRecoverableAt: "2026-11-17T12:34:56.123001Z" };
    await expect(
      offsiteRestore(options, async (argv) => {
        if (argv.includes("inspect")) {
          const label = labels.get(argv.at(-1)!);
          return label
            ? {
                status: 0,
                stdout: JSON.stringify([{ Labels: { "ark.restore-attempt": label } }]),
                stderr: "",
              }
            : { status: 1, stdout: "", stderr: "No such object" };
        }
        if (argv.includes("snapshots"))
          return {
            status: 0,
            stdout: JSON.stringify([
              {
                id: "snapshot",
                short_id: "snapshot",
                time: "2026-11-17",
                tags: ["stage=stage", "layout=relative-v1"],
              },
            ]),
            stderr: "",
          };
        if (argv.includes("dump")) return { status: 0, stdout: JSON.stringify(manifest), stderr: "" };
        if (argv.includes("create"))
          labels.set(argv.at(-1)!, argv[argv.indexOf("--label") + 1]!.split("=")[1]!);
        if (argv.includes("--detach")) {
          // Simulate an unrelated volume replacing one created by the attempt.
          labels.set("owned-restore-pgdata", "some-other-attempt");
          throw new Error("startup failed");
        }
        if (argv[1] === "volume" && argv[2] === "rm") removed.push(argv.at(-1)!);
        return { status: 0, stdout: "", stderr: "" };
      }),
    ).rejects.toThrow(/startup failed/);
    expect(removed).toEqual(["owned-restore-repo"]);
  });
});

const docker = async (args: string[]) => {
  const child = Bun.spawn(["docker", ...args], { stdout: "pipe", stderr: "pipe" });
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (status !== 0) throw new Error(stderr);
  return stdout.trim();
};

test("real Docker collisions preserve an existing container and volume contents", async () => {
  const { RESTIC_IMAGE } = await import("./offsite-restore.ts");
  const name = `ark-restore-safety-${crypto.randomUUID().slice(0, 8)}`;
  const volumes = [`${name}-repo`, `${name}-pgdata`];
  let containerId = "";
  try {
    containerId = await docker([
      "create",
      "--name",
      `${name}-pg`,
      "--label",
      "ark.test=restore-safety",
      RESTIC_IMAGE,
      "version",
    ]);
    await expect(offsiteRestore({ ...options, name })).rejects.toThrow(/already exists/);
    expect(await docker(["inspect", "--format", "{{.Id}}", `${name}-pg`])).toBe(containerId);
    await docker(["rm", containerId]);
    containerId = "";
    for (const volume of volumes) {
      await docker(["volume", "create", "--label", "ark.test=restore-safety", volume]);
      await docker([
        "run",
        "--rm",
        "--network",
        "none",
        "--volume",
        `${volume}:/data`,
        "--entrypoint",
        "/bin/sh",
        RESTIC_IMAGE,
        "-c",
        "printf sentinel > /data/keep",
      ]);
    }
    await expect(offsiteRestore({ ...options, name })).rejects.toThrow(/already exists/);
    for (const volume of volumes)
      expect(
        await docker([
          "run",
          "--rm",
          "--network",
          "none",
          "--volume",
          `${volume}:/data:ro`,
          "--entrypoint",
          "/bin/sh",
          RESTIC_IMAGE,
          "-c",
          "cat /data/keep",
        ]),
      ).toBe("sentinel");
  } finally {
    if (containerId) await docker(["rm", "--force", containerId]);
    for (const volume of volumes) {
      const check = Bun.spawnSync([
        "docker",
        "volume",
        "inspect",
        "--format",
        '{{index .Labels "ark.test"}}',
        volume,
      ]);
      if (check.exitCode === 0 && check.stdout.toString().trim() === "restore-safety")
        await docker(["volume", "rm", volume]);
    }
  }
}, 120000);
