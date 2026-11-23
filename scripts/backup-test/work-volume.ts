// A project-owned Docker volume mirroring the test's work directory for the restic wrapper
// (restic-docker-tailnet.sh mounts it read-only at /work). restic in Docker Desktop cannot read
// host bind mounts reliably (reads fail with EIO), so files restic must back up are copied in with
// `docker cp` after they are written. The volume and its holder container carry the Compose project
// label, so the harness removes them with the project and nothing else.
import { dirname, relative } from "node:path";

import type { EdgeTestRuntime } from "../edge-test/runtime.ts";
import { bunImage } from "../test-images.ts";

export async function createWorkVolume(runtime: EdgeTestRuntime, project: string, work: string) {
  const volume = `${project}_work`;
  const holder = `${project}-work`;
  await runtime.docker("volume", "create", "--label", `com.docker.compose.project=${project}`, volume);
  runtime.containers.push(holder);
  await runtime.docker(
    "run",
    "--detach",
    "--name",
    holder,
    "--label",
    `com.docker.compose.project=${project}`,
    "--volume",
    `${volume}:/work`,
    "--entrypoint",
    "sleep",
    bunImage,
    "infinity",
  );
  return {
    volume,
    /** Copies a file or directory under `work` to the same relative path in the volume. */
    async sync(path: string) {
      const target = `/work/${relative(work, path)}`;
      if (target.includes("..")) throw new Error(`${path} is outside the work directory`);
      await runtime.docker("exec", holder, "mkdir", "-p", dirname(target));
      await runtime.docker("cp", path, `${holder}:${dirname(target)}/`);
    },
  };
}
