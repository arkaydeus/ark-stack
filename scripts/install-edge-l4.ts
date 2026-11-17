// Installer step for the HAProxy SNI router (docs/design/front-door.md §3.8.6, FD-25). It runs before
// the unprivileged services start:
//
// - checks the numeric users of the pinned images instead of assuming names map to IDs: HAProxy must
//   run as uid 99 (the tmpfs socket volumes are created for it) and GID 4400 must not already name a
//   group in the HAProxy or Bun images;
// - seeds `tmp/edge-l4` with an initial generation (no tailnet route: every hostname goes to Caddy)
//   and the `current` symlink, so edge-l4 can start before the domain worker's first edge.l4_apply;
// - as root on Linux, gives the tree to the worker's uid and group 4400: directories 2750, files 0640.
import { chmod, chown, lstat, readdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  CADDY_GLOBAL_BLOCK,
  currentGeneration,
  EDGE_L4_SHARED_GID,
  HAPROXY_IMAGE_UID,
  pointCurrent,
  renderEdgeL4Generation,
  writeGeneration,
} from "@ark-stack/shared";

/** Writes the initial generation unless `current` already points at one. */
export async function seedEdgeL4(root: string) {
  const existing = await currentGeneration(root);
  if (existing) return { generation: existing, seeded: false };
  const generation = renderEdgeL4Generation({ httpHostnames: [] });
  await writeGeneration(root, generation);
  await pointCurrent(root, generation.id);
  return { generation: generation.id, seeded: true };
}

/** Ownership and modes of §3.8.6: worker uid, shared group, directories 2750 and files 0640. */
export async function chownEdgeL4(root: string, uid: number, gid = EDGE_L4_SHARED_GID) {
  const visit = async (path: string) => {
    const info = await lstat(path);
    if (info.isSymbolicLink()) {
      // `current`: lchown is enough, the target directory is handled on its own.
      return;
    }
    await chown(path, uid, gid);
    if (info.isDirectory()) {
      await chmod(path, 0o2750);
      for (const entry of await readdir(path)) await visit(join(path, entry));
    } else {
      await chmod(path, 0o640);
    }
  };
  await visit(root);
}

/** The pinned image's numeric uid and whether a group already uses the shared GID. */
export function checkImageIds(
  input: { image: string; uid: string; group4400: string },
  expectedUid?: number,
) {
  const problems: string[] = [];
  const uid = Number(input.uid.trim());
  if (expectedUid !== undefined && uid !== expectedUid) {
    problems.push(`${input.image} runs as uid ${input.uid.trim() || "?"}, not ${expectedUid}`);
  }
  if (input.group4400.trim()) {
    problems.push(`${input.image} already defines GID ${EDGE_L4_SHARED_GID} (${input.group4400.trim()})`);
  }
  return problems;
}

async function capture(args: string[]) {
  const child = Bun.spawn(args, { env: process.env, stdout: "pipe", stderr: "pipe" });
  const [code, stdout] = await Promise.all([child.exited, new Response(child.stdout).text()]);
  if (code !== 0) throw new Error(`${args.slice(0, 4).join(" ")} failed`);
  return stdout;
}

/** Inspects the pinned HAProxy and Bun images with Docker (installer only; services never use Docker). */
export async function verifyImageIds(images: { haproxy: string; bun: string }) {
  const problems: string[] = [];
  for (const [image, expectedUid] of [
    [images.haproxy, HAPROXY_IMAGE_UID],
    [images.bun, undefined],
  ] as const) {
    const output = await capture([
      "docker",
      "run",
      "--rm",
      "--entrypoint",
      "sh",
      image,
      "-c",
      `id -u; echo ---; getent group ${EDGE_L4_SHARED_GID} || true`,
    ]);
    const [uid = "", group4400 = ""] = output.split("---\n");
    problems.push(...checkImageIds({ image, uid, group4400 }, expectedUid));
  }
  if (problems.length) throw new Error(`edge-l4 user/group check failed: ${problems.join("; ")}`);
}

/** Image references used by the platform Compose file for edge-l4 and the Bun services. */
export function composeImages(compose: string, dockerfile: string) {
  const haproxy = /^\s*image:\s*(haproxy:\S+)\s*$/m.exec(compose)?.[1];
  const bun = /^FROM (oven\/bun:\S+-slim@sha256:[a-f0-9]{64}) AS runtime$/m.exec(dockerfile)?.[1];
  if (!haproxy || !bun) throw new Error("Could not find the pinned HAProxy and Bun images.");
  return { haproxy, bun };
}

/** Upgrade Ark-rendered Caddy files without changing routes, pins, certificate paths or policy. */
export function migrateCaddyL4(source: string) {
  if (/^  https_port 8443$/m.test(source)) return source;
  if (!/^\{\n[\s\S]*?^\}/m.test(source))
    throw new Error("Unrecognized Caddy global block; refusing edge cutover");
  return source
    .replace(/^\{\n[\s\S]*?^\}/m, CADDY_GLOBAL_BLOCK)
    .replace(/^([a-z0-9.-]+) \{$/gm, "$1 {\n  bind 127.0.0.1");
}

/** Runs in a root one-shot container before maintenance starts the new edge services. */
export async function prepareEdgeUpgrade(input: {
  l4Root: string;
  edgeRoot: string;
  uid: number;
  gid?: number;
}) {
  const result = await seedEdgeL4(input.l4Root);
  await chownEdgeL4(input.l4Root, input.uid);
  for (const name of ["Caddyfile", "Caddyfile.closed"]) {
    const path = join(input.edgeRoot, name);
    const source = await readFile(path, "utf8").catch((error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return null;
      throw error;
    });
    if (source === null) continue;
    const migrated = migrateCaddyL4(source);
    if (migrated === source) continue;
    const next = `${path}.l4-upgrade`;
    await writeFile(next, migrated, { mode: 0o600 });
    await chown(next, input.uid, input.gid ?? input.uid);
    await rename(next, path);
  }
  return result;
}
