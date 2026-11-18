import { expect, test } from "bun:test";
import { lstat, mkdtemp, readlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { hashGenerationDir } from "@ark-stack/shared";

import { checkImageIds, composeImages, seedEdgeL4 } from "./install-edge-l4.ts";

const root = join(import.meta.dir, "..");

test("seeds one initial generation and points current at it, idempotently", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ark-install-edge-l4-"));
  const first = await seedEdgeL4(dir);
  expect(first.seeded).toBe(true);
  expect((await lstat(join(dir, "front-ingress"))).isDirectory()).toBe(true);
  expect(await readlink(join(dir, "current"))).toBe(`generations/${first.generation}`);
  expect(await hashGenerationDir(join(dir, "generations", first.generation))).toBe(first.generation);
  expect((await lstat(join(dir, "current", "haproxy.closed.cfg"))).isFile()).toBe(true);
  expect(await seedEdgeL4(dir)).toEqual({ generation: first.generation, seeded: false });
  await rm(join(dir, "front-ingress"), { recursive: true });
  expect(await seedEdgeL4(dir)).toEqual({ generation: first.generation, seeded: false });
  expect((await lstat(join(dir, "front-ingress"))).isDirectory()).toBe(true);
  await rm(dir, { recursive: true, force: true });
});

test("the image check wants HAProxy's numeric uid 99 and a free GID 4400", () => {
  expect(checkImageIds({ image: "haproxy", uid: "99\n", group4400: "" }, 99)).toEqual([]);
  expect(checkImageIds({ image: "haproxy", uid: "100\n", group4400: "" }, 99)).toEqual([
    "haproxy runs as uid 100, not 99",
  ]);
  expect(checkImageIds({ image: "bun", uid: "1000\n", group4400: "edge:x:4400:\n" })).toEqual([
    "bun already defines GID 4400 (edge:x:4400:)",
  ]);
});

test("reads the pinned HAProxy and Bun images from the shipped files", async () => {
  const images = composeImages(
    await Bun.file(join(root, "infra/platform/docker-compose.yml")).text(),
    await Bun.file(join(root, "Dockerfile")).text(),
  );
  expect(images.haproxy).toBe(
    "haproxy:3.2.26-alpine@sha256:1c3568e520453cc8ba98c39501febcf450429c80e6cc27ecad779961d76e597c",
  );
  expect(images.bun).toMatch(/^oven\/bun:1\.4\.2-slim@sha256:[a-f0-9]{64}$/);
});

test("maintenance initializes a pre-FD-25 tree and converts both persisted Caddy variants idempotently", async () => {
  const { mkdir, readFile, writeFile } = await import("node:fs/promises");
  const { prepareEdgeUpgrade } = await import("./install-edge-l4.ts");
  const dir = await mkdtemp(join(tmpdir(), "ark-edge-upgrade-"));
  try {
    const edgeRoot = join(dir, "edge");
    const l4Root = join(dir, "edge-l4");
    await mkdir(edgeRoot);
    const legacy =
      "{\n  admin edge-admin:2019\n  auto_https off\n}\n\nadmin.example.com {\n  tls /certs/fullchain.pem /certs/privkey.pem\n  respond ok\n}\n";
    for (const name of ["Caddyfile", "Caddyfile.closed"]) await writeFile(join(edgeRoot, name), legacy);
    const input = { edgeRoot, l4Root, uid: process.getuid!(), gid: process.getgid!() };
    // On Linux the privileged integration covers the real 1000:4400 ownership. On macOS use
    // the caller's group because an unprivileged host cannot chown to the container-only GID.
    if (process.getuid!() !== 0) {
      const { migrateCaddyL4 } = await import("./install-edge-l4.ts");
      const converted = migrateCaddyL4(legacy);
      expect(converted).toContain("https_port 8443");
      expect(converted).toContain("admin.example.com {\n  bind 127.0.0.1");
      expect(converted).toContain("tls /certs/fullchain.pem /certs/privkey.pem");
      expect(migrateCaddyL4(converted)).toBe(converted);
      return;
    }
    expect((await prepareEdgeUpgrade(input)).seeded).toBe(true);
    expect((await lstat(l4Root)).gid).toBe(4400);
    expect((await lstat(l4Root)).mode & 0o7777).toBe(0o2750);
    const migrated = await readFile(join(edgeRoot, "Caddyfile"), "utf8");
    expect(migrated).toContain("https_port 8443");
    expect((await prepareEdgeUpgrade(input)).seeded).toBe(false);
    expect(await readFile(join(edgeRoot, "Caddyfile"), "utf8")).toBe(migrated);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
