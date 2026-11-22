import { expect, test } from "bun:test";
import { join } from "node:path";

import { bakePublishedImages, composeBuiltImages, pullPublishedImages, type Exec } from "./install-images";

const root = join(import.meta.dir, "..");
const revision = "0123456789ab".padEnd(40, "c");
const compose = `
x-app: &app
  image: ark-stack-app:\${ARK_VERSION:-local}
services:
  edge:
    image: ark-stack-edge-caddy:\${ARK_VERSION:-local}
  edge-l4:
    image: haproxy:3.2.26-alpine@sha256:${"1".repeat(64)}
`;

function fakeDocker(
  overrides: { missing?: string; label?: string; dirty?: boolean; headStatus?: number } = {},
) {
  const calls: string[][] = [];
  const exec: Exec = async (argv) => {
    calls.push(argv);
    const ok = (stdout = "") => ({ status: 0, stdout, stderr: "" });
    if (argv[0] === "git") {
      if (argv.includes("rev-parse"))
        return { status: overrides.headStatus ?? 0, stdout: `${revision}\n`, stderr: "" };
      return ok(overrides.dirty ? " M scripts/install.ts\n" : "");
    }
    if (argv[1] === "pull") {
      return overrides.missing && argv.at(-1)!.includes(overrides.missing)
        ? { status: 1, stdout: "", stderr: "manifest unknown" }
        : ok();
    }
    if (argv[1] === "image") return ok(`${overrides.label ?? revision}\n`);
    return ok();
  };
  return { calls, exec };
}

const pull = (exec: Exec, env: Record<string, string | undefined> = {}) =>
  pullPublishedImages({ root: "/opt/ark-stack", compose, version: "local", env, exec });

test("pulls, verifies and retags every first-party image for the checkout's commit", async () => {
  const { calls, exec } = fakeDocker();
  expect(await pull(exec)).toEqual({ pulled: true, tag: "0123456789ab" });
  expect(calls[0]).toEqual([
    "git",
    "-c",
    "safe.directory=/opt/ark-stack",
    "-C",
    "/opt/ark-stack",
    "rev-parse",
    "HEAD",
  ]);
  expect(calls.filter((argv) => argv[1] === "pull").map((argv) => argv.at(-1))).toEqual([
    "ghcr.io/arkaydeus/ark-stack-app:0123456789ab",
    "ghcr.io/arkaydeus/ark-stack-edge-caddy:0123456789ab",
  ]);
  expect(calls.filter((argv) => argv[1] === "tag")).toEqual([
    ["docker", "tag", "ghcr.io/arkaydeus/ark-stack-app:0123456789ab", "ark-stack-app:local"],
    ["docker", "tag", "ghcr.io/arkaydeus/ark-stack-edge-caddy:0123456789ab", "ark-stack-edge-caddy:local"],
  ]);
});

test("a registry override and ARK_VERSION select the pulled and local names", async () => {
  const { calls, exec } = fakeDocker();
  const result = await pullPublishedImages({
    root,
    compose,
    version: "v2",
    env: { ARK_IMAGE_REGISTRY: "ghcr.io/fork" },
    exec,
  });
  expect(result.pulled).toBe(true);
  expect(calls.filter((argv) => argv[1] === "tag").map((argv) => argv.slice(2))).toContainEqual([
    "ghcr.io/fork/ark-stack-app:0123456789ab",
    "ark-stack-app:v2",
  ]);
});

test("falls back to a local build without tagging anything", async () => {
  const cases: [Parameters<typeof fakeDocker>[0], Record<string, string>, RegExp][] = [
    [{}, { ARK_INSTALL_BUILD_IMAGES: "1" }, /ARK_INSTALL_BUILD_IMAGES/],
    [{}, { ARK_IMAGE_REGISTRY: "docker.io/someone" }, /ARK_IMAGE_REGISTRY/],
    [{ headStatus: 128 }, {}, /commit could not be read/],
    [{ dirty: true }, {}, /local changes/],
    [{ missing: "ark-stack-app" }, {}, /ark-stack-app:0123456789ab is not available/],
    [{ label: "f".repeat(40) }, {}, /built from f{40}/],
    [{ label: "" }, {}, /unknown revision/],
  ];
  for (const [docker, env, reason] of cases) {
    const { calls, exec } = fakeDocker(docker);
    const result = await pull(exec, env);
    expect(result.pulled).toBe(false);
    if (!result.pulled) expect(result.reason).toMatch(reason);
    expect(calls.some((argv) => argv[1] === "tag")).toBe(false);
  }
  const forced = fakeDocker();
  await pull(forced.exec, { ARK_INSTALL_BUILD_IMAGES: "1" });
  expect(forced.calls).toEqual([]);
});

test("Compose builds exactly the images Bake publishes", async () => {
  const built = composeBuiltImages(await Bun.file(join(root, "infra/platform/docker-compose.yml")).text());
  expect(built).toEqual(bakePublishedImages(await Bun.file(join(root, "docker-bake.hcl")).text()));
  expect(built).toHaveLength(12);
  expect(() => composeBuiltImages("services: {}\n")).toThrow();
});
