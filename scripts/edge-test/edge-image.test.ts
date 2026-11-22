import { expect, test } from "bun:test";

import {
  EDGE_CADDY_PIN_FORMAT,
  LOCAL_EDGE_CADDY_IMAGE,
  PINNED_EDGE_PLATFORM,
  checkEdgeCaddyBase,
  composeEdgeImage,
  isEdgeCaddyReleaseImage,
  pinComposeEdge,
  pinReleaseEdge,
  prepareEdgeImage,
} from "./edge-image.ts";

const compose = await Bun.file(new URL("../../infra/platform/docker-compose.yml", import.meta.url)).text();
const dockerfile = await Bun.file(new URL("../../Dockerfile", import.meta.url)).text();
const release = await Bun.file(new URL("../../infra/platform/release.json", import.meta.url)).json();
const officialCaddy = [...compose.matchAll(/^\s*image:\s*(caddy:\S+)\s*$/gm)].map((match) => match[1]);
const digest = `sha256:${"a".repeat(64)}`;
const reference = `ghcr.io/arkaydeus/ark-stack-edge-caddy:0123456789ab@${digest}`;
const legacyReference = `ghcr.io/arkaydeus/ark-edge-caddy@sha256:${"b".repeat(64)}`;

const buildFixture = `services:
  edge:
    image: ark-stack-edge-caddy:\${ARK_VERSION:-local}
    build:
      context: ../..
      dockerfile: Dockerfile
      target: edge-caddy
    restart: unless-stopped
  tailnet-gateway:
    image: ${officialCaddy[0]}
`;
const otherImages = ["registry.example/base@sha256:" + "e".repeat(64)];
const legacyPinnedFixture = `services:
  edge:
    image: ${legacyReference}
    platform: ${PINNED_EDGE_PLATFORM}
    restart: unless-stopped
  tailnet-gateway:
    image: ${officialCaddy[0]}
`;

test("the shipped edge build or pin agrees with the release bundle", () => {
  const shipped = composeEdgeImage(compose);
  const releaseEdge = release.images.filter(isEdgeCaddyReleaseImage);
  expect(releaseEdge).toEqual(shipped.kind === "build" ? [] : [shipped.image]);
  if (shipped.kind === "pinned") {
    const document = Bun.YAML.parse(compose) as { services: { edge: { platform?: string } } };
    expect(document.services.edge.platform).toBe(PINNED_EDGE_PLATFORM);
  }
  // Only tailnet-gateway runs the official image; it is also the custom build's base.
  expect(officialCaddy).toHaveLength(1);
  expect(() => checkEdgeCaddyBase(dockerfile, officialCaddy[0]!)).not.toThrow();
  expect(() => checkEdgeCaddyBase(dockerfile, `caddy:2.11.9@sha256:${"0".repeat(64)}`)).toThrow(
    "must be FROM",
  );
  // The plugin is pinned to one tagged version and module hash, and the builder by digest.
  expect(dockerfile).toContain("ARG CADDY_RATELIMIT_VERSION=v0.1.0\n");
  expect(dockerfile).toMatch(/^ARG CADDY_RATELIMIT_SUM=h1:[A-Za-z0-9+/]{43}=$/m);
  expect(dockerfile).toMatch(/^FROM caddy:2\.11\.9-builder@sha256:[a-f0-9]{64} AS edge-caddy-build$/m);
});

test("pinning replaces the build with the published digest, and re-pinning replaces that", () => {
  const pinned = pinComposeEdge(buildFixture, reference);
  expect(composeEdgeImage(pinned)).toEqual({
    kind: "pinned",
    image: reference,
    platform: PINNED_EDGE_PLATFORM,
  });
  expect(pinned).not.toMatch(/^ {2}edge:\n(?: {4}.*\n)*? {4}build:/m);
  // Every other service, including the official tailnet-gateway pin, is unchanged.
  expect(pinned.replace(/^ {2}edge:\n(?: {4}#.*\n)* {4}image: .*\n {4}platform: .*\n/m, "")).toBe(
    buildFixture.replace(/^ {2}edge:\n(?: {4}#.*\n)* {4}image: .*\n {4}build:\n(?: {6}.*\n)+/m, ""),
  );
  const next = `ghcr.io/arkaydeus/ark-stack-edge-caddy:v0.2.0@sha256:${"b".repeat(64)}`;
  expect(composeEdgeImage(pinComposeEdge(pinned, next)).image).toBe(next);
  // Exactly the line `mise run images:publish` prints, without a tag, is accepted too.
  const printed = `ghcr.io/arkaydeus/ark-stack-edge-caddy@sha256:${"d".repeat(64)}`;
  expect(composeEdgeImage(pinComposeEdge(buildFixture, printed)).image).toBe(printed);
});

test("refuses tags without a digest, other registries and other images", () => {
  for (const bad of [
    "ghcr.io/arkaydeus/ark-stack-edge-caddy:latest",
    "ghcr.io/arkaydeus/ark-edge-caddy:latest",
    `docker.io/arkaydeus/ark-stack-edge-caddy:1@${digest}`,
    `docker.io/arkaydeus/ark-edge-caddy@${digest}`,
    `ghcr.io/arkaydeus/ark-stack-app:1@${digest}`,
    `caddy:2.11.9@${digest}`,
  ]) {
    expect(() => pinComposeEdge(buildFixture, bad)).toThrow();
    expect(() => pinReleaseEdge(otherImages, bad)).toThrow();
    expect(() => composeEdgeImage(legacyPinnedFixture.replace(legacyReference, bad))).toThrow(
      EDGE_CADDY_PIN_FORMAT,
    );
  }
  expect(() =>
    composeEdgeImage(
      buildFixture.replace("image: ark-stack-edge-caddy:${ARK_VERSION:-local}", "image: caddy:latest"),
    ),
  ).toThrow("must build");
  expect(() => composeEdgeImage(buildFixture.replace("target: edge-caddy", "target: runtime"))).toThrow(
    "must build",
  );
});

test("the release bundle keeps the official pin and holds one edge-caddy digest", () => {
  const once = pinReleaseEdge(otherImages, reference);
  expect(once).toEqual([...otherImages, reference]);
  const next = `ghcr.io/arkaydeus/ark-stack-edge-caddy:v2@sha256:${"c".repeat(64)}`;
  expect(pinReleaseEdge(once, next)).toEqual([...otherImages, next]);
});

test("a new pin replaces the legacy pin in both Compose and the release image list", () => {
  const pinned = pinComposeEdge(legacyPinnedFixture, reference);
  const images = pinReleaseEdge([officialCaddy[0]!, legacyReference], reference);
  const { services } = Bun.YAML.parse(pinned) as { services: Record<string, { image: string }> };

  expect(composeEdgeImage(pinned).image).toBe(reference);
  expect(images).toEqual([officialCaddy[0]!, reference]);
  expect(images.toSorted()).toEqual(
    Object.values(services)
      .map((service) => service.image)
      .toSorted(),
  );
});

test("edge setup builds the local stage and explicitly uses amd64 for a pin", async () => {
  const calls: string[][] = [];
  const docker = async (...args: string[]) => {
    calls.push(args);
    if (args.at(-1) === "version") return "v2.11.9 build";
    if (args.at(-1) === "list-modules") return "http.handlers.rate_limit";
    if (args.at(-1) === "build-info") return "=>\t/build/ark-bounded-ratelimit\t(devel)";
    return "";
  };
  const local = await prepareEdgeImage(docker, { root: "/repo", compose: buildFixture });
  expect(local.image).toBe(LOCAL_EDGE_CADDY_IMAGE);
  expect(calls[0]).toEqual([
    "buildx",
    "build",
    "--load",
    "--target",
    "edge-caddy",
    "--tag",
    LOCAL_EDGE_CADDY_IMAGE,
    "--file",
    "/repo/Dockerfile",
    "/repo",
  ]);
  expect(calls[1]).toEqual(["run", "--rm", LOCAL_EDGE_CADDY_IMAGE, "caddy", "version"]);

  for (const [manifest, image] of [
    [pinComposeEdge(buildFixture, reference), reference],
    [legacyPinnedFixture, legacyReference],
  ] as const) {
    calls.length = 0;
    expect(composeEdgeImage(manifest)).toEqual({ kind: "pinned", image, platform: PINNED_EDGE_PLATFORM });
    const pinned = await prepareEdgeImage(docker, { root: "/repo", compose: manifest });
    expect(pinned).toMatchObject({ image, version: "v2.11.9" });
    expect(calls).toEqual([
      ["pull", "--platform", PINNED_EDGE_PLATFORM, image],
      ["run", "--rm", "--platform", PINNED_EDGE_PLATFORM, image, "caddy", "version"],
      ["run", "--rm", "--platform", PINNED_EDGE_PLATFORM, image, "caddy", "list-modules"],
      ["run", "--rm", "--platform", PINNED_EDGE_PLATFORM, image, "caddy", "build-info"],
    ]);
  }
});
