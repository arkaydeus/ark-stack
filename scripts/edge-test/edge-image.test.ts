import { expect, test } from "bun:test";

import {
  LOCAL_EDGE_CADDY_IMAGE,
  checkEdgeCaddyBase,
  composeEdgeImage,
  pinComposeEdge,
  pinReleaseEdge,
} from "./edge-image.ts";

const compose = await Bun.file(new URL("../../infra/platform/docker-compose.yml", import.meta.url)).text();
const dockerfile = await Bun.file(new URL("../../Dockerfile", import.meta.url)).text();
const release = await Bun.file(new URL("../../infra/platform/release.json", import.meta.url)).json();
const officialCaddy = [...compose.matchAll(/^\s*image:\s*(caddy:\S+)\s*$/gm)].map((match) => match[1]);
const digest = `sha256:${"a".repeat(64)}`;
const reference = `ghcr.io/arkaydeus/ark-edge-caddy:0123456789ab@${digest}`;

test("the shipped edge service builds the edge-caddy stage on the official Caddy pin", () => {
  expect(composeEdgeImage(compose)).toEqual({ kind: "build", image: LOCAL_EDGE_CADDY_IMAGE });
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
  const pinned = pinComposeEdge(compose, reference);
  expect(composeEdgeImage(pinned)).toEqual({ kind: "pinned", image: reference });
  expect(pinned).not.toMatch(/^ {2}edge:\n(?: {4}.*\n)*? {4}build:/m);
  // Every other service, including the official tailnet-gateway pin, is unchanged.
  expect(pinned.replace(/^ {2}edge:\n(?: {4}#.*\n)* {4}image: .*\n/m, "")).toBe(
    compose.replace(/^ {2}edge:\n(?: {4}#.*\n)* {4}image: .*\n {4}build:\n(?: {6}.*\n)+/m, ""),
  );
  const next = `ghcr.io/arkaydeus/ark-edge-caddy:v0.2.0@sha256:${"b".repeat(64)}`;
  expect(composeEdgeImage(pinComposeEdge(pinned, next)).image).toBe(next);
  // Exactly the line `mise run images:publish` prints, without a tag, is accepted too.
  const printed = `ghcr.io/arkaydeus/ark-edge-caddy@sha256:${"d".repeat(64)}`;
  expect(composeEdgeImage(pinComposeEdge(compose, printed)).image).toBe(printed);
});

test("refuses tags without a digest, other registries and other images", () => {
  for (const bad of [
    "ghcr.io/arkaydeus/ark-edge-caddy:latest",
    `docker.io/arkaydeus/ark-edge-caddy:1@${digest}`,
    `ghcr.io/arkaydeus/ark-stack:1@${digest}`,
    `caddy:2.11.9@${digest}`,
  ]) {
    expect(() => pinComposeEdge(compose, bad)).toThrow();
    expect(() => pinReleaseEdge(release.images, bad)).toThrow();
  }
  expect(() =>
    composeEdgeImage(compose.replace("image: ark-edge-caddy:${ARK_VERSION:-local}", "image: caddy:latest")),
  ).toThrow("must build");
  expect(() => composeEdgeImage(compose.replace("target: edge-caddy", "target: runtime"))).toThrow(
    "must build",
  );
});

test("the release bundle keeps the official pin and holds one edge-caddy digest", () => {
  const once = pinReleaseEdge(release.images, reference);
  expect(once).toEqual([...release.images, reference]);
  const next = `ghcr.io/arkaydeus/ark-edge-caddy:v2@sha256:${"c".repeat(64)}`;
  expect(pinReleaseEdge(once, next)).toEqual([...release.images, next]);
});
