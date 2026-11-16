import { expect, test } from "bun:test";
import { bundleDigest } from "@ark-stack/shared";

import { checkReleasePins } from "./pins.ts";

const compose = await Bun.file(new URL("../../infra/platform/docker-compose.yml", import.meta.url)).text();
const caddyImage = [...compose.matchAll(/^\s*image:\s*(caddy:\S+)\s*$/gm)][0][1];
const release = await Bun.file(new URL("../../infra/platform/release.json", import.meta.url)).json();

test("sample release matches the Compose Caddy pin and bundle digest", () => {
  expect(() => checkReleasePins(release, caddyImage)).not.toThrow();
});

test("rejects a stale release pin even when its digest is correct", () => {
  const images = [`caddy:stale@sha256:${"0".repeat(64)}`];
  expect(() => checkReleasePins({ images, digest: bundleDigest(images) }, caddyImage)).toThrow(
    "must include the tested",
  );
});

test("rejects a stale digest even when the Caddy pin is correct", () => {
  expect(() => checkReleasePins({ ...release, digest: `sha256:${"0".repeat(64)}` }, caddyImage)).toThrow(
    "digest does not match",
  );
});

test("the digest covers every image in the release", () => {
  const images = [...release.images, `example:test@sha256:${"a".repeat(64)}`];
  expect(() => checkReleasePins({ ...release, images }, caddyImage)).toThrow("digest does not match");
  expect(() => checkReleasePins({ images, digest: bundleDigest(images) }, caddyImage)).not.toThrow();
});
