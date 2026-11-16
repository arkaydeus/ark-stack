import { bundleDigest } from "@ark-stack/shared";

export function checkReleasePins(release: { images: string[]; digest: string }, caddyImage: string) {
  const caddyPins = release.images.filter((image) => image.startsWith("caddy:"));
  if (caddyPins.length !== 1 || caddyPins[0] !== caddyImage) {
    throw new Error(`infra/platform/release.json must include the tested ${caddyImage}.`);
  }
  if (release.digest !== bundleDigest(release.images)) {
    throw new Error("infra/platform/release.json digest does not match bundleDigest(images).");
  }
}
