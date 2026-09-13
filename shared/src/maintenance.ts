import { createHash } from "node:crypto";

import { rollbackSafe, statefulComponents } from "./update-policy.ts";

export type MaintenanceBundle = {
  version: string;
  images: string[];
  digest: string;
  allowStateful?: boolean;
};

export function bundleDigest(images: string[]) {
  return `sha256:${createHash("sha256").update(images.toSorted().join("\n")).digest("hex")}`;
}

export function validateMaintenanceBundle(bundle: MaintenanceBundle) {
  if (!bundle.version || !bundle.images.length) {
    throw new Error("Maintenance bundle must include a version and at least one image.");
  }
  if (bundle.digest !== bundleDigest(bundle.images)) {
    throw new Error("Maintenance bundle digest does not match the image list.");
  }
  const stateful = bundle.images.filter((image) =>
    [...statefulComponents].some((name) => image.includes(name)),
  );
  if (stateful.length && !bundle.allowStateful) {
    throw new Error(
      `Refusing unattended stateful images: ${stateful.join(", ")}. Set allowStateful after a reviewed plan.`,
    );
  }
  return { images: bundle.images, rollbackSafe: bundle.images.every((image) => rollbackSafe(image)) };
}

export function maintenanceArgv(project: string, file: string) {
  return ["docker", "compose", "-f", file, "-p", project, "up", "-d", "--no-build", "--pull", "never"];
}
