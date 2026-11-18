import { createHash, verify } from "node:crypto";
import { parse as parseYaml } from "yaml";

import { statefulComponents } from "./update-policy.ts";

export type MaintenanceBundle = {
  version: string;
  images: string[];
  digest: string;
  composeDigest?: string;
  signature?: string;
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
  if (bundle.images.some((image) => !/@sha256:[a-f0-9]{64}$/i.test(image))) {
    throw new Error("Every maintenance image must be pinned by an immutable sha256 digest.");
  }
  const stateful = bundle.images.filter((image) =>
    [...statefulComponents].some((name) => image.includes(name)),
  );
  if (stateful.length && !bundle.allowStateful) {
    throw new Error(
      `Refusing unattended stateful images: ${stateful.join(", ")}. Set allowStateful after a reviewed plan.`,
    );
  }
  // `rollbackSafe` takes a bare component name, so calling it with a full image reference
  // never matches. Reuse the stateful set already computed from the same references.
  return { images: bundle.images, rollbackSafe: stateful.length === 0 };
}

export function composeDigest(source: string) {
  return `sha256:${createHash("sha256").update(source).digest("hex")}`;
}

export function maintenanceSignaturePayload(bundle: MaintenanceBundle) {
  return JSON.stringify({
    version: bundle.version,
    images: bundle.images.toSorted(),
    digest: bundle.digest,
    composeDigest: bundle.composeDigest,
    allowStateful: Boolean(bundle.allowStateful),
  });
}

/** Verify publisher trust and bind approval to the exact Compose file executed. */
export function verifyMaintenanceRelease(
  bundle: MaintenanceBundle,
  composeSource: string,
  publisherPublicKey: string,
) {
  const validated = validateMaintenanceBundle(bundle);
  if (!bundle.composeDigest || bundle.composeDigest !== composeDigest(composeSource)) {
    throw new Error("Maintenance release does not match the exact Compose manifest.");
  }
  if (!bundle.signature) throw new Error("Maintenance release is not signed by a publisher.");
  const trusted = verify(
    null,
    Buffer.from(maintenanceSignaturePayload(bundle)),
    publisherPublicKey,
    Buffer.from(bundle.signature, "base64"),
  );
  if (!trusted) throw new Error("Maintenance release publisher signature is invalid.");
  const document = parseYaml(composeSource) as { services?: Record<string, { image?: unknown }> };
  const composeImages = [
    ...new Set(
      Object.values(document.services ?? {})
        .map((service) => service.image)
        .filter((image): image is string => typeof image === "string"),
    ),
  ].toSorted();
  if (
    composeImages.length !== bundle.images.length ||
    composeImages.some((image, index) => image !== bundle.images.toSorted()[index])
  ) {
    throw new Error("Maintenance release image list does not match the exact Compose manifest.");
  }
  return { ...validated, serviceNames: Object.keys(document.services ?? {}) };
}

export function maintenanceArgv(project: string, file: string) {
  return [
    "docker",
    "compose",
    "-f",
    file,
    "-p",
    project,
    "up",
    "-d",
    "--no-build",
    "--pull",
    "never",
    "--wait",
    "--wait-timeout",
    "120",
  ];
}

/** One container of a Compose project, as `docker inspect` reports it. */
export type NamespaceContainer = {
  service: string;
  id: string;
  /** `HostConfig.NetworkMode`; `container:<id>` for a `network_mode: service:` dependent. */
  networkMode: string;
  running: boolean;
  /** `State.StartedAt`, an RFC 3339 timestamp. */
  startedAt: string;
};

export type StaleNamespaceDependent = {
  service: string;
  parent?: string;
  reason: "owner-replaced" | "owner-restarted" | "owner-stopped" | "not-running";
};

/**
 * Finds `network_mode: service:` dependents that are no longer in their owner's live namespace.
 *
 * A dependent joins the namespace of one container instance. If the owner is recreated (new id)
 * or restarted after the dependent started, the dependent keeps running in the old namespace with
 * only loopback, so the edge silently stops serving. Compose recreates dependents only when it
 * recreates the owner itself; a crash restart or `docker restart` is not detected
 * (docs/design/front-door.md §3.6).
 */
export function staleNamespaceDependents(containers: NamespaceContainer[]): StaleNamespaceDependent[] {
  const byId = new Map(containers.map((container) => [container.id, container]));
  const stale: StaleNamespaceDependent[] = [];
  for (const container of containers) {
    if (!container.networkMode.startsWith("container:")) continue;
    const ownerId = container.networkMode.slice("container:".length);
    const owner = byId.get(ownerId);
    if (!owner) {
      stale.push({ service: container.service, reason: "owner-replaced" });
    } else if (!owner.running) {
      stale.push({ service: container.service, parent: owner.service, reason: "owner-stopped" });
    } else if (!container.running) {
      stale.push({ service: container.service, parent: owner.service, reason: "not-running" });
    } else if (Date.parse(owner.startedAt) > Date.parse(container.startedAt)) {
      stale.push({ service: container.service, parent: owner.service, reason: "owner-restarted" });
    }
  }
  return stale;
}
