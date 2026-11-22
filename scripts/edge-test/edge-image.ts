// The image of the shipped `edge` service (docs/design/front-door.md FD-23): Caddy 2.11.9 plus the
// pinned caddy-ratelimit plugin. Compose either builds it from the `edge-caddy` Dockerfile stage (the
// default) or pins a published GHCR digest (`mise run images:pin-edge-caddy`). Edge harnesses run
// the same image: they build the stage, or pull the pinned digest, and check what it reports.

/** The local tag Compose gives the built image when ARK_VERSION is unset. */
export const LOCAL_EDGE_CADDY_IMAGE = "ark-stack-edge-caddy:local";
export const PINNED_EDGE_PLATFORM = "linux/amd64";
export const EDGE_CADDY_TARGET = "edge-caddy";
export const EDGE_CADDY_PIN_FORMAT = "ghcr.io/<namespace>/ark-stack-edge-caddy[:<tag>]@sha256:<digest>";
const edgeCaddyPin =
  /^ghcr\.io\/[a-z0-9][a-z0-9-]*\/(ark-(?:stack-)?edge-caddy)(?::[A-Za-z0-9._-]{1,128})?@sha256:[a-f0-9]{64}$/;

export function isPublishedEdgeCaddyPin(reference: string) {
  return edgeCaddyPin.exec(reference)?.[1] === "ark-stack-edge-caddy";
}

export function isEdgeCaddyReleaseImage(reference: string) {
  return /\/ark-(?:stack-)?edge-caddy[:@]/.test(reference);
}

type ComposeService = { image?: unknown; build?: { target?: unknown; dockerfile?: unknown } | unknown };

/**
 * What Compose runs as `edge`, refused unless it is exactly the local `edge-caddy` build or a
 * digest-pinned GHCR reference for either edge repository without a build section.
 */
export function composeEdgeImage(compose: string) {
  const services = (Bun.YAML.parse(compose) as { services?: Record<string, ComposeService> }).services;
  const edge = services?.edge;
  if (!edge || typeof edge.image !== "string") throw new Error("Compose has no edge service image.");
  if (edge.build !== undefined) {
    const build = edge.build as { target?: unknown; dockerfile?: unknown };
    if (
      edge.image !== "ark-stack-edge-caddy:${ARK_VERSION:-local}" ||
      build.target !== EDGE_CADDY_TARGET ||
      build.dockerfile !== "Dockerfile"
    ) {
      throw new Error(
        `Compose edge must build the ${EDGE_CADDY_TARGET} Dockerfile stage as ark-stack-edge-caddy:\${ARK_VERSION:-local}.`,
      );
    }
    return { kind: "build" as const, image: LOCAL_EDGE_CADDY_IMAGE };
  }
  if (!edgeCaddyPin.test(edge.image)) {
    throw new Error(
      `Invalid Compose edge image ${edge.image}. Use the ${EDGE_CADDY_TARGET} build or pin ${EDGE_CADDY_PIN_FORMAT}. Existing pins to the legacy ark-edge-caddy repository are also supported.`,
    );
  }
  return { kind: "pinned" as const, image: edge.image, platform: PINNED_EDGE_PLATFORM };
}

/** The Dockerfile's edge-caddy runtime stage must sit on the tested official Caddy digest. */
export function checkEdgeCaddyBase(dockerfile: string, caddyImage: string) {
  if (!dockerfile.includes(`FROM ${caddyImage} AS ${EDGE_CADDY_TARGET}\n`)) {
    throw new Error(`The Dockerfile ${EDGE_CADDY_TARGET} stage must be FROM the tested ${caddyImage}.`);
  }
}

/**
 * Builds the edge-caddy stage (or pulls the pinned digest), then requires Caddy v2.11.9 with the
 * `http.handlers.rate_limit` module. Returns the image reference to run.
 */
export async function prepareEdgeImage(
  docker: (...args: string[]) => Promise<string>,
  input: { root: string; compose: string },
) {
  const edge = composeEdgeImage(input.compose);
  if (edge.kind === "build") {
    await docker(
      "buildx",
      "build",
      "--load",
      "--target",
      EDGE_CADDY_TARGET,
      "--tag",
      edge.image,
      "--file",
      `${input.root}/Dockerfile`,
      input.root,
    );
  } else {
    await docker("pull", "--platform", edge.platform, edge.image);
  }
  const platformArgs = edge.kind === "pinned" ? ["--platform", edge.platform] : [];
  const version = await checkEdgeImage(docker, edge.image, platformArgs);
  return { ...edge, platformArgs, version };
}

export async function checkEdgeImage(
  docker: (...args: string[]) => Promise<string>,
  image: string,
  platformArgs: string[],
) {
  const version = await docker("run", "--rm", ...platformArgs, image, "caddy", "version");
  if (!version.startsWith("v2.11.9 ")) throw new Error(`${image} reports ${version}, expected v2.11.9.`);
  const modules = (await docker("run", "--rm", ...platformArgs, image, "caddy", "list-modules")).split("\n");
  if (!modules.some((line) => line.trim() === "http.handlers.rate_limit"))
    throw new Error(`${image} has no http.handlers.rate_limit module.`);
  const build = await docker("run", "--rm", ...platformArgs, image, "caddy", "build-info");
  if (!/^=>\s+\/build\/ark-bounded-ratelimit\s/m.test(build))
    throw new Error(`${image} has no Ark rate-limit memory budget.`);
  return version.split(" ")[0]!;
}

const COMPOSE_EDGE_HEAD =
  /^ {2}edge:\n(?: {4}#.*\n)* {4}image: .*\n(?: {4}platform: .*\n)?(?: {4}build:\n(?: {6}.*\n)+)?/m;

/**
 * Pins Compose's `edge` service to a published `ark-stack-edge-caddy` digest (`mise run images:pin-edge-caddy`):
 * the image line is replaced and the build section removed, so Compose pulls exactly that digest.
 */
export function pinComposeEdge(compose: string, reference: string) {
  if (!isPublishedEdgeCaddyPin(reference))
    throw new Error(`Expected ${EDGE_CADDY_PIN_FORMAT}, got ${reference}.`);
  if (!COMPOSE_EDGE_HEAD.test(compose)) throw new Error("Could not find the edge service image in Compose.");
  const pinned = compose.replace(
    COMPOSE_EDGE_HEAD,
    () => `  edge:
    # Caddy 2.11.9 plus the pinned caddy-ratelimit plugin (docs/design/front-door.md FD-23): the published
    # \`edge-caddy\` image (Dockerfile stage and Bake target), pinned by digest with
    # \`mise run images:pin-edge-caddy\`. Its base is the same official caddy:2.11.9 digest as tailnet-gateway.
    image: ${reference}
    platform: ${PINNED_EDGE_PLATFORM}
`,
  );
  composeEdgeImage(pinned);
  return pinned;
}

/** Replaces earlier edge pins under either repository name with `reference`. */
export function pinReleaseEdge(images: string[], reference: string) {
  if (!isPublishedEdgeCaddyPin(reference))
    throw new Error(`Expected ${EDGE_CADDY_PIN_FORMAT}, got ${reference}.`);
  return [...images.filter((image) => !isEdgeCaddyReleaseImage(image)), reference];
}
