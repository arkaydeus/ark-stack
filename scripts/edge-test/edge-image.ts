// The image of the shipped `edge` service (docs/design/front-door.md FD-23): Caddy 2.11.9 plus the
// pinned caddy-ratelimit plugin. Compose either builds it from the `edge-caddy` Dockerfile stage (the
// default) or pins a published GHCR digest (`mise run images:pin-edge-caddy`). Edge harnesses run
// the same image: they build the stage, or pull the pinned digest, and check what it reports.

/** The local tag Compose gives the built image when ARK_VERSION is unset. */
export const LOCAL_EDGE_CADDY_IMAGE = "ark-edge-caddy:local";
export const EDGE_CADDY_TARGET = "edge-caddy";
export const PINNED_EDGE_CADDY =
  /^ghcr\.io\/[a-z0-9][a-z0-9-]*\/ark-edge-caddy(?::[A-Za-z0-9._-]{1,128})?@sha256:[a-f0-9]{64}$/;

type ComposeService = { image?: unknown; build?: { target?: unknown; dockerfile?: unknown } | unknown };

/**
 * What Compose runs as `edge`, refused unless it is exactly the local `edge-caddy` build or a
 * digest-pinned GHCR `ark-edge-caddy` reference without a build section.
 */
export function composeEdgeImage(compose: string) {
  const services = (Bun.YAML.parse(compose) as { services?: Record<string, ComposeService> }).services;
  const edge = services?.edge;
  if (!edge || typeof edge.image !== "string") throw new Error("Compose has no edge service image.");
  if (edge.build !== undefined) {
    const build = edge.build as { target?: unknown; dockerfile?: unknown };
    if (
      edge.image !== "ark-edge-caddy:${ARK_VERSION:-local}" ||
      build.target !== EDGE_CADDY_TARGET ||
      build.dockerfile !== "Dockerfile"
    ) {
      throw new Error(
        `Compose edge must build the ${EDGE_CADDY_TARGET} Dockerfile stage as ark-edge-caddy:\${ARK_VERSION:-local}.`,
      );
    }
    return { kind: "build" as const, image: LOCAL_EDGE_CADDY_IMAGE };
  }
  if (!PINNED_EDGE_CADDY.test(edge.image)) {
    throw new Error(
      `Compose edge image ${edge.image} is neither the ${EDGE_CADDY_TARGET} build nor a digest-pinned ghcr.io/<namespace>/ark-edge-caddy reference.`,
    );
  }
  return { kind: "pinned" as const, image: edge.image };
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
    await docker("pull", edge.image);
  }
  const version = await docker("run", "--rm", edge.image, "caddy", "version");
  if (!version.startsWith("v2.11.9 ")) throw new Error(`${edge.image} reports ${version}, expected v2.11.9.`);
  const modules = (await docker("run", "--rm", edge.image, "caddy", "list-modules")).split("\n");
  if (!modules.some((line) => line.trim() === "http.handlers.rate_limit"))
    throw new Error(`${edge.image} has no http.handlers.rate_limit module.`);
  return { ...edge, version: version.split(" ")[0]! };
}

const COMPOSE_EDGE_HEAD = /^ {2}edge:\n(?: {4}#.*\n)* {4}image: .*\n(?: {4}build:\n(?: {6}.*\n)+)?/m;

/**
 * Pins Compose's `edge` service to a published `ark-edge-caddy` digest (`mise run images:pin-edge-caddy`):
 * the image line is replaced and the build section removed, so Compose pulls exactly that digest.
 */
export function pinComposeEdge(compose: string, reference: string) {
  if (!PINNED_EDGE_CADDY.test(reference))
    throw new Error(`${reference} is not ghcr.io/<namespace>/ark-edge-caddy[:<tag>]@sha256:<digest>.`);
  if (!COMPOSE_EDGE_HEAD.test(compose)) throw new Error("Could not find the edge service image in Compose.");
  const pinned = compose.replace(
    COMPOSE_EDGE_HEAD,
    () => `  edge:
    # Caddy 2.11.9 plus the pinned caddy-ratelimit plugin (docs/design/front-door.md FD-23): the published
    # \`edge-caddy\` image (Dockerfile stage and Bake target), pinned by digest with
    # \`mise run images:pin-edge-caddy\`. Its base is the same official caddy:2.11.9 digest as tailnet-gateway.
    image: ${reference}
`,
  );
  composeEdgeImage(pinned);
  return pinned;
}

/** Replaces any earlier ark-edge-caddy entry of a release bundle's image list with `reference`. */
export function pinReleaseEdge(images: string[], reference: string) {
  if (!PINNED_EDGE_CADDY.test(reference))
    throw new Error(`${reference} is not ghcr.io/<namespace>/ark-edge-caddy[:<tag>]@sha256:<digest>.`);
  return [...images.filter((image) => !/\/ark-edge-caddy[:@]/.test(image)), reference];
}
