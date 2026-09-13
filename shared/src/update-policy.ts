export const statefulComponents = new Set(["postgres", "stalwart", "ark-agent", "ark-api", "ark-control"]);

export function parseImageRef(image: string) {
  const [nameDigest, digest] = image.split("@sha256:");
  const colon = nameDigest.lastIndexOf(":");
  const name = colon === -1 ? nameDigest : nameDigest.slice(0, colon);
  const tag = colon === -1 ? "latest" : nameDigest.slice(colon + 1);
  return { name, tag, digest: digest ? `sha256:${digest}` : null };
}

export function mayAutoUpdate(input: { updatePolicy: string; image: string; component?: string }) {
  if (input.component && statefulComponents.has(input.component)) return false;
  if (input.updatePolicy !== "auto_stateless") return false;
  const parsed = parseImageRef(input.image);
  return Boolean(parsed.digest);
}

export function rollbackSafe(component: string) {
  return !statefulComponents.has(component);
}

export function candidateRequiresApproval(input: { component?: string; updatePolicy: string }) {
  return (
    input.updatePolicy !== "auto_stateless" ||
    Boolean(input.component && statefulComponents.has(input.component))
  );
}
