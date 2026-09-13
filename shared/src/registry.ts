import { parseImageRef } from "./update-policy.ts";

export function registryHost(image: string) {
  const { name } = parseImageRef(image);
  const first = name.split("/")[0] ?? "";
  if (first === "localhost" || first.includes(".") || first.includes(":")) return first;
  return "docker.io";
}

function dockerHubRepo(name: string) {
  const rest = name.replace(/^docker.io\//, "");
  if (!rest.includes("/")) return `library/${rest}`;
  const first = rest.split("/")[0] ?? "";
  if (first.includes(".") || first.includes(":")) return rest.split("/").slice(1).join("/");
  return rest;
}

export function registryManifestUrl(image: string) {
  const { name, tag } = parseImageRef(image);
  const host = registryHost(image);
  const repo =
    host === "docker.io"
      ? dockerHubRepo(name)
      : name.replace(new RegExp(`^${host.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/`), "");
  const base =
    host === "docker.io"
      ? "https://registry-1.docker.io"
      : host.startsWith("localhost")
        ? `http://${host}`
        : `https://${host}`;
  return {
    url: `${base}/v2/${repo}/manifests/${tag}`,
    host,
    accept: "application/vnd.docker.distribution.manifest.v2+json",
  };
}

export function digestFromHeaders(headers: Headers) {
  return headers.get("docker-content-digest") ?? headers.get("Docker-Content-Digest");
}

export function firstComposeImage(compose: string) {
  const match = compose.match(/^\s*image:\s*["']?(\S+?)["']?\s*$/m);
  return match?.[1];
}

export function pinComposeImage(compose: string, digest: string) {
  const image = firstComposeImage(compose);
  if (!image) throw new Error("Service compose has no image to pin.");
  const { name, tag } = parseImageRef(image);
  const pinned = `${name}:${tag}@${digest.startsWith("sha256:") ? digest : `sha256:${digest}`}`;
  return compose.replace(/^(\s*image:\s*)["']?\S+["']?\s*$/m, `$1${pinned}`);
}
