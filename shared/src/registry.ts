import { parseImageRef } from "./update-policy.ts";

export function registryManifestUrl(image: string) {
  const { name, tag } = parseImageRef(image);
  if (name.startsWith("ghcr.io/")) {
    const repo = name.replace(/^ghcr.io\//, "");
    return {
      url: `https://ghcr.io/v2/${repo}/manifests/${tag}`,
      accept: "application/vnd.docker.distribution.manifest.v2+json",
    };
  }
  const repo = name.replace(/^docker.io\/(?:library\/)?/, "library/");
  return {
    url: `https://registry-1.docker.io/v2/${repo}/manifests/${tag}`,
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
