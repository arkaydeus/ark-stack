import { validateComposeSource } from "./compose-policy.ts";

export type DiscoveredContainer = {
  id: string;
  name: string;
  image: string;
  state: string;
  labels: Record<string, string>;
  project?: string;
};

export function classifyDiscovery(
  discovered: DiscoveredContainer[],
  registeredNames: string[],
  protectedProjects = ["ark-platform", "ark-mail", "ark-monitoring"],
) {
  const unmanaged = discovered.filter((item) => {
    const project = item.project ?? item.labels["com.docker.compose.project"];
    if (project && protectedProjects.includes(project)) return false;
    const service = item.labels["com.docker.compose.service"] ?? item.name.replace(/^\//, "");
    return !registeredNames.includes(service);
  });
  return {
    unmanaged,
    protected: discovered.filter((item) =>
      protectedProjects.includes(item.project ?? item.labels["com.docker.compose.project"] ?? ""),
    ),
  };
}

export function adoptionPreview(compose: string) {
  const policy = validateComposeSource(compose);
  if (!policy.ok) {
    return { ok: false as const, violations: policy.violations, readOnly: true };
  }
  return { ok: true as const, images: policy.images, readOnly: false };
}
