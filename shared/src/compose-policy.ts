import { parse as parseYaml } from "yaml";

const MAX_BYTES = 64 * 1024;
const MAX_SERVICES = 20;
const RESERVED_PORTS = new Set([25, 80, 443, 465, 587, 993, 5432, 5433]);
const DEFAULT_REGISTRIES = ["docker.io", "ghcr.io", "public.ecr.aws", "quay.io"];

const FORBIDDEN_SERVICE_KEYS = new Set([
  "privileged",
  "devices",
  "device_cgroup_rules",
  "cap_add",
  "cap_drop",
  "security_opt",
  "pid",
  "ipc",
  "userns_mode",
  "uts",
  "build",
  "extends",
  "include",
  "env_file",
  "secrets",
  "configs",
  "network_mode",
  "container_name",
  "cgroup_parent",
  "runtime",
  "hooks",
  "post_start",
  "pre_stop",
]);

export type ComposeViolation = { path: string; message: string };

export type ComposePolicyResult =
  | { ok: true; services: string[]; images: string[]; ports: number[] }
  | { ok: false; violations: ComposeViolation[] };

export function validateComposeSource(
  source: string,
  options: { allowedRegistries?: string[] } = {},
): ComposePolicyResult {
  const violations: ComposeViolation[] = [];
  if (source.length > MAX_BYTES) {
    return {
      ok: false,
      violations: [{ path: "$", message: "Compose document exceeds the 64 KiB input limit." }],
    };
  }
  if (/include:/.test(source)) {
    violations.push({ path: "include", message: "Remote or local Compose includes are not allowed." });
  }
  let parsed: unknown;
  try {
    parsed = parseYaml(source, { merge: false, uniqueKeys: true });
  } catch (error) {
    return {
      ok: false,
      violations: [
        { path: "$", message: error instanceof Error ? error.message : "Compose YAML is invalid." },
      ],
    };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, violations: [{ path: "$", message: "Compose document must be a mapping." }] };
  }
  const doc = parsed as Record<string, unknown>;
  if ("include" in doc) violations.push({ path: "include", message: "Compose includes are not allowed." });
  if (doc.secrets)
    violations.push({
      path: "secrets",
      message: "Use platform secret references, not Compose secrets blocks.",
    });
  const services = asRecord(doc.services, "services", violations);
  if (!services) return { ok: false, violations };
  const names = Object.keys(services);
  if (names.length === 0) violations.push({ path: "services", message: "At least one service is required." });
  if (names.length > MAX_SERVICES) {
    violations.push({ path: "services", message: `At most ${MAX_SERVICES} services are allowed.` });
  }
  const images: string[] = [];
  const ports: number[] = [];
  for (const [name, raw] of Object.entries(services)) {
    const service = asRecord(raw, `services.${name}`, violations);
    if (!service) continue;
    for (const key of Object.keys(service)) {
      if (FORBIDDEN_SERVICE_KEYS.has(key)) {
        violations.push({
          path: `services.${name}.${key}`,
          message: `Unsupported field "${key}" is rejected.`,
        });
      }
    }
    if (service.privileged === true) {
      violations.push({
        path: `services.${name}.privileged`,
        message: "Privileged containers are not allowed.",
      });
    }
    const image = typeof service.image === "string" ? service.image : "";
    if (!image) {
      violations.push({
        path: `services.${name}.image`,
        message: "Every service must use a prebuilt image. Raw build is disabled.",
      });
    } else if (hasInterpolation(image)) {
      violations.push({
        path: `services.${name}.image`,
        message: "Compose interpolation is not allowed in image references.",
      });
    } else {
      images.push(image);
      if (!isAllowedImage(image, options.allowedRegistries ?? DEFAULT_REGISTRIES)) {
        violations.push({
          path: `services.${name}.image`,
          message:
            "Image must come from an allowed registry and must not use a floating latest tag without a digest.",
        });
      }
    }
    if (
      hasInterpolation(service.volumes) ||
      hasInterpolation(service.ports) ||
      hasInterpolation(service.environment)
    ) {
      violations.push({
        path: `services.${name}`,
        message: "Compose interpolation is not allowed in volumes, ports, or environment values.",
      });
    }
    if (hasForbiddenMount(service.volumes)) {
      violations.push({
        path: `services.${name}.volumes`,
        message: "Bind mounts, Docker sockets, and host paths are not allowed. Use named volumes.",
      });
    }
    for (const port of extractPorts(service.ports)) {
      ports.push(port);
      if (RESERVED_PORTS.has(port)) {
        violations.push({
          path: `services.${name}.ports`,
          message: `Host port ${port} is reserved for platform listeners.`,
        });
      }
    }
    if (typeof service.network_mode === "string" && /host|service:|container:/.test(service.network_mode)) {
      violations.push({
        path: `services.${name}.network_mode`,
        message: "Host or shared network namespaces are not allowed.",
      });
    }
  }
  if (violations.length) return { ok: false, violations };
  return { ok: true, services: names, images, ports };
}

function asRecord(value: unknown, path: string, violations: ComposeViolation[]) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    violations.push({ path, message: "Expected a mapping." });
    return null;
  }
  return value as Record<string, unknown>;
}

export function imageRegistry(image: string) {
  const name = image.split("@")[0] ?? image;
  const first = name.split("/")[0] ?? "";
  if (first === "localhost" || first.includes(".") || first.includes(":")) return first;
  return "docker.io";
}

function isAllowedImage(image: string, registries: string[]) {
  if (image.includes("..") || image.startsWith("/")) return false;
  const [name, digest] = image.split("@");
  const tag = name.includes(":") ? name.slice(name.lastIndexOf(":") + 1) : "latest";
  if (tag === "latest" && !digest) return false;
  const registry = imageRegistry(name);
  return registries.includes(registry);
}

function hasInterpolation(value: unknown): boolean {
  if (typeof value === "string") return value.includes("$");
  if (Array.isArray(value)) return value.some((item) => hasInterpolation(item));
  if (value && typeof value === "object") return Object.values(value).some((item) => hasInterpolation(item));
  return false;
}

function hasForbiddenMount(volumes: unknown) {
  if (!volumes) return false;
  const items = Array.isArray(volumes) ? volumes : [];
  return items.some((item) => {
    if (typeof item === "string") {
      return (
        item.includes("$") ||
        item.includes("docker.sock") ||
        item.startsWith("/") ||
        item.startsWith("./") ||
        item.startsWith("../")
      );
    }
    if (item && typeof item === "object") {
      const mount = item as { type?: string; source?: string; target?: string };
      if (mount.type === "bind") return true;
      if (
        typeof mount.source === "string" &&
        (mount.source.includes("$") || mount.source.startsWith("/") || mount.source.includes("docker.sock"))
      ) {
        return true;
      }
    }
    return false;
  });
}

export function extractPublishedPort(item: string): number | undefined {
  const cleaned = item.trim().replace(/\/(?:tcp|udp)$/i, "");
  const bracket = /^\[([^\]]+)\]:(\d+):(\d+)$/.exec(cleaned);
  if (bracket) {
    const hostPort = Number(bracket[2]);
    return Number.isFinite(hostPort) ? hostPort : undefined;
  }
  const parts = cleaned.split(":");
  if (parts.length === 3) {
    const hostPort = Number(parts[1]);
    return Number.isFinite(hostPort) ? hostPort : undefined;
  }
  if (parts.length === 2) {
    const hostPort = Number(parts[0]);
    return Number.isFinite(hostPort) ? hostPort : undefined;
  }
  if (parts.length === 1) {
    const port = Number(parts[0]);
    return Number.isFinite(port) ? port : undefined;
  }
  return undefined;
}

function extractPorts(ports: unknown): number[] {
  if (!Array.isArray(ports)) return [];
  return ports.flatMap((item) => {
    if (typeof item === "number") return [item];
    if (typeof item === "string") {
      const published = extractPublishedPort(item);
      return published !== undefined ? [published] : [];
    }
    if (item && typeof item === "object" && "published" in item) {
      const published = Number((item as { published: string | number }).published);
      return Number.isFinite(published) ? [published] : [];
    }
    return [];
  });
}
