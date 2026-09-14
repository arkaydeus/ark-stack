import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

const MAX_BYTES = 64 * 1024;
const MAX_SERVICES = 20;
const RESERVED_PORTS = new Set([25, 80, 443, 465, 587, 993, 5432, 5433]);
const DEFAULT_REGISTRIES = ["docker.io", "ghcr.io", "public.ecr.aws", "quay.io"];
const TOP_LEVEL_KEYS = new Set(["services", "volumes", "networks"]);
const SERVICE_KEYS = new Set([
  "image",
  "command",
  "entrypoint",
  "environment",
  "ports",
  "expose",
  "volumes",
  "networks",
  "depends_on",
  "restart",
  "healthcheck",
  "labels",
  "user",
  "working_dir",
  "stop_grace_period",
]);
const RESERVED_RESOURCE_PREFIXES = ["ark_", "ark-", "platform", "control", "docker"];

const FORBIDDEN_SERVICE_KEYS = new Set([
  "privileged",
  "devices",
  "device_cgroup_rules",
  "cap_add",
  "cap_drop",
  "security_opt",
  "read_only",
  "tmpfs",
  "init",
  "pids_limit",
  "mem_limit",
  "cpus",
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
  "volumes_from",
  "extra_hosts",
  "logging",
  "sysctls",
  "ulimits",
  "profiles",
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
  if (source.includes("$")) {
    violations.push({ path: "$", message: "Compose interpolation is not allowed." });
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
  for (const key of Object.keys(doc)) {
    if (!TOP_LEVEL_KEYS.has(key)) {
      violations.push({ path: key, message: `Unsupported top-level field "${key}" is rejected.` });
    }
  }
  if ("include" in doc) violations.push({ path: "include", message: "Compose includes are not allowed." });
  if (doc.secrets)
    violations.push({
      path: "secrets",
      message: "Use platform secret references, not Compose secrets blocks.",
    });
  const services = asRecord(doc.services, "services", violations);
  if (!services) return { ok: false, violations };
  const volumes = optionalRecord(doc.volumes, "volumes", violations);
  const networks = optionalRecord(doc.networks, "networks", violations);
  validateTopLevelResources("volumes", volumes, violations);
  validateTopLevelResources("networks", networks, violations);
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
      if (FORBIDDEN_SERVICE_KEYS.has(key) || !SERVICE_KEYS.has(key)) {
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
    if (hasInterpolation(service)) {
      violations.push({
        path: `services.${name}`,
        message: "Compose interpolation is not allowed in service fields.",
      });
    }
    if (hasForbiddenMount(service.volumes)) {
      violations.push({
        path: `services.${name}.volumes`,
        message: "Bind mounts, Docker sockets, and host paths are not allowed. Use named volumes.",
      });
    }
    validateVolumeReferences(name, service.volumes, volumes, violations);
    validateNetworkReferences(name, service.networks, networks, violations);
    for (const port of extractPorts(service.ports)) {
      if (!Number.isFinite(port)) {
        violations.push({
          path: `services.${name}.ports`,
          message: "Port ranges and ambiguous publish syntax are not allowed.",
        });
        continue;
      }
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

/**
 * Produces the only Compose document that may be executed by the agent.  The
 * caller's source is validated first and mandatory sandboxing is then injected
 * into the effective model, so approval and execution cannot diverge.
 */
export function canonicalizeComposeSource(source: string, options: { allowedRegistries?: string[] } = {}) {
  const policy = validateComposeSource(source, options);
  if (!policy.ok)
    throw new Error(policy.violations.map((item) => `${item.path}: ${item.message}`).join("\n"));
  const doc = parseYaml(source, { merge: false, uniqueKeys: true }) as Record<string, unknown>;
  const services = doc.services as Record<string, Record<string, unknown>>;
  for (const service of Object.values(services)) {
    service.read_only = true;
    service.init = true;
    service.pids_limit = 256;
    service.mem_limit = "512m";
    service.cpus = 1;
    service.tmpfs = ["/tmp:rw,noexec,nosuid,nodev,size=64m"];
    service.cap_drop = ["ALL"];
    service.security_opt = ["no-new-privileges:true"];
  }
  return stringifyYaml(doc, { sortMapEntries: true, lineWidth: 0 });
}

function asRecord(value: unknown, path: string, violations: ComposeViolation[]) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    violations.push({ path, message: "Expected a mapping." });
    return null;
  }
  return value as Record<string, unknown>;
}

function optionalRecord(value: unknown, path: string, violations: ComposeViolation[]) {
  if (value === undefined) return {} as Record<string, unknown>;
  return asRecord(value, path, violations) ?? {};
}

function isReservedResourceName(name: string) {
  const lower = name.toLowerCase();
  return RESERVED_RESOURCE_PREFIXES.some((prefix) => lower.startsWith(prefix));
}

function validateTopLevelResources(
  kind: "volumes" | "networks",
  resources: Record<string, unknown>,
  violations: ComposeViolation[],
) {
  for (const [name, raw] of Object.entries(resources)) {
    const path = `${kind}.${name}`;
    if (!/^[a-z0-9][a-z0-9_-]{0,62}$/i.test(name) || isReservedResourceName(name)) {
      violations.push({ path, message: `Resource name "${name}" is reserved or invalid.` });
    }
    if (raw === null) continue;
    const value = asRecord(raw, path, violations);
    if (!value) continue;
    for (const key of Object.keys(value)) {
      violations.push({
        path: `${path}.${key}`,
        message: `${kind === "volumes" ? "Volume" : "Network"} options, external resources, drivers, and caller-chosen global names are not allowed.`,
      });
    }
  }
}

function mountSource(item: unknown) {
  if (typeof item === "string") {
    const match = /^(?:[^:]+):/.exec(item);
    return match ? match[0].slice(0, -1) : null;
  }
  if (item && typeof item === "object") {
    const mount = item as { type?: string; source?: string };
    return mount.type === "volume" || (!mount.type && mount.source) ? (mount.source ?? null) : null;
  }
  return null;
}

function validateVolumeReferences(
  service: string,
  value: unknown,
  volumes: Record<string, unknown>,
  violations: ComposeViolation[],
) {
  if (value === undefined) return;
  if (!Array.isArray(value)) {
    violations.push({ path: `services.${service}.volumes`, message: "Volumes must be a list." });
    return;
  }
  for (const item of value) {
    const source = mountSource(item);
    if (source && !(source in volumes)) {
      violations.push({
        path: `services.${service}.volumes`,
        message: `Named volume "${source}" must be declared and workload-owned.`,
      });
    }
  }
}

function validateNetworkReferences(
  service: string,
  value: unknown,
  networks: Record<string, unknown>,
  violations: ComposeViolation[],
) {
  if (value === undefined) return;
  const names = Array.isArray(value)
    ? value.map(String)
    : value && typeof value === "object"
      ? Object.keys(value)
      : [];
  if (!Array.isArray(value) && (!value || typeof value !== "object")) {
    violations.push({ path: `services.${service}.networks`, message: "Networks must be a list or mapping." });
    return;
  }
  for (const name of names) {
    if (!(name in networks)) {
      violations.push({
        path: `services.${service}.networks`,
        message: `Network "${name}" must be declared and workload-owned.`,
      });
    }
  }
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
      if (/\d+-\d+/.test(item)) return [Number.NaN];
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
