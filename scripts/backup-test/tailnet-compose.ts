// FD-30 deployment invariants of infra/platform/docker-compose.yml (docs/design/front-door.md §3.18.3),
// shared by the unit test (tailnet-compose.test.ts) and the runtime report of
// scripts/test-backups-tailnet.ts:
//   - backup-ts is its own node: the pinned tailscale image the edge uses, userspace networking with no
//     tun device and no capabilities, --shields-up, SOCKS5 on :1055, no published ports;
//   - its LocalAPI socket volume is mounted read-write in backup-ts and read-only in backup-worker
//     only: api, domain-worker and every other service cannot read it;
//   - backup-tailnet is internal and joined by backup-ts and backup-worker only; backup-ts's egress
//     network has no other member, and edge-ts is on neither;
//   - no service sets a process-wide proxy (HTTP_PROXY, ALL_PROXY, NO_PROXY, ...), so S3, API and
//     executor traffic can never follow the tailnet proxy; the backup worker only knows the proxy URL.
import { join } from "node:path";

export const composePath = join(import.meta.dir, "..", "..", "infra", "platform", "docker-compose.yml");

type Service = {
  image?: string;
  environment?: Record<string, string> | string[];
  volumes?: Array<string | { source?: string; target?: string; read_only?: boolean }>;
  networks?: string[] | Record<string, { aliases?: string[] } | null>;
  ports?: unknown[];
  devices?: unknown[];
  cap_add?: string[];
  cap_drop?: string[];
  user?: string;
};
type Compose = {
  services: Record<string, Service>;
  networks: Record<string, { internal?: boolean } | null>;
  volumes: Record<string, unknown>;
};

const PROXY_VARIABLES = new Set(["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY"]);

export async function loadCompose(): Promise<Compose> {
  return Bun.YAML.parse(await Bun.file(composePath).text()) as Compose;
}

function environment(service: Service): Record<string, string> {
  if (Array.isArray(service.environment)) {
    return Object.fromEntries(
      service.environment.map((entry) => [entry.split("=")[0]!, entry.split("=").slice(1).join("=")]),
    );
  }
  return service.environment ?? {};
}

function networks(service: Service) {
  return Array.isArray(service.networks) ? service.networks : Object.keys(service.networks ?? {});
}

function mounts(service: Service) {
  return (service.volumes ?? []).map((volume) => {
    if (typeof volume !== "string")
      return {
        source: volume.source ?? "",
        target: volume.target ?? "",
        readOnly: Boolean(volume.read_only),
      };
    const [source = "", target = "", mode = ""] = volume.split(":");
    return { source, target, readOnly: mode.split(",").includes("ro") };
  });
}

export type Claim = { claim: string; ok: boolean; observed: string };

/** Every FD-30 deployment invariant as a claim with what was observed. */
export function tailnetComposeClaims(compose: Compose): Claim[] {
  const claims: Claim[] = [];
  const add = (claim: string, ok: boolean, observed: string) => claims.push({ claim, ok, observed });
  const backupTs = compose.services["backup-ts"];
  const edgeTs = compose.services["edge-ts"];
  const worker = compose.services["backup-worker"];
  add("backup-ts exists", Boolean(backupTs), backupTs ? "present" : "missing");
  if (!backupTs || !worker || !edgeTs) return claims;
  const env = environment(backupTs);
  add(
    "backup-ts uses the edge's pinned tailscale image (v1.86.2, by digest)",
    backupTs.image === edgeTs.image && /tailscale:v1\.86\.2@sha256:[0-9a-f]{64}$/.test(backupTs.image ?? ""),
    backupTs.image ?? "",
  );
  add(
    "backup-ts runs userspace networking with SOCKS5 on :1055 and --shields-up",
    env.TS_USERSPACE === "true" &&
      env.TS_SOCKS5_SERVER === ":1055" &&
      /--shields-up/.test(env.TS_EXTRA_ARGS ?? ""),
    `TS_USERSPACE=${env.TS_USERSPACE} TS_SOCKS5_SERVER=${env.TS_SOCKS5_SERVER} TS_EXTRA_ARGS=${env.TS_EXTRA_ARGS}`,
  );
  add(
    "backup-ts has no tun device, no added capabilities and no published ports",
    !backupTs.devices?.length &&
      !backupTs.cap_add?.length &&
      (backupTs.cap_drop ?? []).includes("ALL") &&
      !backupTs.ports?.length,
    `devices=${JSON.stringify(backupTs.devices ?? [])} cap_add=${JSON.stringify(backupTs.cap_add ?? [])} ports=${JSON.stringify(backupTs.ports ?? [])}`,
  );
  add(
    "backup-ts authenticates with its own key, never the edge's",
    /TS_BACKUP_AUTHKEY/.test(env.TS_AUTHKEY ?? "") && !/TS_EDGE_AUTHKEY/.test(env.TS_AUTHKEY ?? ""),
    env.TS_AUTHKEY ?? "",
  );
  const socketUsers = Object.entries(compose.services).flatMap(([name, service]) =>
    mounts(service)
      .filter((mount) => mount.source === "ark_backup_ts_socket")
      .map((mount) => ({ name, ...mount })),
  );
  add(
    "ark_backup_ts_socket is mounted only in backup-ts (rw) and backup-worker (ro)",
    socketUsers.length === 2 &&
      socketUsers.some((item) => item.name === "backup-ts" && !item.readOnly) &&
      socketUsers.some((item) => item.name === "backup-worker" && item.readOnly),
    socketUsers.map((item) => `${item.name}:${item.readOnly ? "ro" : "rw"}`).join(", "),
  );
  for (const name of ["api", "domain-worker"]) {
    const service = compose.services[name];
    add(
      `${name} cannot read backup-ts's LocalAPI (no socket mount)`,
      Boolean(service) && !mounts(service!).some((mount) => mount.source === "ark_backup_ts_socket"),
      service
        ? mounts(service)
            .map((mount) => mount.source)
            .join(", ") || "no volumes"
        : "missing",
    );
  }
  const members = (network: string) =>
    Object.entries(compose.services)
      .filter(([, service]) => networks(service).includes(network))
      .map(([name]) => name)
      .toSorted();
  add(
    "backup-tailnet is internal and joined only by backup-ts and backup-worker",
    compose.networks["backup-tailnet"]?.internal === true &&
      JSON.stringify(members("backup-tailnet")) === JSON.stringify(["backup-ts", "backup-worker"]),
    `internal=${compose.networks["backup-tailnet"]?.internal} members=${members("backup-tailnet").join(",")}`,
  );
  add(
    "backup-ts's egress network has no other member; backup-ts joins nothing else",
    JSON.stringify(members("backup-ts-egress")) === JSON.stringify(["backup-ts"]) &&
      JSON.stringify(networks(backupTs).toSorted()) ===
        JSON.stringify(["backup-tailnet", "backup-ts-egress"]),
    `backup-ts-egress=${members("backup-ts-egress").join(",")}; backup-ts networks=${networks(backupTs).join(",")}`,
  );
  const alias = !Array.isArray(backupTs.networks)
    ? backupTs.networks?.["backup-tailnet"]?.aliases
    : undefined;
  add(
    "backup-ts answers as backup-ts on backup-tailnet",
    Boolean(alias?.includes("backup-ts")),
    JSON.stringify(alias ?? []),
  );
  add(
    "edge-ts shares no network with backup-ts",
    !networks(edgeTs).some((network) => networks(backupTs).includes(network)),
    networks(edgeTs).join(","),
  );
  const workerEnv = environment(worker);
  add(
    "backup-worker knows backup-ts's socket and SOCKS5 URL, and joins backup-tailnet",
    workerEnv.ARK_BACKUP_SOCKS5_PROXY === "socks5://backup-ts:1055" &&
      (workerEnv.ARK_BACKUP_TS_SOCKET ?? "").startsWith(
        mounts(worker).find((mount) => mount.source === "ark_backup_ts_socket")?.target ?? "\u0000",
      ) &&
      networks(worker).includes("backup-tailnet"),
    `ARK_BACKUP_SOCKS5_PROXY=${workerEnv.ARK_BACKUP_SOCKS5_PROXY} ARK_BACKUP_TS_SOCKET=${workerEnv.ARK_BACKUP_TS_SOCKET}`,
  );
  const proxied = Object.entries(compose.services).flatMap(([name, service]) =>
    Object.keys(environment(service))
      .filter((key) => PROXY_VARIABLES.has(key.toUpperCase()))
      .map((key) => `${name}:${key}`),
  );
  add(
    "no service sets a process-wide proxy variable (S3, API and executor calls are never proxied)",
    proxied.length === 0,
    proxied.join(", ") || "none",
  );
  return claims;
}
