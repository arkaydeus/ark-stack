// Compose policy for the edge node's tailscaled socket (front door §3.6, §3.16, FD-06): only edge-ts
// owns it, only the domain worker mounts it (read-only), and the API, the watchdog and every other
// service have no path to it.
import { describe, expect, test } from "bun:test";
import { join } from "node:path";

type Service = {
  volumes?: Array<string | { source?: string; target?: string }>;
  volumes_from?: string[];
  network_mode?: string;
  networks?: string[] | Record<string, unknown>;
  environment?: Record<string, string>;
  entrypoint?: string[];
  read_only?: boolean;
  cap_drop?: string[];
  user?: string;
};

const compose = Bun.YAML.parse(
  await Bun.file(join(import.meta.dir, "../../infra/platform/docker-compose.yml")).text(),
) as { services: Record<string, Service>; volumes: Record<string, unknown> };
const services = compose.services;

function mounts(service: Service) {
  return (service.volumes ?? []).map((volume) =>
    typeof volume === "string" ? volume : `${volume.source ?? ""}:${volume.target ?? ""}`,
  );
}

function networks(service: Service) {
  return Array.isArray(service.networks) ? service.networks : Object.keys(service.networks ?? {});
}

const socketMount = (mount: string) =>
  mount.startsWith("ark_edge_ts_socket:") || mount.includes("/var/run/tailscale");

describe("tailscaled socket policy", () => {
  test("only edge-ts (read-write) and domain-worker (read-only) mount the edge node's socket", () => {
    const holders = Object.entries(services)
      .filter(([, service]) => mounts(service).some(socketMount))
      .map(([name, service]) => [name, mounts(service).filter(socketMount)]);
    expect(holders).toEqual([
      ["domain-worker", ["ark_edge_ts_socket:/var/run/tailscale:ro"]],
      ["edge-ts", ["ark_edge_ts_socket:/var/run/tailscale"]],
    ]);
    expect(services["edge-ts"]?.environment?.TS_SOCKET).toBe("/var/run/tailscale/tailscaled.sock");
    expect(services["domain-worker"]?.environment?.ARK_EDGE_TS_SOCKET).toBe(
      "/var/run/tailscale/tailscaled.sock",
    );
    expect("ark_edge_ts_socket" in compose.volumes).toBe(true);
  });

  test("the API container has no access to the tailscaled socket", () => {
    const api = services.api!;
    expect(mounts(api).filter(socketMount)).toEqual([]);
    expect(mounts(api).some((mount) => mount.includes("tailscale"))).toBe(false);
    expect(api.volumes_from).toBeUndefined();
    expect(api.network_mode).toBeUndefined();
    expect(Object.keys(api.environment ?? {}).filter((key) => /TS_SOCKET|TAILSCALE/.test(key))).toEqual([]);
    // Nothing shares a namespace with the API, and the API cannot reach edge-ts's admin side.
    expect(networks(api)).not.toContain("edge-control");
    expect(Object.values(services).some((service) => service.network_mode === "service:api")).toBe(false);
  });

  test("no service borrows a socket holder's mounts", () => {
    for (const [name, service] of Object.entries(services)) {
      for (const source of service.volumes_from ?? []) {
        expect([name, source]).not.toEqual([name, "domain-worker"]);
        expect([name, source]).not.toEqual([name, "edge-ts"]);
      }
    }
  });

  test("the edge watchdog holds no socket, database credential or root key", () => {
    const watchdog = services["edge-watchdog"]!;
    expect(mounts(watchdog)).toEqual(["../../tmp/edge:/var/lib/ark/edge:ro"]);
    expect(Object.keys(watchdog.environment ?? {}).toSorted()).toEqual(
      [
        "ARK_API_URL",
        "ARK_EDGE_ADMIN_URL",
        "ARK_EDGE_DIR",
        "ARK_EDGE_WATCHDOG_PORT",
        "ARK_EDGE_WATCHDOG_TOKEN",
      ].toSorted(),
    );
    expect(networks(watchdog).toSorted()).toEqual(["control", "edge-control"]);
    expect(watchdog.read_only).toBe(true);
    expect(watchdog.cap_drop).toEqual(["ALL"]);
  });

  test("Caddy starts through the launch guard from the rendered directory", () => {
    const edge = services.edge!;
    expect(edge.entrypoint).toEqual(["/bin/sh", "/usr/local/bin/ark-edge-launch-guard"]);
    expect(mounts(edge)).toContain("../../tmp/edge:/etc/caddy/ark:ro");
    expect(mounts(edge)).toContain("./edge-launch-guard.sh:/usr/local/bin/ark-edge-launch-guard:ro");
    expect(mounts(edge).filter(socketMount)).toEqual([]);
    expect(edge.environment?.ARK_EDGE_WATCHDOG_URL).toBe("http://edge-watchdog:2021");
  });
});
