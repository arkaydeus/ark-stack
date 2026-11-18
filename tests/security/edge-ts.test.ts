// The shipped shape of the edge Tailscale node and the edge namespace move (FD-05,
// docs/design/front-door.md §3.6 and §3.16). `mise run test:edge` runs these services; this checks the
// manifest itself, without Docker.
import { describe, expect, test } from "bun:test";
import { join } from "node:path";

const root = join(import.meta.dir, "..", "..");

type Service = {
  image?: string;
  hostname?: string;
  profiles?: string[];
  environment?: Record<string, string>;
  devices?: string[];
  cap_add?: string[];
  cap_drop?: string[];
  security_opt?: string[];
  ports?: string[];
  volumes?: string[];
  network_mode?: string;
  networks?: string[] | Record<string, { aliases?: string[] } | null>;
  depends_on?: string[] | Record<string, unknown>;
  user?: string;
};

const compose = Bun.YAML.parse(await Bun.file(join(root, "infra/platform/docker-compose.yml")).text()) as {
  services: Record<string, Service>;
  networks: Record<string, { internal?: boolean } | null>;
  volumes: Record<string, unknown>;
};
const edgeTs = compose.services["edge-ts"]!;
const edge = compose.services.edge!;

function networkNames(service: Service) {
  return Array.isArray(service.networks) ? service.networks : Object.keys(service.networks ?? {});
}

function aliases(service: Service) {
  if (Array.isArray(service.networks) || !service.networks) return [];
  return Object.values(service.networks).flatMap((network) => network?.aliases ?? []);
}

describe("edge-ts", () => {
  test("uses the admin node's pinned official Tailscale image", () => {
    expect(edgeTs.image).toMatch(/^tailscale\/tailscale:v\d+\.\d+\.\d+@sha256:[a-f0-9]{64}$/);
    expect(edgeTs.image).toBe(compose.services.tailscale!.image!);
  });

  test("runs in kernel mode with shields up, Docker DNS and its own WireGuard port", () => {
    expect(edgeTs.environment).toEqual({
      TS_USERSPACE: "false",
      TS_AUTHKEY: "${TS_EDGE_AUTHKEY:-}",
      TS_STATE_DIR: "/var/lib/tailscale",
      TS_SOCKET: "/var/run/tailscale/tailscaled.sock",
      TS_ACCEPT_DNS: "false",
      TS_EXTRA_ARGS: "--shields-up",
      TS_TAILSCALED_EXTRA_ARGS: "--port=41642",
    });
    expect(edgeTs.hostname).toBe("ark-edge");
    expect(edgeTs.profiles).toBeUndefined();
  });

  test("has only the kernel-mode capabilities and the TUN device", () => {
    expect(edgeTs.cap_drop).toEqual(["ALL"]);
    expect(edgeTs.cap_add?.toSorted()).toEqual(["NET_ADMIN", "NET_RAW"]);
    expect(edgeTs.devices).toEqual(["/dev/net/tun:/dev/net/tun"]);
    expect(edgeTs.security_opt).toContain("no-new-privileges:true");
    // The LocalAPI socket volume is shared read-only with domain-worker only (FD-06).
    expect(edgeTs.volumes).toEqual([
      "ark_edge_ts_state:/var/lib/tailscale",
      "ark_edge_ts_socket:/var/run/tailscale",
    ]);
    expect(compose.volumes).toHaveProperty("ark_edge_ts_state");
    expect(compose.volumes).toHaveProperty("ark_edge_ts_socket");
  });

  test("publishes the edge's ports and carries the edge-admin alias", () => {
    expect(edgeTs.ports).toEqual([
      "80:80",
      "443:443",
      // The PostgreSQL router (FD-26): edge-l4's fe_pg5432.
      "5432:5432",
      // Shared SNI ports (FD-14): published only when the installer enabled them; otherwise only on
      // an ephemeral loopback port where nothing listens.
      "${ARK_EDGE_SNI_PORT_8883:-127.0.0.1::8883}",
      "${ARK_EDGE_SNI_PORT_5671:-127.0.0.1::5671}",
      "${ARK_EDGE_SNI_PORT_636:-127.0.0.1::636}",
      "${ARK_EDGE_SNI_PORT_6380:-127.0.0.1::6380}",
      // Dedicated raw TCP route ports (FD-14).
      "20000-20049:20000-20049",
      "41642:41642/udp",
    ]);
    // pgbouncer-ingress (FD-26): HAProxy reaches PgBouncer only; never database-management.
    expect(edgeTs.networks).toEqual({
      admin: {},
      "edge-control": { aliases: ["edge-admin"] },
      "pgbouncer-ingress": {},
    });
    expect(compose.networks["pgbouncer-ingress"]?.internal).toBe(true);
    expect(compose.networks["edge-control"]?.internal).toBe(true);
  });
});

describe("edge in the edge-ts namespace", () => {
  test("joins edge-ts and owns no ports, networks or capabilities", () => {
    expect(edge.network_mode).toBe("service:edge-ts");
    expect(edge.ports).toBeUndefined();
    expect(edge.networks).toBeUndefined();
    expect(edge.cap_drop).toEqual(["ALL"]);
    expect(edge.cap_add).toBeUndefined();
    expect(edge.user).toBe("1000:1000");
    expect(edge.depends_on).toEqual(["edge-ts", "api", "edge-watchdog"]);
  });

  test("only edge-ts publishes 80/443 and only it answers to edge-admin", () => {
    for (const [name, service] of Object.entries(compose.services)) {
      if (name === "edge-ts") continue;
      expect(aliases(service)).not.toContain("edge-admin");
      for (const port of service.ports ?? []) expect(port).not.toMatch(/(^|:)(80|443|41642)(\/\w+)?$/);
    }
  });

  test("api is not on edge-control, so it cannot reach the Caddy admin API", () => {
    const members = Object.entries(compose.services)
      .filter(([, service]) => networkNames(service).includes("edge-control"))
      .map(([name]) => name)
      .toSorted();
    // edge-watchdog withdraws tailnet routes through the admin API (FD-06); it holds no database
    // credential, root key or socket.
    expect(members).toEqual(["domain-worker", "edge-ts", "edge-watchdog"]);
  });
});

describe("admin tailnet node", () => {
  test("tailscale and tailnet-gateway stay userspace, capability-free and opt-in", () => {
    const tailscale = compose.services.tailscale!;
    expect(tailscale.profiles).toEqual(["tailnet"]);
    expect(tailscale.environment?.TS_USERSPACE).toBe("true");
    expect(tailscale.environment?.TS_AUTHKEY).toBe("${TS_AUTHKEY:-}");
    expect(tailscale.cap_drop).toEqual(["ALL"]);
    expect(tailscale.cap_add).toBeUndefined();
    expect(tailscale.devices).toBeUndefined();
    expect(tailscale.networks).toEqual(["admin"]);
    const gateway = compose.services["tailnet-gateway"]!;
    expect(gateway.profiles).toEqual(["tailnet"]);
    expect(gateway.network_mode).toBe("service:tailscale");
  });
});
