// Compose policy for the HAProxy SNI router (front door §3.8.6, §3.16, FD-25): edge-l4 owns 443 in the
// edge-ts namespace with no capabilities, its sockets are shared through group 4400 only with the
// domain worker and the edge watchdog, and the validator has no network.
import { describe, expect, test } from "bun:test";
import { join } from "node:path";

type Service = {
  image?: string;
  build?: { target?: string };
  volumes?: string[];
  network_mode?: string;
  networks?: string[] | Record<string, unknown>;
  environment?: Record<string, string>;
  entrypoint?: string[];
  command?: string[];
  read_only?: boolean;
  cap_drop?: string[];
  cap_add?: string[];
  group_add?: string[];
  security_opt?: string[];
  user?: string;
  tmpfs?: string[];
  ports?: string[];
};

const root = join(import.meta.dir, "../..");
const source = await Bun.file(join(root, "infra/platform/docker-compose.yml")).text();
const compose = Bun.YAML.parse(source) as {
  services: Record<string, Service>;
  volumes: Record<string, { driver_opts?: Record<string, string> } | null>;
};
const services = compose.services;
const dockerfile = await Bun.file(join(root, "Dockerfile")).text();

const haproxyImage =
  "haproxy:3.2.26-alpine@sha256:1c3568e520453cc8ba98c39501febcf450429c80e6cc27ecad779961d76e597c";

describe("edge-l4 compose policy", () => {
  test("edge-l4 is the digest-pinned HAProxy 3.2.26 in the edge-ts namespace, unprivileged", () => {
    const l4 = services["edge-l4"]!;
    expect(l4.image).toBe(haproxyImage);
    expect(l4.network_mode).toBe("service:edge-ts");
    expect(l4.cap_drop).toEqual(["ALL"]);
    expect(l4.cap_add).toBeUndefined();
    expect(l4.read_only).toBe(true);
    expect(l4.security_opt).toContain("no-new-privileges:true");
    expect(l4.user).toBeUndefined(); // the image's own numeric uid 99
    expect(l4.group_add).toEqual(["4400"]);
    expect(l4.entrypoint).toEqual(["/bin/sh", "/usr/local/bin/ark-edge-l4-launch-guard"]);
    expect(l4.volumes).toEqual([
      "../../tmp/edge-l4:/usr/local/etc/haproxy:ro",
      "./edge-l4-launch-guard.sh:/usr/local/bin/ark-edge-l4-launch-guard:ro",
      "ark_haproxy_run:/var/run/haproxy",
    ]);
    expect(services["edge-ts"]!.ports).toContain("443:443");
  });

  test("the validator uses the same HAProxy digest, has no network and mounts configuration read-only", () => {
    const validator = services["haproxy-validator"]!;
    expect(validator.build?.target).toBe("haproxy-validator");
    expect(validator.network_mode).toBe("none");
    expect(validator.cap_drop).toEqual(["ALL"]);
    expect(validator.read_only).toBe(true);
    expect(validator.group_add).toEqual(["4400"]);
    expect(validator.volumes).toEqual([
      "../../tmp/edge-l4:/usr/local/etc/haproxy:ro",
      "ark_haproxy_validator_run:/var/run/haproxy-validator",
    ]);
    expect(dockerfile).toContain(`FROM ${haproxyImage} AS haproxy-validator`);
    expect(dockerfile).toMatch(/AS haproxy-validator[\s\S]*USER haproxy\n/);
    // Services that build without a target use the last stage; it must stay a Bun worker image.
    expect(dockerfile.trim().split("\n").at(-1)).toBe("FROM runtime AS mail-worker");
  });

  test("socket volumes are 99:4400 setgid tmpfs, shared with exactly the services that need them", () => {
    for (const name of ["ark_haproxy_run", "ark_haproxy_validator_run"]) {
      expect(compose.volumes[name]?.driver_opts).toEqual({
        type: "tmpfs",
        device: "tmpfs",
        o: "uid=99,gid=4400,mode=2770,size=1m",
      });
    }
    const holders = (volume: string) =>
      Object.entries(services)
        .filter(([, service]) => (service.volumes ?? []).some((mount) => mount.startsWith(`${volume}:`)))
        .map(([name]) => name)
        .toSorted();
    expect(holders("ark_haproxy_run")).toEqual(["domain-worker", "edge-l4", "edge-watchdog"]);
    expect(holders("ark_haproxy_validator_run")).toEqual(["domain-worker", "haproxy-validator"]);
    // Only those services join the shared group.
    const grouped = Object.entries(services)
      .filter(([, service]) => service.group_add?.includes("4400"))
      .map(([name]) => name)
      .toSorted();
    expect(grouped).toEqual(["domain-worker", "edge-l4", "edge-watchdog", "haproxy-validator"]);
  });

  test("only the domain worker writes generations; it has no Docker access", () => {
    const writers = Object.entries(services)
      .filter(([, service]) => (service.volumes ?? []).some((mount) => /tmp\/edge-l4:[^:]+$/.test(mount)))
      .map(([name]) => name);
    expect(writers).toEqual(["domain-worker"]);
    const worker = services["domain-worker"]!;
    expect((worker.volumes ?? []).some((mount) => mount.includes("docker.sock"))).toBe(false);
    expect(worker.environment).toMatchObject({
      ARK_EDGE_L4_DIR: "/usr/local/etc/haproxy",
      ARK_HAPROXY_VALIDATOR_SOCKET: "/var/run/haproxy-validator/validate.sock",
      ARK_HAPROXY_MASTER_SOCKET: "/var/run/haproxy/master.sock",
      ARK_HAPROXY_ADMIN_SOCKET: "/var/run/haproxy/admin.sock",
    });
    expect(source).toMatch(/domain-worker:[\s\S]*?cap_drop: \[ALL\]|x-app: &app[\s\S]*cap_drop: \[ALL\]/);
  });
});
