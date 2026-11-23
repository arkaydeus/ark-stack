// Starts the production `edge-ts`, `edge` and `edge-l4` services (and optionally `haproxy-validator`)
// from infra/platform/docker-compose.yml in a disposable Compose project. Only what cannot run on a
// test machine is overridden: host paths (fixture directories instead of tmp/, and a project volume
// seeded by the installer's edge-l4 step instead of tmp/edge-l4), published ports (ephemeral loopback
// ports instead of the host's 80/443/41642), and whatever environment the caller passes. Test networks use explicit private /24s to avoid exhausting Docker's default pools. The optional
// host firewall runs in a separate forwarding namespace with DNAT to the real edge. Everything
// else (image pins, kernel mode, capabilities, /dev/net/tun, network isolation, the edge-admin alias,
// network_mode, the launch guards, group 4400 and the socket volumes) is the shipped definition.
import { randomBytes } from "node:crypto";
import { join } from "node:path";

import type { EdgeTestRuntime } from "./runtime.ts";
import { bunImage } from "../test-images.ts";

export const composeFile = join(import.meta.dir, "..", "..", "infra", "platform", "docker-compose.yml");

export type EdgeStackOptions = {
  runtime: EdgeTestRuntime;
  /** Compose project name; becomes the prefix of every container, network and volume. */
  project: string;
  /** Temporary directory for the override and env files. */
  directory: string;
  acmeDir: string;
  certDir: string;
  /**
   * Mounted read-only at /etc/caddy/ark, as tmp/edge is in production: the launch guard starts Caddy
   * from its Caddyfile, or from Caddyfile.closed without a valid lease (front door §3.2).
   */
  edgeDir: string;
  /** Published ports for edge-ts, replacing the production list. */
  ports: string[];
  /** Extra or replacement edge-ts environment. */
  edgeTsEnvironment?: Record<string, string>;
  /** Extra or replacement environment for the `edge` (Caddy) service, such as ARK_EDGE_GATE_TOKEN. */
  edgeEnvironment?: Record<string, string>;
  /**
   * Replaces edge-ts's entrypoint and command. containerboot exits after its 60 s boot timeout when
   * the node cannot log in, and the restart strands `edge`; long offline runs start tailscaled itself.
   */
  edgeTsCommand?: string[];
  /**
   * Test-only "uid:gid" for the `edge` (Caddy) service and the files the seed step owns. Unset, the
   * shipped 1000:1000 applies. See GateEdgeOptions.edgeUser.
   */
  edgeUser?: string;
  /** Also build and start the restricted `haproxy-validator` service from the Dockerfile target. */
  validator?: boolean;
  /** Run the shipped host reconciler in an isolated DNAT gateway for firewall tests. */
  ingress?: boolean;
};

export type EdgeStack = {
  project: string;
  edgeTs: string;
  edge: string;
  edgeL4: string;
  networks: { admin: string; edgeControl: string };
  /** Named volumes: the edge-l4 configuration and the shared socket directories. */
  volumes: { edgeL4: string; haproxyRun: string; validatorRun: string };
  composeArgs: string[];
  compose: (...args: string[]) => Promise<string>;
  /** Host port currently mapped to an edge-ts port (it changes when edge-ts restarts). */
  hostPort: (port: number, protocol?: "tcp" | "udp") => Promise<number>;
};

/** Socket mounts for the production watchdog or the fixture worker. */
export function httpRouterArgs(stack: EdgeStack, write = false) {
  return [
    "--env",
    "ARK_EDGE_L4_DIR=/usr/local/etc/haproxy",
    "--env",
    "ARK_HAPROXY_MASTER_SOCKET=/var/run/haproxy/master.sock",
    "--volume",
    `${stack.volumes.haproxyRun}:/var/run/haproxy`,
    "--volume",
    `${stack.volumes.edgeL4}:/usr/local/etc/haproxy${write ? "" : ":ro"}`,
    ...(write
      ? [
          "--env",
          "ARK_HAPROXY_VALIDATOR_SOCKET=/var/run/haproxy-validator/validate.sock",
          "--volume",
          `${stack.volumes.validatorRun}:/var/run/haproxy-validator`,
        ]
      : []),
  ];
}

function yamlString(value: string) {
  return JSON.stringify(value);
}

export async function startEdgeStack(options: EdgeStackOptions): Promise<EdgeStack> {
  const { runtime, project, directory } = options;
  const source = await Bun.file(composeFile).text();
  // Compose interpolates every service, so every required variable needs a value even though only
  // edge-ts and edge start. None of them is used by these two services.
  const required = [...new Set([...source.matchAll(/\$\{([A-Z0-9_]+):\?/g)].map((match) => match[1]))];
  const envFile = join(directory, `${project}.env`);
  await Bun.write(
    envFile,
    required
      .map((name) => `${name}=edge-test-unused`)
      .join("\n")
      .concat("\n"),
  );

  // External networks (mail, monitoring) are checked even for services that do not start; make
  // them project-local so the test needs nothing from the host.
  const document = Bun.YAML.parse(source) as { networks?: Record<string, { external?: boolean } | null> };
  const testSubnet = `10.${100 + (randomBytes(1)[0]! % 80)}`;
  const networkOffset = randomBytes(1)[0]! % 220;
  const external = new Set(
    Object.entries(document.networks ?? {})
      .filter(([, network]) => network?.external)
      .map(([name]) => name),
  );
  const environment = Object.entries(options.edgeTsEnvironment ?? {});
  const edgeEnvironment = Object.entries(options.edgeEnvironment ?? {});
  const l4Volume = `${project}_edge_l4_config`;
  const override = [
    "services:",
    "  edge-ts:",
    "    ports: !override",
    ...options.ports.map((port) => `      - ${yamlString(port)}`),
    ...(environment.length
      ? ["    environment:", ...environment.map(([key, value]) => `      ${key}: ${yamlString(value)}`)]
      : []),
    ...(options.edgeTsCommand
      ? [
          `    entrypoint: ${JSON.stringify(options.edgeTsCommand.slice(0, 1))}`,
          `    command: ${JSON.stringify(options.edgeTsCommand.slice(1))}`,
        ]
      : []),
    "  edge:",
    ...(options.edgeUser ? [`    user: ${yamlString(options.edgeUser)}`] : []),
    ...(edgeEnvironment.length
      ? ["    environment:", ...edgeEnvironment.map(([key, value]) => `      ${key}: ${yamlString(value)}`)]
      : []),
    // Compose merges volumes by target, so these replace the tmp/ bind mounts.
    "    volumes:",
    `      - ${yamlString(`${options.acmeDir}:/var/lib/ark/acme:ro`)}`,
    `      - ${yamlString(`${options.certDir}:/var/lib/ark/certs:ro`)}`,
    `      - ${yamlString(`${options.edgeDir}:/etc/caddy/ark:ro`)}`,
    // The project volume replaces the tmp/edge-l4 bind mount (merged by target).
    "  edge-l4:",
    "    volumes:",
    `      - ${yamlString("edge_l4_config:/usr/local/etc/haproxy:ro")}`,
    ...(options.validator
      ? [
          "  haproxy-validator:",
          "    volumes:",
          `      - ${yamlString("edge_l4_config:/usr/local/etc/haproxy:ro")}`,
        ]
      : []),
    ...(options.ingress
      ? [
          "  database-ingress:",
          "    network_mode: !reset null",
          "    networks: [edge-control]",
          "    sysctls:",
          '      net.ipv4.ip_forward: "1"',
          "    environment:",
          "      ARK_PGBOUNCER_DIR: /tmp/pgbouncer",
          "      ARK_DB_INGRESS_METRICS_DIR: /tmp/db-ingress",
          "      ARK_FRONT_INGRESS_DIR: /var/lib/ark/front-ingress",
          "    volumes: !override",
          "      - type: volume",
          "        source: edge_l4_config",
          "        target: /var/lib/ark/front-ingress",
          "        volume:",
          "          subpath: front-ingress",
        ]
      : []),
    "volumes:",
    "  edge_l4_config:",
    "    external: true",
    `    name: ${yamlString(l4Volume)}`,
    "networks:",
    ...Object.keys(document.networks ?? {}).flatMap((name, index) => [
      `  ${name}:`,
      ...(external.has(name) ? ["    external: false", `    name: ${yamlString(`${project}_${name}`)}`] : []),
      "    ipam:",
      "      config:",
      `        - subnet: ${testSubnet}.${networkOffset + index}.0/24`,
    ]),
    "",
  ].join("\n");
  const overrideFile = join(directory, `${project}.override.yml`);
  await Bun.write(overrideFile, override);
  // The installer's edge-l4 step on a project volume (removed with the project by its label).
  await runtime.docker("volume", "create", "--label", `com.docker.compose.project=${project}`, l4Volume);
  const seedDir = join(directory, `${project}-seed-edge-l4`);
  const built = await Bun.build({
    entrypoints: [join(import.meta.dir, "seed-edge-l4.ts")],
    target: "bun",
    outdir: seedDir,
  });
  if (!built.success) throw new Error(`Bundling seed-edge-l4.ts failed: ${built.logs.join("\n")}`);
  await runtime.docker(
    "run",
    "--rm",
    "--user",
    "0:0",
    "--volume",
    `${seedDir}:/seed:ro`,
    "--volume",
    `${l4Volume}:/usr/local/etc/haproxy`,
    "--volume",
    `${options.edgeDir}:/var/lib/ark/edge`,
    bunImage,
    "bun",
    "/seed/seed-edge-l4.js",
    "/usr/local/etc/haproxy",
    (options.edgeUser ?? "1000:1000").split(":")[0]!,
  );

  const composeArgs = ["-p", project, "--env-file", envFile, "-f", composeFile, "-f", overrideFile];
  const compose = (...args: string[]) => runtime.docker("compose", ...composeArgs, ...args);
  runtime.composeProjects.push(project);
  const edgeTs = `${project}-edge-ts-1`;
  const edge = `${project}-edge-1`;
  const edgeL4 = `${project}-edge-l4-1`;
  runtime.containers.push(edgeTs, edge, edgeL4);
  const services = ["edge-ts", "edge", "edge-l4"];
  // `edge` is the custom Caddy build (FD-23). Rebuild it like the validator, unless Compose pins a
  // published digest instead (then `up` pulls exactly that).
  const composeServices = (Bun.YAML.parse(source) as { services?: Record<string, { build?: unknown }> })
    .services;
  if (composeServices?.edge?.build) await compose("build", "edge");
  if (options.validator) {
    // Always rebuild: a stale local image with the same tag would otherwise be reused.
    await compose("build", "haproxy-validator");
    runtime.containers.push(`${project}-haproxy-validator-1`);
    services.push("haproxy-validator");
  }
  if (options.ingress) {
    await compose("build", "database-ingress");
    runtime.containers.push(`${project}-database-ingress-1`);
    services.push("database-ingress");
  }
  // --no-deps: `edge` also depends on `api` and the watchdog, which the edge tests replace or start
  // themselves. Without a tailnet route both launch guards start without asking the watchdog.
  await compose("up", "--detach", "--no-deps", "--wait", "--wait-timeout", "120", ...services);

  const hostPort = async (port: number, protocol: "tcp" | "udp" = "tcp") => {
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
      const mapped = await runtime.docker("port", edgeTs, `${port}/${protocol}`).catch(() => "");
      const match = mapped.match(/127\.0\.0\.1:(\d+)/) ?? mapped.match(/:(\d+)\s*$/m);
      if (match) return Number(match[1]);
      await Bun.sleep(200);
    }
    throw new Error(`${edgeTs} does not publish ${port}/${protocol}`);
  };
  return {
    project,
    edgeTs,
    edge,
    edgeL4,
    networks: { admin: `${project}_admin`, edgeControl: `${project}_edge-control` },
    volumes: {
      edgeL4: l4Volume,
      haproxyRun: `${project}_ark_haproxy_run`,
      validatorRun: `${project}_ark_haproxy_validator_run`,
    },
    composeArgs,
    compose,
    hostPort,
  };
}
