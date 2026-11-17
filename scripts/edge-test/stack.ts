// Starts the production `edge-ts` and `edge` services from infra/platform/docker-compose.yml in a
// disposable Compose project. Only what cannot run on a test machine is overridden: host paths
// (fixture directories instead of tmp/), published ports (ephemeral loopback ports instead of the
// host's 80/443/41642), and whatever environment the caller passes. Everything else (image pin,
// kernel mode, capabilities, /dev/net/tun, networks, the edge-admin alias, network_mode) is the
// shipped definition.
import { join } from "node:path";

import type { EdgeTestRuntime } from "./runtime.ts";

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
  /**
   * Replaces edge-ts's entrypoint and command. containerboot exits after its 60 s boot timeout when
   * the node cannot log in, and the restart strands `edge`; long offline runs start tailscaled itself.
   */
  edgeTsCommand?: string[];
};

export type EdgeStack = {
  project: string;
  edgeTs: string;
  edge: string;
  networks: { admin: string; edgeControl: string };
  composeArgs: string[];
  compose: (...args: string[]) => Promise<string>;
  /** Host port currently mapped to an edge-ts port (it changes when edge-ts restarts). */
  hostPort: (port: number, protocol?: "tcp" | "udp") => Promise<number>;
};

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
  const external = Object.entries(document.networks ?? {})
    .filter(([, network]) => network?.external)
    .map(([name]) => name);
  const environment = Object.entries(options.edgeTsEnvironment ?? {});
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
    // Compose merges volumes by target, so these replace the tmp/ bind mounts.
    "    volumes:",
    `      - ${yamlString(`${options.acmeDir}:/var/lib/ark/acme:ro`)}`,
    `      - ${yamlString(`${options.certDir}:/var/lib/ark/certs:ro`)}`,
    `      - ${yamlString(`${options.edgeDir}:/etc/caddy/ark:ro`)}`,
    ...(external.length
      ? [
          "networks:",
          ...external.flatMap((name) => [
            `  ${name}:`,
            "    external: false",
            `    name: ${yamlString(`${project}_${name}`)}`,
          ]),
        ]
      : []),
    "",
  ].join("\n");
  const overrideFile = join(directory, `${project}.override.yml`);
  await Bun.write(overrideFile, override);

  const composeArgs = ["-p", project, "--env-file", envFile, "-f", composeFile, "-f", overrideFile];
  const compose = (...args: string[]) => runtime.docker("compose", ...composeArgs, ...args);
  runtime.composeProjects.push(project);
  const edgeTs = `${project}-edge-ts-1`;
  const edge = `${project}-edge-1`;
  runtime.containers.push(edgeTs, edge);
  // --no-deps: `edge` also depends on `api`, which the edge tests replace with a fixture upstream.
  await compose("up", "--detach", "--no-deps", "--wait", "--wait-timeout", "120", "edge-ts", "edge");

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
    networks: { admin: `${project}_admin`, edgeControl: `${project}_edge-control` },
    composeArgs,
    compose,
    hostPort,
  };
}
