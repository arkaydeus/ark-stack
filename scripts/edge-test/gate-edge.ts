// A disposable edge for the login gate tests (FD-11): the shipped edge-ts, edge (Caddy behind its
// launch guard) and edge-l4 (HAProxy on 443) services, an `api:3000` on the admin network, a
// simulated tailnet peer running scripts/edge-test/upstream.ts inside 100.64.0.0/10, and the bundled
// production edge watchdog reading a lease served by this process. `edgeApply` runs the production
// `writeEdge` (render, /adapt, /load with must-revalidate) as the domain worker does.
//
// Used by scripts/test-edge-gate.ts (with the gate-api.ts stand-in as the API) and by
// scripts/test-e2e-gate.ts (with tcp-relay.ts forwarding to the real API on the host).
import { randomBytes } from "node:crypto";
import { chmod, mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";

import type { EdgeLeaseDocument, EdgePolicyRoute, WatchdogEvent } from "@ark-stack/shared";

import type { EdgeTestRuntime } from "./runtime.ts";
import { type EdgeStack, httpRouterArgs, startEdgeStack } from "./stack.ts";

export const bunImage =
  "oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61";
const fixtures = import.meta.dir;
const root = resolve(import.meta.dir, "..", "..");

export async function waitFor<T>(
  what: string,
  attempt: () => Promise<T | undefined>,
  timeoutMs = 30_000,
  stepMs = 200,
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await attempt().catch(() => undefined);
    if (value !== undefined) return value;
    await Bun.sleep(stepMs);
  }
  throw new Error(`Timed out after ${timeoutMs} ms waiting for ${what}.`);
}

/** The simulated tailnet network of a run: not one of the runtime's own resources. */
export const gatePeerNetwork = (name: string) => `${name}-peer`;

/**
 * Removes everything a run created: the runtime's containers, Compose projects and network, then the
 * simulated tailnet network (edge-ts is gone by then). Safe after a partial start.
 */
export async function cleanupGateEdge(runtime: EdgeTestRuntime, name: string, edge?: GateEdge) {
  edge?.stop();
  await runtime.cleanup();
  await Bun.spawn(["docker", "network", "rm", gatePeerNetwork(name)], { stdout: "ignore", stderr: "ignore" })
    .exited;
}

export type GateEdgeOptions = {
  runtime: EdgeTestRuntime;
  directory: string;
  /** Unique per run; prefixes every container, network and Compose project. */
  name: string;
  gateToken: string;
  /** Hostnames that get a self-signed certificate (routes and the login origin). */
  hostnames: string[];
  /** The lease's routes (§3.2); `overdue` below removes entries as the API does (§3.9.3). */
  policy: (peerIp: string) => EdgePolicyRoute[];
  /** The runtime gate suite shares the HAProxy master socket with the in-container worker. */
  targetedHttp?: boolean;
  /** The `api:3000` container: bundled entry point and its environment. */
  lease?: () => Promise<EdgeLeaseDocument | undefined>;
  api: { entry: string; env: Record<string, string>; hostGateway?: boolean };
};

export type GateEdge = {
  stack: EdgeStack;
  peerIp: string;
  httpsPort: number;
  apiName: string;
  peerName: string;
  /** Route IDs the lease leaves out, as the API does for a revocation overdue by more than 5 s. */
  overdue: Set<string>;
  events: WatchdogEvent[];
  edgeApply: (plan: unknown) => Promise<{ applied: boolean; httpRoutes: string[] }>;
  /** `GET /__seen` from inside a fixture container. */
  seen: (container: string) => Promise<unknown[]>;
  stop: () => void;
};

async function bundle(directory: string, entry: string, name: string) {
  const outdir = join(directory, name);
  const built = await Bun.build({ entrypoints: [entry], target: "bun", outdir });
  if (!built.success) throw new Error(`Bundling ${entry} failed: ${built.logs.join("\n")}`);
  await chmod(outdir, 0o755);
  return outdir;
}

function certificate(dir: string, host: string) {
  return `mkdir -p ${dir} && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=${host}" -addext "subjectAltName=DNS:${host}" -keyout ${dir}/privkey.pem -out ${dir}/fullchain.pem 2>/dev/null && chmod 600 ${dir}/privkey.pem`;
}

export async function startGateEdge(options: GateEdgeOptions): Promise<GateEdge> {
  const { runtime, directory, name } = options;
  const docker = (...args: string[]) => runtime.docker(...args);
  const edgeDir = join(directory, "edge");
  const certDir = join(directory, "certs");
  const acmeDir = join(directory, "acme");
  const octet = 64 + (Number.parseInt(randomBytes(1).toString("hex"), 16) % 64);
  const third = 1 + (Number.parseInt(randomBytes(1).toString("hex"), 16) % 250);
  const peerSubnet = `100.${octet}.${third}.0/24`;
  const peerIp = `100.${octet}.${third}.10`;
  const peerNetwork = gatePeerNetwork(name);
  const apiName = `${name}-api`;
  const peerName = `${name}-upstream`;
  const watchdogName = `${name}-watchdog`;
  const policy = options.policy(peerIp);

  // Lease API: the API's read-only lease endpoint, served by this process.
  const watchdogToken = randomBytes(24).toString("base64url");
  const overdue = new Set<string>();
  const events: WatchdogEvent[] = [];
  const leaseApi = Bun.serve({
    hostname: "0.0.0.0",
    port: 0,
    async fetch(incoming) {
      if (incoming.headers.get("authorization") !== `Bearer ${watchdogToken}`)
        return new Response("no", { status: 401 });
      const { pathname } = new URL(incoming.url);
      if (pathname === "/api/internal/edge/lease") {
        const real = await options.lease?.();
        if (real) return Response.json(real);
        const now = Date.now();
        const document: EdgeLeaseDocument = {
          now: new Date(now).toISOString(),
          lease: {
            generation: `gen-${name}`,
            completedAt: new Date(now - 1_000).toISOString(),
            validUntil: new Date(now + 360_000).toISOString(),
            valid: true,
          },
          routes: policy.filter((route) => !overdue.has(route.id)),
          revocations: [...overdue].map((routeId) => ({
            id: `grv_${routeId}`,
            routeId,
            createdAt: new Date(now - 6_000).toISOString(),
            overdue: true,
          })),
        };
        return Response.json(document);
      }
      if (pathname === "/api/internal/edge/watchdog-event") {
        events.push((await incoming.json()) as WatchdogEvent);
        return Response.json({ ok: true });
      }
      return new Response("not found", { status: 404 });
    },
  });

  // Files: a route-free starting configuration and self-signed certificates.
  await mkdir(join(acmeDir, ".well-known", "acme-challenge"), { recursive: true });
  await mkdir(edgeDir);
  await Bun.write(
    join(edgeDir, "Caddyfile"),
    "{\n  admin edge-admin:2019\n  auto_https off\n}\n:80 {\n  respond 404\n}\n",
  );
  await Bun.write(join(edgeDir, "Caddyfile.closed"), await Bun.file(join(edgeDir, "Caddyfile")).text());
  await chmod(directory, 0o755);
  await docker(
    "run",
    "--rm",
    "--user",
    "0:0",
    "--volume",
    `${directory}:/out`,
    bunImage,
    "sh",
    "-c",
    [
      "set -e",
      ...options.hostnames.map((host) => certificate(`/out/certs/${host}`, host)),
      "chown -R 1000:1000 /out/certs /out/edge",
    ].join("\n"),
  );

  // Containers.
  runtime.networkCreated = true;
  await docker("network", "create", runtime.network);
  await docker("network", "create", "--subnet", peerSubnet, peerNetwork);
  const apiBundle = await bundle(directory, options.api.entry, "api");
  const watchdogBundle = await bundle(directory, join(root, "workers/src/edge-watchdog.ts"), "watchdog");
  const writeEdgeBundle = await bundle(directory, join(fixtures, "write-edge.ts"), "write-edge");
  const entry = options.api.entry.split("/").at(-1)!.replace(/\.ts$/, ".js");
  runtime.containers.push(apiName);
  await docker(
    "run",
    "--detach",
    "--name",
    apiName,
    "--network",
    runtime.network,
    ...(options.api.hostGateway ? ["--add-host", "host.docker.internal:host-gateway"] : []),
    ...Object.entries(options.api.env).flatMap(([key, value]) => ["--env", `${key}=${value}`]),
    "--volume",
    `${apiBundle}:/api:ro`,
    bunImage,
    "bun",
    `/api/${entry}`,
  );
  const stack = await startEdgeStack({
    runtime,
    project: name,
    directory,
    acmeDir,
    certDir,
    edgeDir,
    validator: options.targetedHttp,
    ports: ["127.0.0.1::80", "127.0.0.1::443"],
    edgeEnvironment: { ARK_EDGE_GATE_TOKEN: options.gateToken },
    edgeTsCommand: [
      "tailscaled",
      "--state=mem:",
      "--socket=/var/run/tailscale/tailscaled.sock",
      "--port=41641",
      "--tun=tailscale0",
    ],
  });
  await docker("network", "connect", "--alias", "api", stack.networks.admin, apiName);
  await docker("network", "connect", peerNetwork, stack.edgeTs);
  runtime.containers.push(peerName);
  await docker(
    "run",
    "--detach",
    "--name",
    peerName,
    "--network",
    peerNetwork,
    "--ip",
    peerIp,
    "--volume",
    `${join(fixtures, "upstream.ts")}:/fixture/app.ts:ro`,
    bunImage,
    "bun",
    "/fixture/app.ts",
  );

  // The edge watchdog as shipped (uid 1000, read-only root, no capabilities).
  runtime.containers.push(watchdogName);
  await docker(
    "run",
    "--detach",
    "--name",
    watchdogName,
    "--user",
    "1000:1000",
    "--group-add",
    "4400",
    "--read-only",
    "--tmpfs",
    "/tmp",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges:true",
    "--network",
    runtime.network,
    "--add-host",
    "host.docker.internal:host-gateway",
    "--env",
    `ARK_API_URL=http://host.docker.internal:${leaseApi.port}`,
    "--env",
    `ARK_EDGE_WATCHDOG_TOKEN=${watchdogToken}`,
    "--env",
    "ARK_EDGE_ADMIN_URL=http://edge-admin:2019",
    "--env",
    "ARK_EDGE_DIR=/var/lib/ark/edge",
    "--volume",
    `${edgeDir}:/var/lib/ark/edge`,
    ...(options.targetedHttp ? httpRouterArgs(stack) : []),
    "--volume",
    `${watchdogBundle}:/watchdog:ro`,
    "--workdir",
    "/tmp",
    bunImage,
    "bun",
    "/watchdog/edge-watchdog.js",
  );
  await docker("network", "connect", "--alias", "edge-watchdog", stack.networks.edgeControl, watchdogName);
  await waitFor(
    "verified watchdog enforcement on Caddy",
    async () => {
      const status = await docker(
        "exec",
        watchdogName,
        "bun",
        "--eval",
        'const r = await fetch("http://127.0.0.1:2021/v1/supervise?proxy=caddy"); console.log(r.ok ? "ready" : "no")',
      );
      return status === "ready" ? true : undefined;
    },
    30_000,
    500,
  );

  const edgeApply = async (plan: unknown) => {
    const output = await docker(
      "run",
      "--rm",
      "--network",
      stack.networks.edgeControl,
      "--user",
      "1000:1000",
      "--group-add",
      "4400",
      "--env",
      "HOME=/tmp",
      "--env",
      "ARK_EDGE_DIR=/edge",
      "--env",
      "ARK_EDGE_RELOAD_URL=http://edge-admin:2019",
      "--env",
      "ARK_ACME_WEBROOT=/var/lib/ark/acme",
      "--volume",
      `${writeEdgeBundle}:/harness:ro`,
      "--volume",
      `${edgeDir}:/edge`,
      ...(options.targetedHttp ? httpRouterArgs(stack, true) : []),
      "--workdir",
      "/tmp",
      bunImage,
      "bun",
      "/harness/write-edge.js",
      options.targetedHttp ? "write-routed" : "write",
      JSON.stringify(plan),
    );
    return JSON.parse(output) as { applied: boolean; httpRoutes: string[] };
  };

  const seen = async (container: string) =>
    JSON.parse(
      await docker(
        "exec",
        container,
        "bun",
        "--eval",
        'console.log(JSON.stringify(await (await fetch("http://127.0.0.1:3000/__seen")).json()))',
      ),
    ) as unknown[];

  return {
    stack,
    peerIp,
    httpsPort: await stack.hostPort(443),
    apiName,
    peerName,
    overdue,
    events,
    edgeApply,
    seen,
    stop: () => leaseApi.stop(true),
  };
}
