// `edge.l4_apply` file and socket work for the HAProxy SNI router (docs/design/front-door.md §3.8.6,
// FD-25). No database access here, so the runtime tests run exactly this code in a container with
// the domain worker's user, groups and mounts.
import {
  HaproxyMaster,
  haproxyHttpServerName,
  haproxyServerName,
  type EdgePolicyRoute,
  HaproxyWithdrawalAdapter,
  installEdgeL4Generation,
  renderEdgeL4Generation,
  SERVER_FORCED_MAINT,
  type EdgeL4HttpRoute,
  type EdgeL4Input,
} from "@ark-stack/shared";

export type EdgeL4Settings = {
  /** Writable configuration root (`tmp/edge-l4`), mounted read-only into edge-l4 and the validator. */
  root?: string;
  validatorSocket?: string;
  masterSocket?: string;
  adminSocket?: string;
};

export function edgeL4Settings(env: Record<string, string | undefined> = process.env): EdgeL4Settings {
  const value = (name: string) => env[name]?.trim() || undefined;
  return {
    root: value("ARK_EDGE_L4_DIR"),
    validatorSocket: value("ARK_HAPROXY_VALIDATOR_SOCKET"),
    masterSocket: value("ARK_HAPROXY_MASTER_SOCKET"),
    adminSocket: value("ARK_HAPROXY_ADMIN_SOCKET"),
  };
}

/** True where the domain worker manages edge-l4 (its configuration directory is mounted). */
export function edgeL4Configured(env: Record<string, string | undefined> = process.env) {
  return Boolean(edgeL4Settings(env).root);
}

/** The HAProxy withdrawal adapter over the shared master socket, where it is mounted. */
export function haproxyAdapter(env: Record<string, string | undefined> = process.env) {
  const { masterSocket } = edgeL4Settings(env);
  return masterSocket ? new HaproxyWithdrawalAdapter(masterSocket) : null;
}

/**
 * Renders and installs a generation: write, validate (restricted validator), verify, swap `current`,
 * reload on the master CLI. The caller holds the edge lock. Throws on a refused candidate (nothing is
 * swapped or reloaded) and on any failed/unconfirmed reload (current is restored; retries reload).
 */
export async function writeEdgeL4(input: EdgeL4Input, env: Record<string, string | undefined> = process.env) {
  const settings = edgeL4Settings(env);
  if (!settings.root) {
    if (env.NODE_ENV === "production")
      throw new Error("ARK_EDGE_L4_DIR is required to apply edge-l4 in production.");
    return { applied: false as const, reason: "ARK_EDGE_L4_DIR is not set" };
  }
  if (!settings.validatorSocket)
    throw new Error("ARK_HAPROXY_VALIDATOR_SOCKET is required to apply edge-l4.");
  if (!settings.masterSocket && env.NODE_ENV === "production") {
    throw new Error("ARK_HAPROXY_MASTER_SOCKET is required to reload edge-l4 in production.");
  }
  const generation = renderEdgeL4Generation(input);
  const adapter = settings.masterSocket ? new HaproxyWithdrawalAdapter(settings.masterSocket) : null;
  // A withdrawal changes runtime state even if the desired generation hash stayed the same.
  const force = Boolean(
    adapter && input.httpRoutes?.length && (await missingHttpRoutes(input.httpRoutes, adapter.master)).length,
  );
  const result = await installEdgeL4Generation({
    root: settings.root,
    generation,
    validatorSocket: settings.validatorSocket,
    master: adapter?.master,
    force,
  });
  if (adapter && input.httpRoutes !== undefined) {
    const retired = await adapter.retireLegacyHttp();
    if (retired.error) throw new Error(`Legacy HTTP session withdrawal failed: ${retired.error}`);
  }
  return {
    applied: true as const,
    ...result,
    reloadLog: result.reloadLog?.slice(-1_000),
    httpHostnames: generation.manifest.httpHostnames,
    sniPorts: generation.manifest.sniPorts,
    tlsRoutes: generation.manifest.routes.filter((route) => route.kind === "tls").map((route) => route.id),
    tcpRoutes: generation.manifest.routes.filter((route) => route.kind === "tcp").map((route) => route.id),
    postgresRoutes: generation.manifest.routes
      .filter((route) => route.kind === "postgres")
      .map((route) => route.id),
    pooler: generation.manifest.pooler ?? null,
  };
}

/** Desired-versus-running recovery examines accepting workers, never a leaving worker's copy. */
export async function missingL4Routes(routes: EdgePolicyRoute[], master: HaproxyMaster) {
  const servers = await acceptingServers(master);
  return routes
    .filter(
      (route) =>
        (route.kind === "tls" || route.kind === "tcp" || route.kind === "postgres") &&
        !servers.has(haproxyServerName(route)),
    )
    .map((route) => route.id);
}

export async function missingHttpRoutes(routes: EdgeL4HttpRoute[], master: HaproxyMaster) {
  if (!routes.length) return [];
  const servers = await acceptingServers(master);
  return routes.filter((route) => !servers.has(haproxyHttpServerName(route))).map((route) => route.id);
}

async function acceptingServers(master: HaproxyMaster) {
  const workers = (await master.workers()).filter((worker) => worker.section === "current");
  const servers = (await Promise.all(workers.map((worker) => master.servers(worker.pid)))).flat();
  return new Set(
    servers.filter((server) => !(server.adminState & SERVER_FORCED_MAINT)).map((server) => server.server),
  );
}
