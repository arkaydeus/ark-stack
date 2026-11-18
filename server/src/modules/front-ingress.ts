// Host firewall publication shared by the domain worker and runtime tests. No database or host
// privileges: publish exact bytes and require the host reconciler's hash before opening listeners.
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  FRONT_SHARED_LIMIT_DEFAULTS,
  renderDbIngress,
  renderFrontIngress,
  sha256Hex,
  type DbIngressLimits,
  type EdgeL4Input,
} from "@ark-stack/shared";

export function frontIngressRules(
  input: EdgeL4Input,
  limits: DbIngressLimits,
  previous = "",
  sharedLimits = FRONT_SHARED_LIMIT_DEFAULTS,
) {
  const raw = [
    ...(input.tcpRoutes ?? []),
    ...(input.postgresRoutes ?? []).flatMap((route) =>
      route.compatPort == null ? [] : [{ ...route, listenPort: route.compatPort }],
    ),
  ];
  // The database section comes first, followed by the front policy's own shebang.
  const previousDatabase = previous.split("\n#!", 1)[0];
  return (
    renderDbIngress(limits, previousDatabase) + "\n" + renderFrontIngress(raw, input.sniPorts, sharedLimits)
  );
}

export async function applyFrontIngress(
  input: EdgeL4Input,
  limits: DbIngressLimits,
  env: Record<string, string | undefined> = process.env,
) {
  const dir = env.ARK_FRONT_INGRESS_DIR ?? join(env.ARK_EDGE_L4_DIR!, "front-ingress");
  const file = join(dir, "policy.nft");
  const previous = await readFile(file, "utf8").catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return "";
    throw error;
  });
  const defaults = FRONT_SHARED_LIMIT_DEFAULTS;
  const rules = frontIngressRules(input, limits, previous, {
    maxConnectionsPerSource: Number(env.ARK_FRONT_MAX_CONNECTIONS ?? defaults.maxConnectionsPerSource),
    newConnectionsPerSecond: Number(env.ARK_FRONT_RATE_PER_SECOND ?? defaults.newConnectionsPerSecond),
    newConnectionBurst: Number(env.ARK_FRONT_RATE_BURST ?? defaults.newConnectionBurst),
  });
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const temporary = `${file}.${crypto.randomUUID()}.tmp`;
  await writeFile(temporary, rules, { mode: 0o600 });
  await rename(temporary, file);
  const hash = sha256Hex(rules);
  // A persisted acknowledgement from before a host/reconciler restart is not proof that the
  // rules are installed now. Every publication requires a fresh request acknowledgement.
  const requestId = crypto.randomUUID();
  const request = join(dir, "policy.request");
  const requestTemporary = `${request}.${requestId}.tmp`;
  await writeFile(requestTemporary, JSON.stringify({ id: requestId, hash }), { mode: 0o600 });
  await rename(requestTemporary, request);
  const deadline = Date.now() + Number(env.ARK_FRONT_INGRESS_TIMEOUT_MS ?? 15_000);
  let error = "No acknowledgement from database-ingress.";
  do {
    const status = await readFile(join(dir, "policy.status"), "utf8").catch(() => "");
    if (status.includes(`policy_hash=${hash}\n`) && status.includes(`request_id=${requestId}\n`)) {
      if (status.includes("applied=true\n")) return { file, hash, applied: true };
      error = status.split("error=")[1]?.trim() || "Policy not ready.";
    }
    await Bun.sleep(100);
  } while (Date.now() < deadline);
  throw new Error(`Front ingress firewall was not acknowledged: ${error}`);
}
