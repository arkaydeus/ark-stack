// Client for the pgBackRest executors inside the PostgreSQL containers (docs/design/front-door.md
// §3.18.1, FD-21). Fixed actions only, authenticated with a per-cluster token on the internal
// `backup-management` network; the backup worker has no Docker socket and no shell on the cluster.
import { PG_CLUSTERS, type PgBackupType, type PgCluster, type StagedBackup } from "@ark-stack/shared";

export type PgExecutorAction = "status" | "check" | "backup" | "stage" | "prune-stages" | "stanza-create";

export function executorConfig(cluster: PgCluster) {
  const profile = PG_CLUSTERS[cluster];
  const url = process.env[profile.urlEnv] ?? `http://${profile.service}:8432`;
  const token = process.env[profile.tokenEnv] ?? "";
  return { profile, url: url.replace(/\/+$/, ""), token };
}

export async function callExecutor<T = Record<string, unknown>>(
  cluster: PgCluster,
  action: PgExecutorAction,
  body: Record<string, unknown> = {},
  timeoutMs = 6 * 60 * 60 * 1000,
): Promise<T> {
  const { url, token, profile } = executorConfig(cluster);
  if (!token)
    throw new Error(`${profile.tokenEnv} is not set; the ${profile.stanza} executor cannot be reached.`);
  const response = await fetch(`${url}/v1/${action}`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const payload = (await response.json().catch(() => ({}))) as T & { error?: string };
  if (!response.ok)
    throw new Error(`${profile.stanza} executor ${action}: ${payload.error ?? response.status}`);
  return payload;
}

/** Runs one PostgreSQL backup into the cluster's local repo2 through its executor (backup.create). */
export async function runPgBackup(cluster: PgCluster, type: PgBackupType) {
  return callExecutor<{ label: string; type: string; backup?: StagedBackup; output?: string }>(
    cluster,
    "backup",
    {
      type,
    },
  );
}

export function clusterForBackupKind(kind: string): PgCluster | null {
  if (kind === "platform-postgres") return "platform";
  if (kind === "app-postgres") return "app";
  return null;
}
