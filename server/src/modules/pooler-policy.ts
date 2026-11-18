// The pooler-wide source policy for public 5432 (docs/design/front-door.md §3.8.3, FD-26): loading the
// requests (public databases' CIDRs and their Vercel clients) and the saved policy, and the PgBouncer
// section of the `edge.l4_apply` input. The rules themselves are pure (shared/src/pooler-policy.ts).
import {
  PGBOUNCER_INGRESS_SERVER,
  evaluatePoolerPolicy,
  poolerRequests,
  type EdgeL4Pooler,
  type PoolerPolicyEvaluation,
} from "@ark-stack/shared";
import { and, eq } from "drizzle-orm";

import { db } from "../db.ts";
import {
  databaseClients,
  endpoints,
  managedDatabases,
  platformSettings,
  vercelIntegrations,
} from "../schema.ts";

type Executor = Pick<typeof db, "select">;

/** The current requests and the saved pooler policy, evaluated (publication state and conflicts). */
export async function loadPoolerPolicy(executor: Executor = db): Promise<PoolerPolicyEvaluation> {
  return (await loadPoolerState(executor)).evaluation;
}

/** The evaluation plus the retirement watchdog's fence (FD-28 fallback), which omits be_pgbouncer. */
export async function loadPoolerState(executor: Executor = db) {
  const [settings] = await executor.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  const databases = await executor
    .select({
      id: managedDatabases.id,
      name: managedDatabases.name,
      exposure: managedDatabases.exposure,
      sourceCidrs: managedDatabases.sourceCidrs,
    })
    .from(managedDatabases);
  const vercelClients = await executor
    .select({
      id: databaseClients.id,
      name: databaseClients.name,
      databaseId: databaseClients.databaseId,
      status: databaseClients.status,
    })
    .from(vercelIntegrations)
    .innerJoin(
      databaseClients,
      and(eq(databaseClients.id, vercelIntegrations.databaseClientId), eq(databaseClients.status, "active")),
    );
  const fence = settings?.poolerFencedAt
    ? { at: settings.poolerFencedAt.toISOString(), reason: settings.poolerFenceReason ?? null }
    : null;
  const evaluation = evaluatePoolerPolicy({
    fence,
    requests: poolerRequests({ databases, vercelClients }),
    policy: {
      sourceCidrs: Array.isArray(settings?.poolerSourceCidrs) ? settings.poolerSourceCidrs.map(String) : [],
      allowInternet: Boolean(settings?.poolerAllowInternet),
      internetConfirmedAt: settings?.poolerInternetConfirmedAt ?? null,
      reviewedAt: settings?.poolerPolicyReviewedAt ?? null,
      reviewedRequests: settings?.poolerPolicyReviewedRequests ?? null,
    },
  });
  return { evaluation, fence };
}

/** The Ark database hostname (the `database` endpoint): direct TLS with this SNI goes to PgBouncer. */
export async function databaseHostname(executor: Executor = db) {
  const [endpoint] = await executor
    .select({ hostname: endpoints.hostname })
    .from(endpoints)
    .where(eq(endpoints.kind, "database"))
    .limit(1);
  return endpoint?.hostname ?? null;
}

/**
 * The PgBouncer section of `edge.l4_apply`: rendered only while the pooler is publishable, so with no
 * public database (or a refused, unreviewed or empty policy) `SSLRequest` connections are rejected.
 */
export async function poolerEdgeInput(env: Record<string, string | undefined> = process.env): Promise<{
  pooler: EdgeL4Pooler | null;
  evaluation: PoolerPolicyEvaluation;
  fence: Awaited<ReturnType<typeof loadPoolerState>>["fence"];
}> {
  const { evaluation: current, fence } = await loadPoolerState();
  if (!current.publishable || fence) return { pooler: null, evaluation: current, fence };
  return {
    evaluation: current,
    fence,
    pooler: {
      hostname: await databaseHostname(),
      sourceCidrs: current.policy.sourceCidrs,
      allowInternet: current.policy.allowInternet,
      server: env.ARK_PGBOUNCER_INGRESS_SERVER?.trim() || PGBOUNCER_INGRESS_SERVER,
    },
  };
}
