import { secureEqual } from "@ark-stack/shared";
import { runWorker } from "./runtime.ts";
import {
  executeClaimedJob,
  scheduleDnsMaintenance,
  scheduleEdgeObserve,
} from "../../server/src/coordinator.ts";
import { DnsReviewError } from "../../server/src/modules/cloudflare-dns.ts";
import { domainDnsReview } from "../../server/src/modules/domain-dns.ts";

export function dnsControlHandler(token: string) {
  return async (request: Request) => {
    const path = new URL(request.url).pathname;
    if (request.method !== "POST" || path !== "/dns/review") {
      return new Response("not found", { status: 404 });
    }
    if (!secureEqual(request.headers.get("authorization") ?? "", "Bearer " + token)) {
      return new Response("unauthorized", { status: 401 });
    }
    const body = (await request.json().catch(() => null)) as {
      domainId?: string;
    } | null;
    if (typeof body?.domainId !== "string" || !body.domainId) {
      return Response.json({ error: "Invalid domain ID." }, { status: 422 });
    }
    try {
      return Response.json(await domainDnsReview(body.domainId));
    } catch (error) {
      if (error instanceof DnsReviewError) {
        return Response.json({ error: error.message }, { status: error.status });
      }
      console.error("DNS worker request failed:", error);
      return Response.json(
        { error: "DNS worker request failed. Reload the current review and retry." },
        { status: 500 },
      );
    }
  };
}

export function runDomainJobs(
  executor: Parameters<typeof runWorker>[2] = executeClaimedJob,
  options: { signal?: AbortSignal; pollMs?: number } = {},
) {
  // Deployment polling can take 30 minutes. Keep the edge and DNS slot available throughout.
  return Promise.all([
    runWorker("domains", ["domain.", "dns.", "certificate.", "edge.", "admin."], executor, options),
    runWorker("domains", ["integration."], executor, options),
  ]);
}

if (import.meta.main) {
  const token = process.env.ARK_WORKER_TOKEN;
  if (!token) throw new Error("ARK_WORKER_TOKEN is required for the domain worker control endpoint.");
  const control = Bun.serve({
    hostname: "0.0.0.0",
    port: Number(process.env.ARK_DOMAIN_WORKER_PORT ?? 3102),
    idleTimeout: 60,
    maxRequestBodySize: 16 * 1024,
    fetch: dnsControlHandler(token),
  });

  // `edge.observe` every five minutes while the edge node's LocalAPI socket is mounted (front door §3.4).
  const observeSchedule = scheduleEdgeObserve();
  const dnsSchedule = scheduleDnsMaintenance();
  try {
    await runDomainJobs();
  } finally {
    if (observeSchedule) clearInterval(observeSchedule);
    clearInterval(dnsSchedule);
    await control.stop(true);
  }
}
