import { dnsPublishInput, secureEqual } from "@ark-stack/shared";
import { runWorker } from "./runtime.ts";
import {
  executeClaimedJob,
  scheduleDnsMaintenance,
  scheduleEdgeObserve,
} from "../../server/src/coordinator.ts";
import { DnsReviewError } from "../../server/src/modules/cloudflare-dns.ts";
import {
  domainDnsReview,
  publishReviewedDns,
  type DnsPublisher,
} from "../../server/src/modules/domain-dns.ts";

const token = process.env.ARK_WORKER_TOKEN;
if (!token) throw new Error("ARK_WORKER_TOKEN is required for the domain worker control endpoint.");
const control = Bun.serve({
  hostname: "0.0.0.0",
  port: Number(process.env.ARK_DOMAIN_WORKER_PORT ?? 3102),
  idleTimeout: 60,
  maxRequestBodySize: 16 * 1024,
  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (request.method !== "POST" || !["/dns/review", "/dns/publish"].includes(path)) {
      return new Response("not found", { status: 404 });
    }
    if (!secureEqual(request.headers.get("authorization") ?? "", "Bearer " + token)) {
      return new Response("unauthorized", { status: 401 });
    }
    const body = (await request.json().catch(() => null)) as {
      domainId?: string;
      input?: unknown;
      actor?: Partial<DnsPublisher>;
    } | null;
    if (typeof body?.domainId !== "string" || !body.domainId) {
      return Response.json({ error: "Invalid domain ID." }, { status: 422 });
    }
    try {
      if (path === "/dns/review") return Response.json(await domainDnsReview(body.domainId));
      const input = dnsPublishInput.safeParse(body.input);
      const { userId, role } = body.actor ?? {};
      if (!input.success || typeof userId !== "string" || (role !== "owner" && role !== "operator")) {
        return Response.json({ error: "Invalid DNS publish request." }, { status: 422 });
      }
      return Response.json(await publishReviewedDns(body.domainId, input.data, { userId, role }));
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
  },
});

// `edge.observe` every five minutes while the edge node's LocalAPI socket is mounted (front door §3.4).
const observeSchedule = scheduleEdgeObserve();
const dnsSchedule = scheduleDnsMaintenance();
try {
  await runWorker("domains", ["domain.", "dns.", "certificate.", "edge.", "admin."], executeClaimedJob);
} finally {
  if (observeSchedule) clearInterval(observeSchedule);
  clearInterval(dnsSchedule);
  await control.stop(true);
}
