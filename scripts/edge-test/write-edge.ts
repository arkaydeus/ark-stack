// Test-only entry point for `mise run test:edge`. The harness bundles it with Bun.build and runs it
// in the pinned Bun container on the edge-control network of the disposable edge-ts/edge Compose
// project, where edge-ts carries the `edge-admin` alias for the Caddy in its namespace, so the apply
// goes through the production `writeEdge` as the domain worker does:
// render -> write ARK_EDGE_DIR/Caddyfile -> POST /adapt -> POST /load with must-revalidate.
// Caddy's admin API only accepts Host `edge-admin:2019`, which is why this cannot run on the host.
//
//   bun write-edge.js write '<writeEdge input JSON>'
//   bun write-edge.js write-routed '<writeEdge input JSON>' (also apply the HTTP SNI generation)
//   bun write-edge.js coordinator '{"kind":"edge.drain","enqueue":true}' (disposable database)
//   bun write-edge.js load-without-revalidate   (control: /adapt + /load without Cache-Control)
import { join } from "node:path";

import {
  caddyTailnetRouteKeys,
  servedHttpHostnames,
  servedHttpRoutes,
  sha256Hex,
  type EdgeWatchdogHealth,
} from "@ark-stack/shared";
import { writeEdgeL4 } from "../../server/src/modules/edge-l4.ts";
import { writeEdge } from "../../server/src/modules/providers.ts";

const [mode, input] = process.argv.slice(2);

if (mode === "coordinator") {
  const {
    kind,
    enqueue: create,
    failCensus,
    acknowledgeIngress,
    holdLoadFor,
  } = JSON.parse(input ?? "{}") as {
    kind?: string;
    enqueue?: boolean;
    failCensus?: boolean;
    acknowledgeIngress?: boolean;
    holdLoadFor?: { identity: string; allowed: number };
  };
  if (kind !== "edge.drain" && kind !== "edge.l4_apply" && kind !== "edge.apply")
    throw new Error("Unexpected edge operation");
  const { enqueue, processQueued } = await import("../../server/src/coordinator.ts");
  const { sql } = await import("../../server/src/db.ts");
  const caddy = process.env.ARK_EDGE_RELOAD_URL!;
  const admin =
    failCensus || holdLoadFor
      ? Bun.serve({
          hostname: "127.0.0.1",
          port: 0,
          async fetch(request) {
            if (failCensus) return new Response(null, { status: 503 });
            const path = new URL(request.url).pathname;
            const body = request.method === "GET" ? undefined : await request.text();
            const headers = new Headers(request.headers);
            headers.delete("host");
            const response = await fetch(new URL(path, caddy), { method: request.method, headers, body });
            if (holdLoadFor && path === "/load" && body && response.ok) {
              // Caddy has committed the forced load, but the domain worker is still awaiting its
              // response and cannot mark the revocation applied. Run a watchdog pass in that window.
              const loadedAt = Date.now();
              const deadline = performance.now() + 8_000;
              let denied = false;
              while (!denied && performance.now() < deadline) {
                const watchdog = await fetch(new URL("/v1/health", process.env.ARK_EDGE_WATCHDOG_URL!), {
                  signal: AbortSignal.timeout(1_000),
                });
                const health = (await watchdog.json()) as EdgeWatchdogHealth;
                const tick = health.proxies.caddy?.lastTick;
                denied = Boolean(
                  tick?.verified &&
                  tick.policy.leaseValid &&
                  Date.parse(tick.policy.observedAt ?? "") > loadedAt &&
                  tick.policy.allowed === holdLoadFor.allowed,
                );
                if (!denied) await Bun.sleep(100);
              }
              if (!denied)
                throw new Error("The watchdog did not enforce the overdue lease during the forced load.");
              if (caddyTailnetRouteKeys(JSON.parse(body)).includes(holdLoadFor.identity)) {
                throw new Error("The forced load exposed a handler while its gate revocation was overdue.");
              }
            }
            return response;
          },
        })
      : null;
  if (admin) process.env.ARK_EDGE_RELOAD_URL = admin.url.origin;
  // This fixture has no host firewall reconciler. Acknowledge only the exact rendered request.
  const ingress = process.env.ARK_FRONT_INGRESS_DIR;
  let acknowledged = "";
  const timer =
    acknowledgeIngress && ingress
      ? setInterval(async () => {
          try {
            const { id, hash } = await Bun.file(join(ingress, "policy.request")).json();
            if (
              id !== acknowledged &&
              hash === sha256Hex(await Bun.file(join(ingress, "policy.nft")).text())
            ) {
              await Bun.write(
                join(ingress, "policy.status"),
                `request_id=${id}\npolicy_hash=${hash}\napplied=true\n`,
              );
              acknowledged = id;
            }
          } catch {
            // The worker has not published the request yet.
          }
        }, 75)
      : undefined;
  try {
    if (create) await enqueue({ kind, targetIds: ["platform"] });
    const [queued] = await sql`
      SELECT id FROM operations WHERE kind = ${kind} AND status = 'queued' ORDER BY created_at LIMIT 1
    `;
    if (!queued) throw new Error(`No queued ${kind}`);
    await processQueued(1, kind);
    const [finished] = await sql`SELECT id, status, error FROM operations WHERE id = ${queued.id}`;
    const steps = await sql`SELECT evidence FROM operation_steps WHERE operation_id = ${queued.id}`;
    console.log(JSON.stringify({ ...finished, evidence: steps[0]?.evidence ?? null }));
  } finally {
    clearInterval(timer);
    await admin?.stop(true);
    await sql.end();
  }
} else if (mode === "write" || mode === "write-routed") {
  const plan = JSON.parse(input ?? "{}");
  const written = await writeEdge(plan);
  if (mode === "write-routed") {
    await writeEdgeL4({
      httpHostnames: servedHttpHostnames(plan),
      httpRoutes: servedHttpRoutes(plan),
    });
  }
  console.log(JSON.stringify(written));
} else if (mode === "load-without-revalidate") {
  const base = process.env.ARK_EDGE_RELOAD_URL ?? "";
  const caddyfile = await Bun.file(`${process.env.ARK_EDGE_DIR}/Caddyfile`).text();
  const adapted = await fetch(`${base}/adapt`, {
    method: "POST",
    headers: { "content-type": "text/caddyfile" },
    body: caddyfile,
  });
  if (!adapted.ok) throw new Error(`/adapt returned ${adapted.status}: ${await adapted.text()}`);
  const { result } = (await adapted.json()) as { result: unknown };
  const loaded = await fetch(`${base}/load`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(result),
  });
  if (!loaded.ok) throw new Error(`/load returned ${loaded.status}: ${await loaded.text()}`);
  console.log(JSON.stringify({ status: loaded.status }));
} else {
  throw new Error(`Unknown mode ${mode}`);
}
