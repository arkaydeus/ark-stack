import { runWorker } from "./runtime.ts";
import { executeClaimedJob } from "../../server/src/coordinator.ts";
import { cancelWorkspaceQuery } from "../../server/src/modules/database.ts";
import { secureEqual } from "@ark-stack/shared";

const token = process.env.ARK_WORKER_TOKEN;
if (!token) throw new Error("ARK_WORKER_TOKEN is required for the database worker control endpoint.");
const control = Bun.serve({
  hostname: "0.0.0.0",
  port: Number(process.env.ARK_DATABASE_CANCEL_PORT ?? 3101),
  async fetch(request) {
    if (new URL(request.url).pathname !== "/cancel" || request.method !== "POST") {
      return new Response("not found", { status: 404 });
    }
    if (!secureEqual(request.headers.get("authorization") ?? "", `Bearer ${token}`)) {
      return new Response("unauthorized", { status: 401 });
    }
    const body = (await request.json().catch(() => null)) as {
      executionId?: string;
      actorId?: string;
      database?: string;
    } | null;
    if (!body?.executionId || !body.actorId || !body.database) {
      return Response.json({ error: "invalid cancellation scope" }, { status: 422 });
    }
    const cancelled = await cancelWorkspaceQuery({
      executionId: body.executionId,
      actorId: body.actorId,
      database: body.database,
    });
    return Response.json({ executionId: body.executionId, cancelled });
  },
});

try {
  await runWorker("database", ["database.", "pgbouncer."], executeClaimedJob);
} finally {
  await control.stop(true);
}
