import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { eq } from "drizzle-orm";

import { createId, parseEnvFile } from "@ark-stack/shared";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { app } = await import("./app.ts");
const { db } = await import("./db.ts");
const { operations } = await import("./schema.ts");

describe("internal worker boundary", () => {
  test("agent token cannot complete a non-service operation", async () => {
    const id = createId("op");
    await db.insert(operations).values({
      id,
      kind: "backup.restore_test",
      status: "running",
      idempotencyKey: `test-${id}`,
      planHash: "x",
      targetIds: ["t1"],
      payload: {},
    });
    const response = await app.request(`/api/internal/jobs/${id}/complete`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${process.env.ARK_AGENT_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ status: "succeeded" }),
    });
    expect(response.status).toBe(403);
    const [row] = await db.select().from(operations).where(eq(operations.id, id));
    expect(row?.status).toBe("running");
  });

  test("agent completion requires the current claim token", async () => {
    const id = createId("op");
    await db.insert(operations).values({
      id,
      kind: "service.restart",
      status: "running",
      claimToken: "claim-current",
      idempotencyKey: `test-${id}`,
      planHash: "x",
      targetIds: ["svc_x"],
      payload: {},
    });
    for (const body of [{ status: "succeeded" }, { status: "succeeded", claimToken: "stale" }]) {
      const response = await app.request(`/api/internal/jobs/${id}/complete`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${process.env.ARK_AGENT_TOKEN}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
      });
      expect(response.status).toBe(403);
    }
    const [row] = await db.select().from(operations).where(eq(operations.id, id));
    expect(row?.status).toBe("running");
  });

  test("stale agent completion does not write service state", async () => {
    const { projects, services } = await import("./schema.ts");
    const projectId = createId("prj");
    const serviceId = createId("svc");
    const operationId = createId("op");
    await db.insert(projects).values({ id: projectId, name: "edge", slug: `edge-${operationId.slice(-8)}` });
    await db.insert(services).values({
      id: serviceId,
      projectId,
      name: "web",
      compose: "services: {}\n",
      desiredRevision: "rev-1",
      status: "registered",
    });
    await db.insert(operations).values({
      id: operationId,
      kind: "service.restart",
      status: "running",
      claimToken: "claim-stale",
      idempotencyKey: `test-${operationId}`,
      planHash: "x",
      targetIds: [serviceId],
      payload: { name: "web" },
    });
    await db.update(operations).set({ claimToken: "claim-current" }).where(eq(operations.id, operationId));
    const response = await app.request(`/api/internal/jobs/${operationId}/complete`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${process.env.ARK_AGENT_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ status: "succeeded", claimToken: "claim-stale" }),
    });
    expect(response.status).toBe(403);
    const [service] = await db.select().from(services).where(eq(services.id, serviceId));
    const [row] = await db.select().from(operations).where(eq(operations.id, operationId));
    expect(service?.status).toBe("registered");
    expect(row?.status).toBe("running");
  });

  test("concurrent agent completions write service state only for the winning claim", async () => {
    const { projects, services } = await import("./schema.ts");
    const projectId = createId("prj");
    const serviceId = createId("svc");
    const operationId = createId("op");
    await db.insert(projects).values({ id: projectId, name: "win", slug: `win-${operationId.slice(-8)}` });
    await db.insert(services).values({
      id: serviceId,
      projectId,
      name: "web",
      compose: "services: {}\n",
      desiredRevision: "rev-1",
      status: "registered",
    });
    await db.insert(operations).values({
      id: operationId,
      kind: "service.restart",
      status: "running",
      claimToken: "claim-race",
      idempotencyKey: `test-${operationId}`,
      planHash: "x",
      targetIds: [serviceId],
      payload: { name: "web" },
    });
    const request = () =>
      app.request(`/api/internal/jobs/${operationId}/complete`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${process.env.ARK_AGENT_TOKEN}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ status: "succeeded", claimToken: "claim-race" }),
      });
    const [left, right] = await Promise.all([request(), request()]);
    const statuses = [left.status, right.status].toSorted();
    expect(statuses).toEqual([200, 409]);
    const [service] = await db.select().from(services).where(eq(services.id, serviceId));
    const [row] = await db.select().from(operations).where(eq(operations.id, operationId));
    expect(row?.status).toBe("succeeded");
    expect(service?.status).toBe("running");
  });
});
