import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { jmapCall, parseStalwartQueue, type MailQueueItem } from "@ark-stack/shared";

const exec = promisify(execFile);

export async function listMailQueue(): Promise<MailQueueItem[]> {
  if (process.env.STALWART_CLI) {
    const { stdout } = await exec(process.env.STALWART_CLI, ["queue", "list", "--json"], { timeout: 20_000 });
    return parseStalwartQueue(stdout);
  }
  const url = process.env.STALWART_URL;
  if (url && process.env.STALWART_ADMIN_ADDRESS && process.env.STALWART_ADMIN_PASSWORD) {
    const auth = Buffer.from(
      `${process.env.STALWART_ADMIN_ADDRESS}:${process.env.STALWART_ADMIN_PASSWORD}`,
    ).toString("base64");
    const response = await fetch(`${url.replace(/\/$/, "")}/jmap`, {
      method: "POST",
      headers: { authorization: `Basic ${auth}`, "content-type": "application/json" },
      body: JSON.stringify(jmapCall("Queue/query", { limit: 50 })),
    });
    if (!response.ok) return [];
    const body = (await response.json()) as { methodResponses?: Array<[string, { ids?: string[] }]> };
    return (body.methodResponses?.[0]?.[1]?.ids ?? []).map((id) => ({
      id,
      recipient: "unknown@local",
      sender: "",
      ageSeconds: 0,
      state: "queued" as const,
    }));
  }
  return [];
}

export async function mutateMailQueue(action: "retry" | "delete", id: string) {
  if (!process.env.STALWART_CLI) return { executed: false, id, action };
  await exec(process.env.STALWART_CLI, ["queue", action, id, "--json"], { timeout: 20_000 });
  return { executed: true, id, action };
}
