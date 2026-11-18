import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { hostRoutesFromFront, mailEnabled, parseSniPorts, sha256Hex } from "@ark-stack/shared";

export async function appliedHostConfig(root: string, env = process.env) {
  const config = {
    mailEnabled: mailEnabled(env.ARK_MAIL_ENABLED),
    sniPorts: parseSniPorts(env.ARK_EDGE_SNI_PORTS),
  };
  const dir = join(root, "tmp", "edge-l4", "front-ingress");
  const rules = await readFile(join(dir, "policy.nft"), "utf8").catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return null;
    throw error;
  });
  if (rules === null) return config;
  const [requestText, statusText] = await Promise.all([
    readFile(join(dir, "policy.request"), "utf8"),
    readFile(join(dir, "policy.status"), "utf8"),
  ]);
  const request = JSON.parse(requestText) as { id: string; hash: string };
  const status = new Map(
    statusText
      .trimEnd()
      .split("\n")
      .map((line) => line.split("=", 2) as [string, string]),
  );
  if (
    status.get("applied") !== "true" ||
    status.get("request_id") !== request.id ||
    status.get("policy_hash") !== request.hash ||
    sha256Hex(rules) !== request.hash
  ) {
    throw new Error("The front policy is awaiting firewall acknowledgement. Retry after reconciliation.");
  }
  return { ...config, routes: hostRoutesFromFront(rules) };
}
