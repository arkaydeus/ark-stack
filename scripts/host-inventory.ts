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
    readFile(join(dir, "policy.status"), "utf8").catch((error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return "";
      throw error;
    }),
  ]);
  const request = JSON.parse(requestText) as { id: string; hash: string };
  const status = new Map(
    statusText
      .trimEnd()
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const at = line.indexOf("=");
        return (at < 0 ? [line, ""] : [line.slice(0, at), line.slice(at + 1)]) as [string, string];
      }),
  );
  const current = status.get("request_id") === request.id && status.get("policy_hash") === request.hash;
  if (current && status.get("applied") === "false") {
    // database-ingress tried this exact request and failed; waiting will not change that.
    throw new Error(
      `database-ingress could not apply the front policy (request ${request.id}): ${status.get("error") || "no error recorded"}. ` +
        "Check docker compose -f infra/platform/docker-compose.yml logs database-ingress.",
    );
  }
  if (!current || status.get("applied") !== "true" || sha256Hex(rules) !== request.hash) {
    throw new Error("The front policy is awaiting firewall acknowledgement. Retry after reconciliation.");
  }
  return { ...config, routes: hostRoutesFromFront(rules) };
}
