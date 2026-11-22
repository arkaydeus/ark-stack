import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { hostRoutesFromFront, mailEnabled, parseSniPorts, sha256Hex } from "@ark-stack/shared";

export const frontPolicyPending = "The front policy is awaiting firewall acknowledgement";

function readOptional(path: string) {
  return readFile(path, "utf8").catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return null;
    throw error;
  });
}

export async function appliedHostConfig(root: string, env = process.env) {
  const config = {
    mailEnabled: mailEnabled(env.ARK_MAIL_ENABLED),
    sniPorts: parseSniPorts(env.ARK_EDGE_SNI_PORTS),
  };
  const dir = join(root, "tmp", "edge-l4", "front-ingress");
  const rules = await readOptional(join(dir, "policy.nft"));
  if (rules === null) return config;
  const [requestText, statusText] = await Promise.all([
    readOptional(join(dir, "policy.request")),
    readOptional(join(dir, "policy.status")),
  ]);
  if (requestText === null) throw new Error(`${frontPolicyPending} (request not yet published).`);
  const request = JSON.parse(requestText) as { id: string; hash: string };
  const status = new Map(
    (statusText ?? "")
      .trimEnd()
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const at = line.indexOf("=");
        return (at < 0 ? [line, ""] : [line.slice(0, at), line.slice(at + 1)]) as [string, string];
      }),
  );
  const current =
    status.get("request_id") === request.id &&
    status.get("policy_hash") === request.hash &&
    sha256Hex(rules) === request.hash;
  if (current && status.get("applied") === "false") {
    // The reconciler retries ordinary failures and replaces legacy requests after an upgrade.
    throw new Error(
      `${frontPolicyPending}. database-ingress could not apply the front policy (request ${request.id}): ${status.get("error") || "no error recorded"}. ` +
        "Check docker compose -f infra/platform/docker-compose.yml logs database-ingress.",
    );
  }
  if (!current || status.get("applied") !== "true") {
    throw new Error(`${frontPolicyPending}.`);
  }
  return { ...config, routes: hostRoutesFromFront(rules) };
}
