import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import {
  buildStalwartPlan,
  chooseCloudflareMutation,
  cloudflareRecordBody,
  compareInventory,
  digestFromHeaders,
  funnelDisabled,
  jmapCall,
  nftAllowlist,
  pgbouncerConfig,
  pgbouncerUserlist,
  registryManifestUrl,
  renderCaddyfile,
  renderTailscaleServe,
  sesIdentityPlan,
  signAwsRequest,
  type DnsWrite,
  type ExternalInventory,
} from "@ark-stack/shared";

const exec = promisify(execFile);

export async function sesRequest(path: string, method = "GET", body?: Record<string, unknown>) {
  const accessKey = process.env.AWS_ACCESS_KEY_ID ?? process.env.AWS_BOOTSTRAP_ACCESS_KEY_ID ?? "";
  const secretKey = process.env.AWS_SECRET_ACCESS_KEY ?? process.env.AWS_BOOTSTRAP_SECRET_ACCESS_KEY ?? "";
  const region = process.env.AWS_REGION ?? "eu-west-1";
  if (!accessKey || !secretKey) return { configured: false, status: "missing_credentials" };
  const signed = signAwsRequest({
    method,
    path,
    region,
    service: "ses",
    accessKey,
    secretKey,
    body: body ? JSON.stringify(body) : "",
  });
  const response = await fetch(signed.url, {
    method,
    headers: { ...signed.headers, "content-type": "application/json" },
    ...(method === "GET" || method === "HEAD" ? {} : { body: signed.body || undefined }),
  });
  const text = await response.text();
  return { configured: true, ok: response.ok, status: response.status, body: text.slice(0, 4000) };
}

export async function reconcileSes(domain: string, mailFrom: string) {
  const region = process.env.AWS_REGION ?? "eu-west-1";
  const plan = sesIdentityPlan({ domain, mailFrom, region });
  const account = await sesRequest("/v2/email/account");
  if (!account.configured) return { ...plan, account, created: false };
  const created = await sesRequest("/v2/email/identities", "POST", { EmailIdentity: domain });
  await sesRequest(`/v2/email/identities/${domain}/mail-from-attributes`, "PUT", {
    MailFromDomain: mailFrom,
    BehaviorOnMxFailure: "USE_DEFAULT_VALUE",
  });
  return { ...plan, account, created };
}

export async function publishCloudflare(zone: string, records: DnsWrite[]) {
  const token = process.env.DNS_API_TOKEN ?? process.env.CLOUDFLARE_API_TOKEN ?? "";
  if (!token) return { published: false, reason: "manual" as const, records };
  const zoneRes = await fetch(
    `https://api.cloudflare.com/client/v4/zones?name=${encodeURIComponent(zone)}&status=active&per_page=1`,
    { headers: { authorization: `Bearer ${token}` } },
  );
  const zoneBody = (await zoneRes.json()) as { result?: Array<{ id: string }> };
  const zoneId = zoneBody.result?.[0]?.id;
  if (!zoneId) throw new Error(`No unique active Cloudflare zone for ${zone}`);
  const results = [];
  for (const record of records) {
    const existingRes = await fetch(
      `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?type=${record.type}&name=${encodeURIComponent(record.name)}&per_page=100`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    const existingBody = (await existingRes.json()) as {
      result?: Array<{ id: string; content: string; priority?: number }>;
    };
    const mutation = chooseCloudflareMutation(existingBody.result ?? [], record);
    const body = cloudflareRecordBody(record);
    if (mutation.action === "keep") {
      results.push({ record, action: "keep" });
      continue;
    }
    const url =
      mutation.action === "update"
        ? `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${mutation.id}`
        : `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`;
    const response = await fetch(url, {
      method: mutation.action === "update" ? "PUT" : "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`Cloudflare ${mutation.action} failed: ${response.status}`);
    results.push({ record, action: mutation.action });
  }
  return { published: true, reason: "cloudflare" as const, results };
}

export async function applyStalwart(planInput: Parameters<typeof buildStalwartPlan>[0]) {
  const built = buildStalwartPlan(planInput);
  const dir = process.env.ARK_MAIL_STATE_DIR ?? join(process.cwd(), "tmp", "mail-state");
  await mkdir(dir, { recursive: true });
  const file = join(dir, "stalwart-plan.ndjson");
  await Bun.write(file, built.plan.map((item) => JSON.stringify(item)).join("\n"));
  const url = process.env.STALWART_URL;
  if (url && process.env.STALWART_ADMIN_ADDRESS && process.env.STALWART_ADMIN_PASSWORD) {
    const auth = Buffer.from(
      `${process.env.STALWART_ADMIN_ADDRESS}:${process.env.STALWART_ADMIN_PASSWORD}`,
    ).toString("base64");
    const response = await fetch(`${url.replace(/\/$/, "")}/jmap`, {
      method: "POST",
      headers: { authorization: `Basic ${auth}`, "content-type": "application/json" },
      body: JSON.stringify(jmapCall("x:Domain/query", { limit: 1 })),
    });
    if (process.env.STALWART_CLI) {
      await exec(process.env.STALWART_CLI, ["apply", "--file", file, "--json"], { timeout: 120_000 });
    }
    return { applied: response.ok, outbound: built.outbound, file, reachable: response.ok };
  }
  return { applied: false, outbound: built.outbound, file, reachable: false };
}

export function pgbouncerDir() {
  if (process.env.ARK_PGBOUNCER_DIR) return process.env.ARK_PGBOUNCER_DIR;
  return process.env.ARK_STATE_DIR
    ? join(process.env.ARK_STATE_DIR, "pgbouncer")
    : join(process.cwd(), "tmp", "pgbouncer");
}

export async function applyDatabaseAllowlist(dir: string, cidrs: string[], port = 5432) {
  const rules = nftAllowlist(cidrs, port);
  const file = join(dir, "allowlist.nft");
  await writeFile(file, rules, { mode: 0o600 });
  const requireApply = process.env.ARK_APPLY_NFT === "1" || process.env.ARK_EMBEDDED_WORKERS === "0";
  if (!cidrs.length) {
    if (process.env.ARK_APPLY_NFT === "1") {
      await exec("nft", ["delete", "table", "inet", "ark_db_ingress"], { timeout: 10_000 }).catch(
        () => undefined,
      );
    }
    return { file, applied: true, enforced: false };
  }
  if (process.env.ARK_APPLY_NFT === "0") {
    if (requireApply) throw new Error("Database CIDR allowlist cannot be applied because ARK_APPLY_NFT=0.");
    return { file, applied: false, enforced: false, reason: "disabled" };
  }
  try {
    await exec("nft", ["-f", file], { timeout: 10_000 });
    return { file, applied: true, enforced: true };
  } catch (error) {
    const message = error instanceof Error ? error.message : "nft apply failed";
    if (requireApply)
      throw new Error(`Database CIDR allowlist was not applied: ${message}`, { cause: error });
    return { file, applied: false, enforced: false, reason: message };
  }
}

export async function writePgbouncer(input: {
  mappings: Array<{ database: string; host: string }>;
  users: Array<{ name: string; password: string }>;
}) {
  const dir = pgbouncerDir();
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await writeFile(join(dir, "pgbouncer.ini"), pgbouncerConfig(input), { mode: 0o600 });
  await writeFile(join(dir, "userlist.txt"), pgbouncerUserlist(input.users), { mode: 0o600 });
  if (process.env.ARK_PGBOUNCER_RELOAD === "1") {
    await exec(
      "docker",
      ["kill", "-s", "HUP", process.env.ARK_PGBOUNCER_CONTAINER ?? "ark-platform-pgbouncer-public-1"],
      {
        timeout: 10_000,
      },
    );
  }
  return { dir };
}

export async function writeEdge(input: {
  adminMode: "public" | "tailnet";
  adminHostname?: string;
  appRoutes?: Array<{ hostname: string; upstream: string }>;
}) {
  const dir = process.env.ARK_EDGE_DIR ?? join(process.cwd(), "infra", "platform");
  await mkdir(dir, { recursive: true });
  const caddy = renderCaddyfile({
    adminMode: input.adminMode,
    adminHostname: input.adminHostname,
    challengeDir: process.env.ARK_ACME_WEBROOT ?? join(dir, "acme"),
    apiUpstream: process.env.ARK_API_UPSTREAM ?? "api:3000",
    appRoutes: input.appRoutes,
  });
  const serve = renderTailscaleServe();
  if (!funnelDisabled(serve)) throw new Error("Tailscale Funnel must stay disabled on the admin node.");
  await Bun.write(join(dir, "Caddyfile"), caddy);
  await Bun.write(join(dir, "serve.json"), JSON.stringify(serve, null, 2));
  return { dir, funnel: false };
}

export async function resolveImageDigest(image: string) {
  const { url, accept, host } = registryManifestUrl(image);
  const headers: Record<string, string> = { accept };
  if (process.env.GHCR_TOKEN && host === "ghcr.io") {
    headers.authorization = `Bearer ${process.env.GHCR_TOKEN}`;
  }
  const response = await fetch(url, { method: "HEAD", headers });
  return { image, digest: digestFromHeaders(response.headers), status: response.status };
}

export function scanImport(local: ExternalInventory, incoming: ExternalInventory) {
  return compareInventory(local, incoming);
}
