import { randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import {
  buildStalwartPlan,
  chooseCloudflareMutation,
  cloudflareRecordBody,
  compareInventory,
  digestFromHeaders,
  caddyState,
  CaddyWithdrawalAdapter,
  EDGE_CERT_DIR,
  EDGE_ERRORS_DIR,
  GATE_MAX_STREAM_CLOSE_DELAY_MS,
  edgeCertificatePaths,
  funnelDisabled,
  jmapCall,
  nftAllowlist,
  dbIngressAllowlistEnforced,
  sha256Hex,
  parseBearerChallenge,
  registryManifestUrl,
  renderCaddyfile,
  renderTailscaleServe,
  sesIdentityPlan,
  signAwsRequest,
  stalwartRef,
  type DbIngressLimits,
  type DnsWrite,
  type EdgeAppRoute,
  type EdgeHttpRoute,
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
  if (!created.ok && created.status !== 409)
    throw new Error(`SES identity creation failed: ${created.status}`);
  const mailFromResult = await sesRequest(`/v2/email/identities/${domain}/mail-from-attributes`, "PUT", {
    MailFromDomain: mailFrom,
    BehaviorOnMxFailure: "REJECT_MESSAGE",
  });
  if (!mailFromResult.ok) throw new Error(`SES MAIL FROM configuration failed: ${mailFromResult.status}`);
  const identity = await sesRequest(`/v2/email/identities/${encodeURIComponent(domain)}`);
  if (!identity.ok) throw new Error(`SES identity readback failed: ${identity.status}`);
  const accountBody = JSON.parse(account.body || "{}") as {
    ProductionAccessEnabled?: boolean;
    SendingEnabled?: boolean;
  };
  const identityBody = JSON.parse(identity.body || "{}") as {
    VerifiedForSendingStatus?: boolean;
    DkimAttributes?: { Status?: string; Tokens?: string[] };
    MailFromAttributes?: { MailFromDomainStatus?: string };
  };
  return {
    ...plan,
    account: {
      configured: true,
      production: accountBody.ProductionAccessEnabled === true,
      sending: accountBody.SendingEnabled === true,
    },
    created: created.ok || created.status === 409,
    identity: {
      verified: identityBody.VerifiedForSendingStatus === true,
      dkimStatus: identityBody.DkimAttributes?.Status ?? "unknown",
      dkimTokens: identityBody.DkimAttributes?.Tokens ?? [],
      mailFromStatus: identityBody.MailFromAttributes?.MailFromDomainStatus ?? "unknown",
    },
  };
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

type StalwartRecord = { id: string; name: string; domainId?: string };

async function stalwartMethod(
  url: string,
  authorization: string,
  name: string,
  methodArguments: Record<string, unknown>,
) {
  const response = await fetch(`${url.replace(/\/$/, "")}/jmap`, {
    method: "POST",
    headers: { authorization, "content-type": "application/json" },
    body: JSON.stringify(jmapCall(name, methodArguments)),
  });
  const body = (await response.json().catch(() => null)) as {
    methodResponses?: Array<[string, Record<string, unknown>, string]>;
  } | null;
  const result = body?.methodResponses?.[0];
  if (!response.ok || !result || result[0] === "error" || result[0] !== name) {
    throw new Error(`Stalwart ${name} failed without a complete native result.`);
  }
  return result[1];
}

async function stalwartRecords(url: string, authorization: string, object: string) {
  const queried = await stalwartMethod(url, authorization, `x:${object}/query`, { filter: {} });
  const ids = Array.isArray(queried.ids)
    ? queried.ids.filter((id): id is string => typeof id === "string")
    : [];
  if (!ids.length) return [] as StalwartRecord[];
  const fetched = await stalwartMethod(url, authorization, `x:${object}/get`, { ids });
  const list = Array.isArray(fetched.list) ? fetched.list : [];
  return list.filter(
    (item): item is StalwartRecord =>
      typeof item === "object" &&
      item !== null &&
      typeof (item as StalwartRecord).id === "string" &&
      typeof (item as StalwartRecord).name === "string",
  );
}

async function stalwartSet(
  url: string,
  authorization: string,
  object: string,
  changes: {
    create?: Record<string, Record<string, unknown>>;
    update?: Record<string, Record<string, unknown>>;
    destroy?: string[];
  },
) {
  if (
    !Object.values(changes).some((value) =>
      Array.isArray(value) ? value.length : Object.keys(value ?? {}).length,
    )
  ) {
    return {} as Record<string, { id?: string }>;
  }
  const result = await stalwartMethod(url, authorization, `x:${object}/set`, changes);
  for (const key of ["notCreated", "notUpdated", "notDestroyed"] as const) {
    const failures = result[key];
    if (failures && typeof failures === "object" && Object.keys(failures).length) {
      throw new Error(`Stalwart ${object} reconciliation returned partial ${key} results.`);
    }
  }
  return (result.created ?? {}) as Record<string, { id?: string }>;
}

function splitAddress(address: string) {
  const at = address.lastIndexOf("@");
  if (at <= 0 || at === address.length - 1)
    throw new Error(`Invalid mail address in desired state: ${address}`);
  return { local: address.slice(0, at), domain: address.slice(at + 1) };
}

export async function applyStalwart(planInput: Parameters<typeof buildStalwartPlan>[0]) {
  const built = buildStalwartPlan(planInput);
  const dir = process.env.ARK_MAIL_STATE_DIR ?? join(process.cwd(), "tmp", "mail-state");
  await mkdir(dir, { recursive: true });
  const file = join(dir, "stalwart-plan.ndjson");
  await writeFile(file, built.plan.map((item) => JSON.stringify(item)).join("\n"), { mode: 0o600 });
  const url = process.env.STALWART_URL;
  if (url && process.env.STALWART_ADMIN_ADDRESS && process.env.STALWART_ADMIN_PASSWORD) {
    const authorization = `Basic ${Buffer.from(
      `${process.env.STALWART_ADMIN_ADDRESS}:${process.env.STALWART_ADMIN_PASSWORD}`,
    ).toString("base64")}`;
    const domainRows = await stalwartRecords(url, authorization, "Domain");
    const domainIds = new Map(domainRows.map((item) => [item.name, item.id]));
    const createDomains: Record<string, Record<string, unknown>> = {};
    for (const domain of planInput.domains) {
      const nativeId = domainIds.get(domain.name);
      if (!nativeId) createDomains[stalwartRef("domain", domain.name)] = { name: domain.name };
    }
    const createdDomains = await stalwartSet(url, authorization, "Domain", {
      create: createDomains,
    });
    for (const domain of planInput.domains) {
      const reference = stalwartRef("domain", domain.name);
      const nativeId = domainIds.get(domain.name) ?? createdDomains[reference]?.id;
      if (!nativeId) throw new Error(`Stalwart did not return a native ID for ${domain.name}.`);
      domainIds.set(domain.name, nativeId);
    }

    const accountRows = await stalwartRecords(url, authorization, "Account");
    const accountIds = new Map(
      accountRows.map((item) => [`${item.name}\u0000${item.domainId ?? ""}`, item.id]),
    );
    const createAccounts: Record<string, Record<string, unknown>> = {};
    const updateAccounts: Record<string, Record<string, unknown>> = {};
    const destroyAccounts: string[] = [];
    for (const mailbox of planInput.mailboxes) {
      const address = splitAddress(mailbox.address);
      const domainId = domainIds.get(address.domain);
      if (!domainId) throw new Error(`No native Stalwart domain exists for ${mailbox.address}.`);
      const nativeId = mailbox.nativeId ?? accountIds.get(`${address.local}\u0000${domainId}`);
      if (mailbox.lifecycle === "purged") {
        if (nativeId) destroyAccounts.push(nativeId);
        continue;
      }
      const active =
        mailbox.lifecycle === "active" &&
        planInput.domains.some((domain) => domain.name === address.domain && domain.enabled);
      const value: Record<string, unknown> = {
        description: mailbox.displayName,
        credentials:
          active && mailbox.password
            ? { "0": { "@type": "Password", secret: mailbox.password } }
            : active
              ? undefined
              : {},
      };
      if (nativeId) updateAccounts[nativeId] = value;
      else {
        if (!mailbox.password) throw new Error(`A password is required to create ${mailbox.address}.`);
        createAccounts[stalwartRef("account", mailbox.address)] = {
          "@type": "User",
          name: address.local,
          domainId,
          aliases: {},
          credentials: { "0": { "@type": "Password", secret: mailbox.password } },
          memberGroupIds: {},
          permissions: { "@type": "Inherit" },
          quotas: {},
          roles: { "@type": "User" },
          description: mailbox.displayName,
        };
      }
    }
    const createdAccounts = await stalwartSet(url, authorization, "Account", {
      create: createAccounts,
      update: updateAccounts,
      destroy: destroyAccounts,
    });

    const listRows = await stalwartRecords(url, authorization, "MailingList");
    const listIds = new Map(listRows.map((item) => [`${item.name}\u0000${item.domainId ?? ""}`, item.id]));
    const createLists: Record<string, Record<string, unknown>> = {};
    const updateLists: Record<string, Record<string, unknown>> = {};
    for (const alias of planInput.aliases) {
      const address = splitAddress(alias.address);
      const domainId = domainIds.get(address.domain);
      if (!domainId) throw new Error(`No native Stalwart domain exists for ${alias.address}.`);
      const value = {
        recipients: Object.fromEntries(alias.targets.map((target) => [target, true])),
        aliases: {},
        description: `Managed alias ${alias.address}`,
      };
      const nativeId = listIds.get(`${address.local}\u0000${domainId}`);
      if (nativeId) updateLists[nativeId] = value;
      else {
        createLists[stalwartRef("alias", alias.address)] = {
          name: address.local,
          domainId,
          ...value,
        };
      }
    }
    const createdLists = await stalwartSet(url, authorization, "MailingList", {
      create: createLists,
      update: updateLists,
      destroy: planInput.removedAliases?.map((alias) => alias.nativeId) ?? [],
    });

    const mailboxIds: Record<string, string> = {};
    for (const mailbox of planInput.mailboxes) {
      if (mailbox.lifecycle === "purged") continue;
      const address = splitAddress(mailbox.address);
      const domainId = domainIds.get(address.domain)!;
      const nativeId =
        mailbox.nativeId ??
        accountIds.get(`${address.local}\u0000${domainId}`) ??
        createdAccounts[stalwartRef("account", mailbox.address)]?.id;
      if (!nativeId) throw new Error(`Stalwart did not return a native ID for ${mailbox.address}.`);
      mailboxIds[mailbox.address] = nativeId;
    }
    const aliasIds: Record<string, string> = {};
    for (const alias of planInput.aliases) {
      const address = splitAddress(alias.address);
      const domainId = domainIds.get(address.domain)!;
      const nativeId =
        listIds.get(`${address.local}\u0000${domainId}`) ??
        createdLists[stalwartRef("alias", alias.address)]?.id;
      if (!nativeId) throw new Error(`Stalwart did not return a native ID for ${alias.address}.`);
      aliasIds[alias.address] = nativeId;
    }
    return {
      applied: true,
      outbound: built.outbound,
      file,
      reachable: true,
      nativeIds: { domains: Object.fromEntries(domainIds), mailboxes: mailboxIds, aliases: aliasIds },
    };
  }
  throw new Error("Stalwart management credentials and URL are required for reconciliation.");
}

export async function applyStalwartDevice(input: {
  address: string;
  password: string;
  action: "create" | "revoke";
  label?: string;
  nativeId?: string;
}) {
  const url = process.env.STALWART_URL;
  if (!url) throw new Error("STALWART_URL is required for native device credential changes.");
  if (input.action === "revoke" && !input.nativeId) {
    throw new Error("A native Stalwart app-password ID is required for revocation.");
  }
  const jmapArguments =
    input.action === "create"
      ? {
          create: {
            device: {
              description: input.label,
              allowedIps: {},
              permissions: { "@type": "Inherit" },
            },
          },
        }
      : { destroy: [input.nativeId] };
  const response = await fetch(`${url.replace(/\/$/, "")}/jmap`, {
    method: "POST",
    headers: {
      authorization: `Basic ${Buffer.from(`${input.address}:${input.password}`).toString("base64")}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(jmapCall("x:AppPassword/set", jmapArguments)),
  });
  const body = (await response.json().catch(() => null)) as {
    methodResponses?: Array<
      [
        string,
        {
          created?: Record<string, { id?: string; secret?: string }>;
          notCreated?: Record<string, unknown>;
          destroyed?: string[];
          notDestroyed?: Record<string, unknown>;
        },
        string,
      ]
    >;
  } | null;
  const result = body?.methodResponses?.[0];
  if (!response.ok || !result || result[0] === "error") {
    throw new Error(`Stalwart app-password ${input.action} failed.`);
  }
  const value = result[1];
  if (input.action === "create") {
    const created = value.created?.device;
    if (!created?.id || !created.secret || Object.keys(value.notCreated ?? {}).length) {
      throw new Error("Stalwart did not return a native ID and one-time app-password secret.");
    }
    return { nativeId: created.id, secret: created.secret };
  }
  if (!value.destroyed?.includes(input.nativeId!) || Object.keys(value.notDestroyed ?? {}).length) {
    throw new Error("Stalwart did not confirm app-password revocation.");
  }
  return { nativeId: input.nativeId!, revoked: true as const };
}

export function pgbouncerDir() {
  if (process.env.ARK_PGBOUNCER_DIR) return process.env.ARK_PGBOUNCER_DIR;
  return process.env.ARK_STATE_DIR
    ? join(process.env.ARK_STATE_DIR, "pgbouncer")
    : join(process.cwd(), "tmp", "pgbouncer");
}

/**
 * Where the host-namespace `database-ingress` reconciler writes its nft drop counter snapshot
 * (front door §3.11, FD-18). The API reads it for /api/metrics/prometheus.
 */
export function dbIngressCountersFile() {
  if (process.env.ARK_DB_INGRESS_METRICS_DIR) {
    return join(process.env.ARK_DB_INGRESS_METRICS_DIR, "counters.json");
  }
  return process.env.ARK_STATE_DIR
    ? join(process.env.ARK_STATE_DIR, "db-ingress", "counters.json")
    : join(process.cwd(), "tmp", "db-ingress", "counters.json");
}

/**
 * Writes the tcp/5432 nft policy (`ark_db_ingress`, FD-18: per-source limits) for the host-namespace
 * `database-ingress` reconciler and waits for its acknowledgement of these exact bytes. Since FD-26 the
 * reconciler no longer relays 5432 (HAProxy's `fe_pg5432` owns it), so there is no exposure toggle
 * here: whether PgBouncer is reachable is decided by rendering `be_pgbouncer` at the edge.
 */
export async function applyDatabaseAllowlist(
  dir: string,
  cidrs: string[],
  port = 5432,
  options: { limits?: DbIngressLimits } = {},
) {
  const file = join(dir, "allowlist.nft");
  const previousRules = await readFile(file, "utf8").catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return "";
    throw error;
  });
  const rules = nftAllowlist(cidrs, port, options.limits, previousRules);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  // Publish complete policies atomically: the host watcher must never load a partial write.
  const temporary = `${file}.${crypto.randomUUID()}.tmp`;
  await writeFile(temporary, rules, { mode: 0o600 });
  await rename(temporary, file);
  const requireApply = process.env.ARK_APPLY_NFT === "1" || process.env.ARK_EMBEDDED_WORKERS === "0";
  const helper = process.env.ARK_ALLOWLIST_HELPER;
  try {
    if (helper) {
      await exec(helper, [file], { timeout: 20_000 });
      return { file, applied: true, enforced: dbIngressAllowlistEnforced(rules) };
    }
    // An empty allowlist installs per-source limits without CIDR allowlist jumps. The
    // reconcilers read the table back and treat a missing table as a failed apply.
    if (process.env.ARK_APPLY_NFT === "0") {
      if (requireApply) throw new Error("Database ingress policy cannot be applied because ARK_APPLY_NFT=0.");
      return { file, applied: false, enforced: false, reason: "disabled" };
    }
    // External workers have no host NET_ADMIN. The host reconciler acknowledges the exact
    // policy bytes; an older success must never satisfy a new reload/upgrade.
    if (process.env.ARK_EMBEDDED_WORKERS === "0") {
      const expectedHash = sha256Hex(rules);
      let lastStatus = "No acknowledgement from database-ingress.";
      for (let attempt = 0; attempt < 150; attempt++) {
        const status = await readFile(join(dir, "allowlist.status"), "utf8").catch(() => "");
        if (status.includes(`policy_hash=${expectedHash}\n`)) {
          if (status.includes("applied=true\n")) {
            return { file, applied: true, enforced: dbIngressAllowlistEnforced(rules) };
          }
          lastStatus = status.split("error=")[1]?.trim() || "Requested policy is not ready.";
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      throw new Error(`database-ingress did not acknowledge the requested policy: ${lastStatus}`);
    }
    await exec("nft", ["-f", file], { timeout: 10_000 });
    await exec("nft", ["list", "table", "inet", "ark_db_ingress"], { timeout: 10_000 });
    return { file, applied: true, enforced: dbIngressAllowlistEnforced(rules) };
  } catch (error) {
    const message = error instanceof Error ? error.message : "nft apply failed";
    if (requireApply)
      throw new Error(`Database ingress policy was not applied: ${message}`, {
        cause: error,
      });
    return { file, applied: false, enforced: false, reason: message };
  }
}

/**
 * Applies a Caddyfile through Caddy's admin API: `/adapt` first, so a rejected candidate never
 * reaches `/load`, then `/load` of the adapted JSON with `Cache-Control: must-revalidate`. Without
 * that header Caddy skips a `/load` whose config is unchanged, so renewed certificate files at the
 * same paths would never be re-read (docs/design/front-door.md §3.14).
 */
export async function loadCaddyfile(adminUrl: string, caddyfile: string) {
  const base = adminUrl.replace(/\/$/, "");
  const adapted = await fetch(`${base}/adapt`, {
    method: "POST",
    headers: { "content-type": "text/caddyfile" },
    body: caddyfile,
  });
  if (!adapted.ok) throw new Error(`Caddy rejected candidate configuration: ${adapted.status}`);
  // /adapt answers `{ result, warnings }`; only `result` is a Caddy config that /load accepts.
  const { result } = (await adapted.json()) as { result?: unknown };
  if (!result || typeof result !== "object") throw new Error("Caddy /adapt returned no configuration.");
  const loaded = await fetch(`${base}/load`, {
    method: "POST",
    headers: { "content-type": "application/json", "cache-control": "must-revalidate" },
    body: JSON.stringify(result),
  });
  if (!loaded.ok) throw new Error(`Caddy reload failed: ${loaded.status}`);
}

export async function writeEdge(input: {
  adminMode: "public" | "tailnet";
  adminHostname?: string;
  /** The public gate login origin (front door §3.5, FD-10); rendered once its certificate is issued. */
  gateHostname?: string;
  /** The current certificate status per hostname; only `issued` hostnames are served. */
  certificates?: Array<{ hostname: string; status: string }>;
  appRoutes?: EdgeAppRoute[];
  /** Front-door HTTP routes allowed by the current lease and servable (front door §3.2, §3.5). */
  httpRoutes?: EdgeHttpRoute[];
  /**
   * Routes with a pending gate revocation (FD-11, §3.9.3). This /load is their forced reload; if a
   * route's active handler keeps upgraded streams longer than 5m (a public route just switched to
   * SSO), Caddy is stopped after the reload as for a removed route.
   */
  revokedRouteIds?: string[];
}) {
  const dir = process.env.ARK_EDGE_DIR ?? join(process.cwd(), "infra", "platform");
  await mkdir(dir, { recursive: true });
  const generation = randomUUID();
  const render = (httpRoutes: EdgeHttpRoute[]) =>
    renderCaddyfile({
      generation,
      adminMode: input.adminMode,
      adminHostname: input.adminHostname,
      challengeDir: process.env.ARK_ACME_WEBROOT ?? join(dir, "acme"),
      apiUpstream: process.env.ARK_API_UPSTREAM ?? "api:3000",
      gate: input.gateHostname ? { hostname: input.gateHostname } : undefined,
      // Paths inside the edge container, which mounts the certificate directory read-only.
      certificates: (input.certificates ?? []).map((item) => ({
        ...item,
        ...edgeCertificatePaths(item.hostname, EDGE_CERT_DIR),
      })),
      appRoutes: input.appRoutes,
      httpRoutes,
      // Static 502/503/504 pages: the edge container mounts infra/platform/edge-errors there (FD-09).
      errorsDir: EDGE_ERRORS_DIR,
    });
  const caddy = render(input.httpRoutes ?? []);
  // The closed variant renders no front-door route. The Caddy launch guard starts from it whenever the
  // edge watchdog does not confirm a valid lease for every tailnet backend in `Caddyfile` (§3.2).
  const closed = render([]);
  const serve = renderTailscaleServe();
  if (!funnelDisabled(serve)) throw new Error("Tailscale Funnel must stay disabled on the admin node.");
  const caddyPath = join(dir, "Caddyfile");
  const nextCaddy = `${caddyPath}.next`;
  const closedPath = join(dir, "Caddyfile.closed");
  const nextClosed = `${closedPath}.next`;
  const servePath = join(dir, "serve.json");
  const nextServe = `${servePath}.next`;
  await writeFile(nextCaddy, caddy, { mode: 0o600 });
  await writeFile(nextClosed, closed, { mode: 0o600 });
  await writeFile(nextServe, JSON.stringify(serve, null, 2), { mode: 0o600 });
  const reloadUrl = process.env.ARK_EDGE_RELOAD_URL;
  let applied = false;
  let lingering: string[] = [];
  const state = caddyState(dir);
  const adapter = reloadUrl ? new CaddyWithdrawalAdapter(reloadUrl, fetch, 3_000, state) : null;
  if (reloadUrl) {
    // A prior apply may have loaded/renamed its files but failed to stop the old streams.
    // Retry that durable stop before inspection can mistake the new config for an empty census.
    const pending = await state.pendingStreams();
    if (pending.length) {
      await adapter!.stopForStreams();
      throw new Error("Caddy is restarting after a pending stream stop; retry edge.apply.");
    }
    const next = new Set(
      [...caddy.matchAll(/^\s*vars ark_tailnet_route (\S+)\s*$/gm)].map((match) => match[1]!),
    );
    // An unreadable config is unknown, never evidence of absent streams. Abort before /load.
    lingering = await adapter!.lingeringStreams(
      next,
      input.revokedRouteIds?.length
        ? { routeIds: new Set(input.revokedRouteIds), maxMs: GATE_MAX_STREAM_CLOSE_DELAY_MS }
        : null,
    );
    if (lingering.length) await adapter!.markPendingStreams(lingering);
    await loadCaddyfile(reloadUrl, caddy);
    applied = true;
  } else if (process.env.NODE_ENV === "production") {
    throw new Error("ARK_EDGE_RELOAD_URL is required to apply gateway changes in production.");
  }
  await rename(nextClosed, closedPath);
  await rename(nextCaddy, caddyPath);
  await rename(nextServe, servePath);
  await chmod(caddyPath, 0o600);
  // A removed route must not keep serving through open WebSockets: stop Caddy once the new files are
  // in place, so its launch guard restarts it from them (front door §3.2, §3.5). The marker tells
  // the edge watchdog that the restart is expected, not a failed withdrawal.
  if (reloadUrl && lingering.length) {
    await adapter!.stopForStreams();
  }
  return {
    dir,
    funnel: false,
    applied,
    httpRoutes: (input.httpRoutes ?? []).map((route) => route.id),
    ...(lingering.length ? { stoppedForStreams: lingering } : {}),
  };
}

export async function resolveImageDigest(image: string) {
  const { url, accept, host } = registryManifestUrl(image);
  const headers: Record<string, string> = { accept };
  if (process.env.GHCR_TOKEN && host === "ghcr.io") {
    headers.authorization = `Bearer ${process.env.GHCR_TOKEN}`;
  }
  let response = await fetch(url, { headers });
  if (response.status === 401) {
    const challenge = parseBearerChallenge(response.headers.get("www-authenticate"));
    if (!challenge) throw new Error(`Registry ${host} returned an unsupported authentication challenge.`);
    const tokenUrl = new URL(challenge.realm);
    if (challenge.service) tokenUrl.searchParams.set("service", challenge.service);
    if (challenge.scope) tokenUrl.searchParams.set("scope", challenge.scope);
    const tokenResponse = await fetch(tokenUrl, {
      headers: process.env.ARK_REGISTRY_USERNAME
        ? {
            authorization: `Basic ${Buffer.from(`${process.env.ARK_REGISTRY_USERNAME}:${process.env.ARK_REGISTRY_PASSWORD ?? ""}`).toString("base64")}`,
          }
        : {},
    });
    if (!tokenResponse.ok) throw new Error(`Registry token request failed: ${tokenResponse.status}`);
    const tokenBody = (await tokenResponse.json()) as { token?: string; access_token?: string };
    const token = tokenBody.token ?? tokenBody.access_token;
    if (!token) throw new Error("Registry token response did not contain a bearer token.");
    headers.authorization = `Bearer ${token}`;
    response = await fetch(url, { headers });
  }
  if (!response.ok) throw new Error(`Registry manifest request failed: ${response.status}`);
  let digest = digestFromHeaders(response.headers);
  const contentType = response.headers.get("content-type") ?? "";
  const body = (await response.json().catch(() => null)) as {
    manifests?: Array<{ digest: string; platform?: { architecture?: string; os?: string } }>;
  } | null;
  if (contentType.includes("manifest.list") || contentType.includes("image.index")) {
    const architecture = process.arch === "x64" ? "amd64" : process.arch;
    const selected = body?.manifests?.find(
      (item) => item.platform?.os === "linux" && item.platform.architecture === architecture,
    );
    if (!selected) throw new Error(`Registry index has no linux/${architecture} manifest.`);
    const selectedResponse = await fetch(
      url.replace(/\/manifests\/[^/]+$/, `/manifests/${selected.digest}`),
      {
        headers,
      },
    );
    if (!selectedResponse.ok) throw new Error(`Platform manifest request failed: ${selectedResponse.status}`);
    digest = digestFromHeaders(selectedResponse.headers) ?? selected.digest;
  }
  if (!digest?.startsWith("sha256:")) throw new Error("Registry did not return an immutable content digest.");
  return { image, digest, status: response.status };
}

export function scanImport(local: ExternalInventory, incoming: ExternalInventory) {
  return compareInventory(local, incoming);
}
