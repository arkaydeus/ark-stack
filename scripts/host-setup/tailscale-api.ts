// The Tailscale API key source for the guided setup (part 2 of the automated installer).
//
// With one API credential (an API access token, or an OAuth client with the `policy_file` and
// `auth_keys` scopes), setup merges the Ark entries into the tailnet policy after showing the diff
// and getting a yes, then mints one single-use, pre-approved, one-hour key per node and revokes it
// once the node has joined. Without a credential the manual source (tailscale-keys.ts) is used.
//
// The credential, the OAuth access token and every minted key live only in this process's memory:
// they are registered with the redactor, never written to disk, `.env`, the state file or the log,
// and never passed to a child process except the one key a node needs, on stdin or in its env.
import { ARK_BACKUP_TAG, ARK_EDGE_TAG, ARK_VPS_TAG } from "@ark-stack/shared";

import type { Ui } from "./system.ts";
import { lineDiff, mergeArkPolicy } from "./tailnet-policy.ts";
import {
  manualKeySource,
  tailnetPolicyInstructions,
  type AcquiredKey,
  type KeyRequest,
  type TailscaleKeySource,
} from "./tailscale-keys.ts";

export const TAILSCALE_API = "https://api.tailscale.com";
/** The tag an OAuth client carries; it owns the Ark tags so the client may mint their keys. */
export const DEFAULT_OAUTH_TAG = "tag:ark-setup";
/** Minted keys expire within the hour even if setup is interrupted before revoking them. */
export const KEY_EXPIRY_SECONDS = 3600;

export type TailscaleCredential =
  | { kind: "access-token"; token: string }
  | { kind: "oauth"; clientId: string; clientSecret: string; tag: string };

const ACCESS_TOKEN = /^tskey-api-[A-Za-z0-9-]+$/;
const CLIENT_SECRET = /^tskey-client-[A-Za-z0-9-]+$/;
const TAG = /^tag:[a-z0-9][a-z0-9-]*$/i;

/** The credential named in the environment (never a flag: flags show up in the process list). */
export function credentialFromEnv(env: Record<string, string | undefined>): TailscaleCredential | undefined {
  const token = env.TS_API_KEY?.trim();
  const secret = env.TS_OAUTH_CLIENT_SECRET?.trim();
  if (token && secret) throw new Error("Give only one of TS_API_KEY and TS_OAUTH_CLIENT_SECRET.");
  if (token) {
    if (!ACCESS_TOKEN.test(token))
      throw new Error("TS_API_KEY must be a Tailscale API access token (tskey-api-…).");
    return { kind: "access-token", token };
  }
  if (secret) return oauthCredential(secret, env.TS_OAUTH_CLIENT_ID, env.TS_OAUTH_TAG);
  return undefined;
}

function oauthCredential(secret: string, id?: string, tag?: string): TailscaleCredential {
  if (!CLIENT_SECRET.test(secret))
    throw new Error("TS_OAUTH_CLIENT_SECRET must be a Tailscale OAuth client secret (tskey-client-…).");
  // The secret embeds the client ID: tskey-client-<id>-<secret>.
  const clientId = id?.trim() || /^tskey-client-([A-Za-z0-9]+)-/.exec(secret)?.[1];
  if (!clientId) throw new Error("Set TS_OAUTH_CLIENT_ID to the OAuth client's ID.");
  const clientTag = tag?.trim() || DEFAULT_OAUTH_TAG;
  if (!TAG.test(clientTag)) throw new Error("TS_OAUTH_TAG must be a tag such as tag:ark-setup.");
  return { kind: "oauth", clientId, clientSecret: secret, tag: clientTag };
}

export type ApiOptions = {
  base?: string;
  tailnet?: string;
  fetch?: typeof fetch;
  /** Registers a value with the redactor. */
  secret: (value: string) => void;
  log: (line: string) => void;
};

type ApiResponse = { status: number; headers: Headers; text: string };

export class TailscaleApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

/** A minimal Tailscale API v2 client. Request and response bodies are never logged. */
export class TailscaleApi {
  readonly base: string;
  readonly tailnet: string;
  private bearer?: { token: string; expires: number };
  private fetcher: typeof fetch;

  constructor(
    private credential: TailscaleCredential,
    private options: ApiOptions,
  ) {
    this.base = (options.base ?? TAILSCALE_API).replace(/\/$/, "");
    this.tailnet = options.tailnet?.trim() || "-";
    this.fetcher = options.fetch ?? fetch;
    if (credential.kind === "access-token") options.secret(credential.token);
    else options.secret(credential.clientSecret);
  }

  private async authorization() {
    if (this.credential.kind === "access-token") return `Bearer ${this.credential.token}`;
    if (this.bearer && this.bearer.expires > Date.now() + 60_000) return `Bearer ${this.bearer.token}`;
    const response = await this.fetcher(`${this.base}/api/v2/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({
        client_id: this.credential.clientId,
        client_secret: this.credential.clientSecret,
        grant_type: "client_credentials",
      }),
      signal: AbortSignal.timeout(30_000),
    });
    this.options.log(`Tailscale API POST /api/v2/oauth/token -> ${response.status}`);
    const body = (await response.json().catch(() => ({}))) as { access_token?: string; expires_in?: number };
    if (!response.ok || !body.access_token) {
      throw new TailscaleApiError(
        `Tailscale refused the OAuth client (HTTP ${response.status}). Check TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET.`,
        response.status,
      );
    }
    this.options.secret(body.access_token);
    this.bearer = { token: body.access_token, expires: Date.now() + (body.expires_in ?? 3600) * 1000 };
    return `Bearer ${body.access_token}`;
  }

  async request(
    method: string,
    path: string,
    init: { body?: string; contentType?: string; accept?: string; headers?: Record<string, string> } = {},
  ): Promise<ApiResponse> {
    const url = `${this.base}/api/v2/tailnet/${encodeURIComponent(this.tailnet)}${path}`;
    const response = await this.fetcher(url, {
      method,
      headers: {
        authorization: await this.authorization(),
        accept: init.accept ?? "application/json",
        ...(init.contentType ? { "content-type": init.contentType } : {}),
        ...init.headers,
      },
      body: init.body,
      signal: AbortSignal.timeout(30_000),
    });
    this.options.log(`Tailscale API ${method} /api/v2/tailnet/${this.tailnet}${path} -> ${response.status}`);
    return { status: response.status, headers: response.headers, text: await response.text() };
  }

  private fail(what: string, response: ApiResponse, hint = ""): never {
    let message = "";
    try {
      message = (JSON.parse(response.text) as { message?: string }).message ?? "";
    } catch {
      message = response.text.slice(0, 200);
    }
    const scopes =
      response.status === 401 || response.status === 403
        ? ` The credential needs ${this.credential.kind === "oauth" ? "the policy_file and auth_keys scopes" : "an admin's API access token"}.`
        : "";
    throw new TailscaleApiError(
      `Tailscale API: ${what} failed (HTTP ${response.status}${message ? `: ${message}` : ""}).${scopes}${hint}`,
      response.status,
    );
  }

  async getPolicy() {
    const response = await this.request("GET", "/acl", { accept: "application/hujson" });
    if (response.status !== 200) this.fail("reading the tailnet policy", response);
    const etag = response.headers.get("etag");
    if (!etag)
      throw new Error("Tailscale API: the tailnet policy has no ETag, so it cannot be updated safely.");
    return { text: response.text, etag };
  }

  /** Returns a problem description, or undefined when Tailscale accepts the policy and its tests. */
  async validatePolicy(text: string) {
    const response = await this.request("POST", "/acl/validate", {
      body: text,
      contentType: "application/hujson",
    });
    let parsed: { message?: string; data?: unknown } = {};
    try {
      parsed = response.text.trim() ? (JSON.parse(response.text) as typeof parsed) : {};
    } catch {
      parsed = { message: response.text.slice(0, 200) };
    }
    if (response.status === 200 && !parsed.message && !parsed.data) return undefined;
    if (response.status === 401 || response.status === 403)
      this.fail("validating the tailnet policy", response);
    return `${parsed.message ?? `HTTP ${response.status}`}${parsed.data ? ` ${JSON.stringify(parsed.data)}` : ""}`;
  }

  async setPolicy(text: string, etag: string) {
    const response = await this.request("POST", "/acl", {
      body: text,
      contentType: "application/hujson",
      accept: "application/hujson",
      headers: { "if-match": etag },
    });
    if (response.status === 412) {
      throw new Error(
        "The tailnet policy changed while setup was showing it; nothing was applied. Re-run host:setup to review the new version.",
      );
    }
    if (response.status !== 200) this.fail("updating the tailnet policy", response);
  }

  async createKey(tag: string, description: string) {
    const response = await this.request("POST", "/keys", {
      contentType: "application/json",
      body: JSON.stringify({
        description,
        capabilities: {
          devices: { create: { reusable: false, ephemeral: false, preauthorized: true, tags: [tag] } },
        },
        expirySeconds: KEY_EXPIRY_SECONDS,
      }),
    });
    if (response.status !== 200) {
      this.fail(
        `creating a ${tag} auth key`,
        response,
        this.credential.kind === "oauth"
          ? ` The OAuth client must carry ${this.credential.tag}, which the policy makes an owner of ${tag}.`
          : "",
      );
    }
    const body = JSON.parse(response.text) as { id?: string; key?: string };
    if (!body.id || !body.key || !/^tskey-[A-Za-z0-9-]+$/.test(body.key))
      throw new Error(`Tailscale API: the new ${tag} key is malformed.`);
    this.options.secret(body.key);
    return { id: body.id, key: body.key };
  }

  async deleteKey(id: string) {
    const response = await this.request("DELETE", `/keys/${encodeURIComponent(id)}`);
    if (response.status !== 200 && response.status !== 204 && response.status !== 404)
      this.fail(`revoking key ${id}`, response);
  }
}

export type ApiKeySourceOptions = {
  ui: Ui;
  interactive: boolean;
  /** --approve-tailnet-policy: apply a policy change without asking (scripted installs). */
  approve: boolean;
  /** Also declare tag:ark-backup (the optional backup node). */
  backup: boolean;
};

/** Mints the keys through the Tailscale API after merging the Ark entries into the policy. */
export function apiKeySource(
  api: TailscaleApi,
  credential: TailscaleCredential,
  options: ApiKeySourceOptions,
) {
  const { ui } = options;
  const tags = [ARK_VPS_TAG, ARK_EDGE_TAG, ...(options.backup ? [ARK_BACKUP_TAG] : [])];
  let prepared: Promise<void> | undefined;

  async function preparePolicy() {
    const current = await api.getPolicy();
    const merge = mergeArkPolicy(current.text, {
      tags,
      owners: ["autogroup:admin"],
      requiredOwner: credential.kind === "oauth" ? credential.tag : undefined,
    });
    for (const warning of merge.warnings) ui.print(`      Warning: ${warning}`);
    if (!merge.changed) {
      ui.print(`      The tailnet policy already has the Ark tag owners and the owner SSH rule.`);
      return;
    }
    ui.print("      Proposed tailnet policy change (only Ark entries are added; nothing else changes):");
    for (const line of merge.additions) ui.print(`        - ${line}`);
    ui.print("");
    for (const line of lineDiff(current.text, merge.text)) ui.print(`        ${line}`);
    ui.print("");
    const problem = await api.validatePolicy(merge.text);
    if (problem) throw new Error(`Tailscale rejected the merged policy, so nothing was applied: ${problem}`);
    ui.print("      Tailscale validated the merged policy.");
    let approved = options.approve;
    if (!approved && options.interactive) {
      const answer = await ui.ask("Apply this change to the tailnet policy? (yes/no)", "");
      approved = /^y(?:es)?$/i.test(answer.trim());
    }
    if (!approved) {
      throw new Error(
        options.interactive
          ? "The tailnet policy change was declined, so nothing was applied. Re-run host:setup to review it again, or run it without a Tailscale credential to make the change by hand."
          : "The tailnet policy needs the change shown above. Re-run with --approve-tailnet-policy to apply it, or interactively to review it.",
      );
    }
    await api.setPolicy(merge.text, current.etag);
    ui.print("      Tailnet policy updated.");
  }

  const source: TailscaleKeySource = {
    id: "tailscale-api",
    policyInstructions: () => tailnetPolicyInstructions({ backup: options.backup }),
    preparePolicy() {
      // Once per run; a failure is retried by the next call (the next run).
      prepared ??= preparePolicy().catch((error: unknown) => {
        prepared = undefined;
        throw error;
      });
      return prepared;
    },
    async acquire(request: KeyRequest): Promise<AcquiredKey> {
      await source.preparePolicy!();
      const minted = await api.createKey(request.tag, `ark-stack setup ${request.tag.slice(4)}`);
      ui.print(
        `      Minted a one-off ${request.tag} key through the Tailscale API (pre-approved, expires in one hour).`,
      );
      let released = false;
      return {
        key: minted.key,
        inMemoryOnly: true,
        release: async () => {
          if (released) return;
          released = true;
          try {
            await api.deleteKey(minted.id);
            ui.print(`      Revoked the ${request.tag} key.`);
          } catch (error) {
            ui.print(
              `      Could not revoke the ${request.tag} key (${error instanceof Error ? error.message : String(error)}). It expires within the hour; revoke it under Settings > Keys.`,
            );
          }
        },
      };
    },
  };
  return source;
}

export type AutomaticKeySourceOptions = {
  env: Record<string, string | undefined>;
  ui: Ui;
  interactive: boolean;
  approve: boolean;
  backup: boolean;
  secret: (value: string) => void;
  log: (line: string) => void;
  apiBase?: string;
  fetch?: typeof fetch;
};

/**
 * The default key source. A key given in the environment for a request wins; otherwise a Tailscale
 * API credential (environment, or asked once when a key is first needed) selects the API source,
 * and no credential keeps part 1's manual flow.
 */
export function automaticKeySource(options: AutomaticKeySourceOptions): TailscaleKeySource {
  const { env, ui, interactive } = options;
  const manual = manualKeySource({ env, ui, interactive, backup: options.backup });
  let chosen: Promise<TailscaleKeySource> | undefined;

  async function choose(): Promise<TailscaleKeySource> {
    let credential = credentialFromEnv(env);
    if (!credential && interactive) {
      for (;;) {
        const value = (
          await ui.askSecret(
            "Tailscale API access token (tskey-api-…) or OAuth client secret (tskey-client-…) to set up the policy and keys automatically (Enter for the manual steps)",
          )
        ).trim();
        if (!value) break;
        try {
          if (ACCESS_TOKEN.test(value)) credential = { kind: "access-token", token: value };
          else if (CLIENT_SECRET.test(value)) {
            options.secret(value);
            const derived = /^tskey-client-([A-Za-z0-9]+)-/.exec(value)?.[1];
            const id = env.TS_OAUTH_CLIENT_ID?.trim() || derived || (await ui.ask("OAuth client ID", ""));
            credential = oauthCredential(value, id, env.TS_OAUTH_TAG);
          } else throw new Error("That is neither an API access token nor an OAuth client secret.");
          break;
        } catch (error) {
          ui.print(`  ${error instanceof Error ? error.message : String(error)}`);
        }
      }
    }
    if (!credential) return manual;
    const api = new TailscaleApi(credential, {
      base: options.apiBase ?? env.ARK_SETUP_TS_API_URL,
      tailnet: env.TS_TAILNET,
      fetch: options.fetch,
      secret: options.secret,
      log: options.log,
    });
    ui.print(
      `      Using the Tailscale API (${credential.kind === "oauth" ? "OAuth client" : "API access token"}, tailnet ${api.tailnet}); the credential stays in memory.`,
    );
    return apiKeySource(api, credential, options);
  }
  const resolve = () => (chosen ??= choose());

  const source: TailscaleKeySource = {
    id: "automatic",
    policyInstructions: () => tailnetPolicyInstructions({ backup: options.backup }),
    async preparePolicy() {
      const selected = await resolve();
      if (selected.preparePolicy) return selected.preparePolicy();
      for (const line of selected.policyInstructions()) ui.print(`      ${line}`);
      if (interactive) await ui.ask("Press Enter once the policy is saved", "");
    },
    async acquire(request) {
      // An explicitly supplied key (or key file) is used as given.
      if (env[request.variable]?.trim() || (request.tag === ARK_VPS_TAG && env.TS_VPS_AUTHKEY_FILE?.trim()))
        return manual.acquire(request);
      return (await resolve()).acquire(request);
    },
  };
  return source;
}
