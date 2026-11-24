// The Tailscale API key source for the guided setup (part 2 of the automated installer).
//
// With one API credential, setup checks the tailnet policy for a catch-all rule (policy-gate.ts), merges
// the Ark entries into it after showing the added lines and getting a yes, then mints one single-use, pre-approved, one-hour key per node and revokes it
// once the node has joined. Without a credential the manual source (tailscale-keys.ts) is used.
//
// The credential, the OAuth access token and every minted key live only in this process's memory:
// they are registered with the redactor, never written to disk, `.env`, the state file or the log,
// and only the one key a node needs is passed to its enrolment process, on stdin.
import { ARK_BACKUP_TAG, ARK_EDGE_TAG, ARK_VPS_TAG } from "@ark-stack/shared";
import { createHash } from "node:crypto";

import type { PolicyGate } from "./policy-gate.ts";
import type { Ui } from "./system.ts";
import { mergeArkPolicy, type EnrolledTag } from "./tailnet-policy.ts";
import {
  manualKeySource,
  tailnetPolicyInstructions,
  type AcquiredKey,
  type KeyRequest,
  type PolicyPreparation,
  type TailscaleKeySource,
} from "./tailscale-keys.ts";

export const TAILSCALE_API = "https://api.tailscale.com";
/** The tag an OAuth client carries; it owns the Ark tags so the client may mint their keys. */
export const DEFAULT_OAUTH_TAG = "tag:ark-setup";
/** Minted keys expire within the hour even if setup is interrupted before revoking them. */
export const KEY_EXPIRY_SECONDS = 3600;
const SETUP_OAUTH_SCOPES = ["policy_file", "devices:posture_attributes", "devices:core:read", "auth_keys"];

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
        scope: SETUP_OAUTH_SCOPES.join(" "),
      }),
      signal: AbortSignal.timeout(30_000),
    });
    this.options.log(`Tailscale API POST /api/v2/oauth/token -> ${response.status}`);
    const body = (await response.json().catch(() => ({}))) as { access_token?: string; expires_in?: number };
    if (!response.ok || !body.access_token) {
      throw new TailscaleApiError(
        `Tailscale refused the OAuth client (HTTP ${response.status}). Check TS_OAUTH_CLIENT_ID, TS_OAUTH_CLIENT_SECRET and the scopes ${SETUP_OAUTH_SCOPES.join(", ")}.`,
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
    const scopes =
      response.status === 401 || response.status === 403
        ? ` The credential needs ${this.credential.kind === "oauth" ? `the OAuth scopes ${SETUP_OAUTH_SCOPES.join(", ")}` : "an admin's API access token"}.`
        : "";
    throw new TailscaleApiError(
      `Tailscale API: ${what} failed (HTTP ${response.status}).${scopes}${hint}`,
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

  /** Throws a generic diagnostic if Tailscale rejects the policy or its tests. */
  async validatePolicy(text: string) {
    const response = await this.request("POST", "/acl/validate", {
      body: text,
      contentType: "application/hujson",
    });
    if (response.status === 401 || response.status === 403)
      this.fail("validating the tailnet policy", response);
    // Tailscale can return policy-test diagnostics in a successful HTTP response.
    let parsed: { message?: string; data?: unknown } | null = null;
    try {
      parsed = response.text.trim() ? (JSON.parse(response.text) as typeof parsed) : {};
    } catch {
      // A non-JSON response is also unverified.
    }
    if (response.status === 200 && parsed && !parsed.message && !parsed.data) return;
    throw new TailscaleApiError(
      `Tailscale rejected the merged policy or its tests (HTTP ${response.status}). Nothing was applied. Review the policy and its tests in Access controls, then rerun setup.`,
      response.status,
    );
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
  gate: PolicyGate;
  interactive: boolean;
  /** Explicit non-interactive mode plus --approve-tailnet-policy or its environment equivalent. */
  approve: boolean;
  /** Also declare tag:ark-backup (the optional backup node). */
  backup: boolean;
  sleep?: (ms: number) => Promise<void>;
};

/** Mints the keys through the Tailscale API after merging the Ark entries into the policy. */
export function apiKeySource(
  api: TailscaleApi,
  credential: TailscaleCredential,
  options: ApiKeySourceOptions,
) {
  const { ui } = options;
  const tags = [ARK_VPS_TAG, ARK_EDGE_TAG, ...(options.backup ? [ARK_BACKUP_TAG] : [])];
  // A successful read verifies an explicit Tailnet ID. Aliases such as "-" can only be
  // tied to this API source for the current run.
  const scope = /^T[A-Za-z0-9]+CNTRL$/.test(api.tailnet)
    ? createHash("sha256")
        .update(JSON.stringify([api.base, api.tailnet]))
        .digest("hex")
    : Symbol("tailnet");

  async function preparePolicy(pending: EnrolledTag[]) {
    const current = await api.getPolicy();
    let merge: ReturnType<typeof mergeArkPolicy>;
    try {
      merge = mergeArkPolicy(current.text, {
        tags,
        owners: ["autogroup:admin"],
        requiredOwner: credential.kind === "oauth" ? credential.tag : undefined,
      });
    } catch (error) {
      if (error instanceof SyntaxError) {
        // Native JSON parser errors can quote the policy.
        // oxlint-disable-next-line eslint/preserve-caught-error -- The original error can contain private policy text.
        throw new Error(
          "Tailscale returned an invalid policy. Review it in Access controls, then rerun setup.",
        );
      }
      throw error;
    }
    // Before the policy changes, a key is minted or a node enrolled.
    await options.gate.found(merge.catchAll, pending, scope);
    if (!merge.changed) {
      options.gate.policyWriteDeferred(false);
      ui.print(`      The tailnet policy already has the Ark tag owners and the owner SSH rule.`);
      return;
    }
    ui.print("      Proposed tailnet policy change (only Ark entries are added; nothing else changes):");
    for (const line of merge.additions) ui.print(`        - ${line}`);
    ui.print("");
    for (const line of merge.inserted) ui.print(`        ${line}`);
    ui.print("");
    let approved = options.approve;
    if (options.interactive) {
      const answer = await ui.ask("Apply this change to the tailnet policy? (yes/no)", "");
      approved = /^y(?:es)?$/i.test(answer.trim());
    }
    if (!approved) {
      if (!pending.length) {
        options.gate.policyWriteDeferred(true);
        ui.print("      Ark policy additions are awaiting approval and will be listed in the summary.");
        return;
      }
      throw new Error(
        options.interactive
          ? "The tailnet policy change was declined, so nothing was applied. Re-run host:setup to review it again, or run it without a Tailscale credential to make the change by hand."
          : "The tailnet policy needs the change shown above. Re-run with --non-interactive and --approve-tailnet-policy to apply it, or interactively to review it.",
      );
    }
    await api.validatePolicy(merge.text);
    ui.print("      Tailscale validated the merged policy.");
    await api.setPolicy(merge.text, current.etag);
    options.gate.policyWriteDeferred(false);
    ui.print("      Tailnet policy updated.");
  }

  const source: TailscaleKeySource = {
    id: "tailscale-api",
    policyInstructions: () => tailnetPolicyInstructions({ backup: options.backup }),
    preparePolicy({ pending = [ARK_VPS_TAG] }: PolicyPreparation = {}) {
      return preparePolicy(pending);
    },
    async acquire(request: KeyRequest): Promise<AcquiredKey> {
      await source.preparePolicy!({ pending: [request.tag] });
      const minted = await api.createKey(request.tag, `ark-stack setup ${request.tag.slice(4)}`);
      ui.print(
        `      Minted a one-off ${request.tag} key through the Tailscale API (ID ${minted.id}, expires in one hour).`,
      );
      let released = false;
      return {
        key: minted.key,
        inMemoryOnly: true,
        release: async () => {
          if (released) return true;
          for (let attempt = 0; ; attempt++) {
            try {
              await api.deleteKey(minted.id);
              released = true;
              ui.print(`      Revoked the ${request.tag} key.`);
              return true;
            } catch (error) {
              const status = error instanceof TailscaleApiError ? error.status : undefined;
              if (attempt === 2 || (status && status !== 408 && status !== 429 && status < 500)) {
                ui.print(
                  `      Could not revoke the ${request.tag} key (ID ${minted.id}). Revoke it under Settings > Keys. It expires within one hour of creation.`,
                );
                return false;
              }
              await (options.sleep ?? Bun.sleep)(250 * 2 ** attempt);
            }
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
  gate: PolicyGate;
  interactive: boolean;
  approve: boolean;
  backup: boolean;
  sleep?: (ms: number) => Promise<void>;
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

  async function choose(allowPrompt: boolean): Promise<TailscaleKeySource> {
    let credential = credentialFromEnv(env);
    if (!credential && interactive && allowPrompt) {
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
  const resolve = (allowPrompt = true) => (chosen ??= choose(allowPrompt));

  const source: TailscaleKeySource = {
    id: "automatic",
    policyInstructions: () => tailnetPolicyInstructions({ backup: options.backup }),
    async preparePolicy({ pending = [ARK_VPS_TAG], supplied = [], offerCredential }: PolicyPreparation = {}) {
      // With every node enrolled, a manual rerun needs no credential.
      const useSource = chosen || credentialFromEnv(env) || pending.length || offerCredential;
      const selected = useSource ? await resolve() : manual;
      if (selected.preparePolicy) {
        if (supplied.length) await options.gate.unread(supplied, true);
        return selected.preparePolicy({ pending });
      }
      if (pending.includes(ARK_VPS_TAG))
        for (const line of selected.policyInstructions()) ui.print(`      ${line}`);
      await options.gate.unread(pending);
    },
    async collect(request) {
      const selected = await resolve();
      // The API source waits until enrolment to review the current policy and mint the key.
      if (selected.collect) await options.gate.unread([request.tag]);
      return selected.collect?.(request);
    },
    async acquire(request, { allowPrompt = true } = {}) {
      // An explicitly supplied key (or key file) is used as given.
      if (env[request.variable]?.trim() || (request.tag === ARK_VPS_TAG && env.TS_VPS_AUTHKEY_FILE?.trim()))
        return manual.acquire(request);
      return (await resolve(allowPrompt)).acquire(request, { allowPrompt });
    },
  };
  return source;
}
