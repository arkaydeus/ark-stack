// FD-29 provider calls. The audit observer receives endpoint templates and statuses only.
export const VERCEL_ORIGIN = "https://api.vercel.com";
export const projectIdPattern = /^prj_[A-Za-z0-9]+$/;
export const teamIdPattern = /^team_[A-Za-z0-9]+$/;
export const deploymentIdPattern = /^dpl_[A-Za-z0-9]+$/;
const hookJobIdPattern = /^(?:dpl_)?[A-Za-z0-9]{16,80}$/;

export type VercelSelection = {
  projectId: string;
  teamId: string;
  otherProjectId: string;
  target: "production" | "preview";
  gitBranch?: string | null;
};

export type VercelScopeProof = {
  evidence: string;
  listDenialCode: string;
  otherProjectDenialCode: string;
};

// Record reviewed, redacted live evidence in source before enabling connections. The public
// AuthToken schema currently documents user and team scopes only. No environment toggle can
// substitute for confirming the parser and the two project-scope denials against the real API.
export function reviewedVercelScopeProof(): VercelScopeProof | null {
  return null;
}

export type VercelTransport = (input: URL, init: RequestInit) => Promise<Response>;
type RequestInput = {
  endpoint: string;
  url: URL;
  method?: "GET" | "POST";
  token?: string;
  body?: unknown;
};
export type VercelCall = { endpoint: string; method: string; status: number | "network_error" };
export type VercelObserver = (call: VercelCall) => void;

export function object(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

export class VercelApi {
  constructor(
    private readonly transport: VercelTransport = fetch,
    private readonly observe: VercelObserver = () => {},
  ) {}

  async request(input: RequestInput) {
    const method = input.method ?? "GET";
    let status: VercelCall["status"] = "network_error";
    try {
      const headers = new Headers({ accept: "application/json" });
      if (input.token) headers.set("authorization", `Bearer ${input.token}`);
      if (input.body !== undefined) headers.set("content-type", "application/json");
      const response = await this.transport(input.url, {
        method,
        headers,
        body: input.body === undefined ? undefined : JSON.stringify(input.body),
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
      status = response.status;
      return { status, body: (await response.json().catch(() => undefined)) as unknown };
    } catch {
      // Transport exceptions can contain URLs (including the secret deploy hook) or headers.
      return { status, body: undefined };
    } finally {
      this.observe({ endpoint: input.endpoint, method, status });
    }
  }
}

export function vercelUrl(path: string, teamId?: string) {
  const url = new URL(path, VERCEL_ORIGIN);
  if (teamId) url.searchParams.set("teamId", teamId);
  return url;
}

export function readScopeProbes(api: VercelApi, input: VercelSelection, token: string) {
  const { projectId, teamId, otherProjectId } = input;
  return Promise.all([
    api.request({
      endpoint: "/v5/user/tokens/current",
      url: vercelUrl("/v5/user/tokens/current"),
      token,
    }),
    api.request({
      endpoint: "/v9/projects/{selectedProjectId}",
      url: vercelUrl(`/v9/projects/${projectId}`, teamId),
      token,
    }),
    api.request({
      endpoint: "/v9/projects",
      url: vercelUrl("/v9/projects", teamId),
      token,
    }),
    api.request({
      endpoint: "/v9/projects/{knownOtherProjectId}",
      url: vercelUrl(`/v9/projects/${otherProjectId}`, teamId),
      token,
    }),
  ]);
}

export function verifiedScope(
  [metadata, selected, list, other]: Awaited<ReturnType<typeof readScopeProbes>>,
  input: VercelSelection,
  proof: VercelScopeProof,
  now: Date,
) {
  const token = object(object(metadata.body)?.token);
  const scopes = token?.scopes;
  const scope = Array.isArray(scopes) && scopes.length === 1 ? object(scopes[0]) : undefined;
  const expiresAt = token?.expiresAt;
  const project = object(selected.body);
  const denied = (response: typeof list, code: string) => {
    const error = object(object(response.body)?.error);
    return (
      response.status === 403 &&
      code.length > 0 &&
      !["forbidden", "unauthorized", "access_denied"].includes(code) &&
      error?.code === code &&
      (error.invalidToken === undefined || error.invalidToken === false) &&
      (error.missingToken === undefined || error.missingToken === false)
    );
  };
  if (
    metadata.status !== 200 ||
    typeof expiresAt !== "number" ||
    !Number.isSafeInteger(expiresAt) ||
    expiresAt <= now.getTime() ||
    expiresAt > 8.64e15 ||
    token?.revokedAt != null ||
    scope?.type !== "project" ||
    scope.projectId !== input.projectId ||
    scope.teamId !== input.teamId ||
    Object.keys(scope).some(
      (key) => !["type", "projectId", "teamId", "createdAt", "expiresAt", "origin"].includes(key),
    ) ||
    selected.status !== 200 ||
    project?.id !== input.projectId ||
    project.accountId !== input.teamId ||
    !denied(list, proof.listDenialCode) ||
    !denied(other, proof.otherProjectDenialCode)
  )
    return null;

  const scopeExpiry = scope.expiresAt;
  if (
    scopeExpiry !== undefined &&
    (typeof scopeExpiry !== "number" || !Number.isSafeInteger(scopeExpiry) || scopeExpiry <= now.getTime())
  ) {
    return null;
  }
  return { expiresAt: new Date(Math.min(expiresAt, scopeExpiry ?? expiresAt)), project };
}

/** A hook is a bearer credential. Only accept the exact Vercel origin and selected project path. */
export function deployHookUrl(value: string, projectId: string) {
  if (
    !projectIdPattern.test(projectId) ||
    !new RegExp(
      `^https://api\\.vercel\\.com/v1/integrations/deploy/${projectId}/[A-Za-z0-9_-]{1,160}(?:\\?buildCache=(?:true|false))?$`,
    ).test(value)
  ) {
    return null;
  }
  return new URL(value);
}

/** Confirm the hook's ref and environment from the selected project's Git settings. */
export function deployHookBranch(project: Record<string, unknown>, hook: URL, selection: VercelSelection) {
  const link = object(project.link);
  if (typeof link?.productionBranch !== "string" || !Array.isArray(link.deployHooks)) return null;
  const hooks = link.deployHooks
    .map(object)
    .filter(
      (row) =>
        typeof row?.url === "string" &&
        deployHookUrl(row.url, selection.projectId)?.pathname === hook.pathname,
    );
  const ref = hooks.length === 1 ? hooks[0]?.ref : undefined;
  if (
    typeof ref !== "string" ||
    !ref ||
    (selection.target === "production") !== (ref === link.productionBranch) ||
    (selection.gitBranch && ref !== selection.gitBranch)
  ) {
    return null;
  }
  return ref;
}

export async function upsertVercelVariables(
  api: VercelApi,
  selection: VercelSelection,
  token: string,
  variables: Record<string, string>,
) {
  const url = vercelUrl(`/v10/projects/${selection.projectId}/env`, selection.teamId);
  url.searchParams.set("upsert", "true");
  const entries = Object.entries(variables).map(([key, value]) => ({
    key,
    value,
    type: "sensitive",
    target: [selection.target],
    ...(selection.gitBranch ? { gitBranch: selection.gitBranch } : {}),
  }));
  const { status, body } = await api.request({
    endpoint: "/v10/projects/{projectId}/env",
    url,
    method: "POST",
    token,
    body: entries,
  });
  const { created, failed } = object(body) ?? {};
  if (
    status !== 201 ||
    !Array.isArray(created) ||
    !Array.isArray(failed) ||
    failed.length !== 0 ||
    created.length !== entries.length ||
    !entries.every(({ key, gitBranch, target }) =>
      created.some((item: unknown) => {
        const row = object(item);
        return (
          row?.key === key &&
          row.type === "sensitive" &&
          Array.isArray(row.target) &&
          row.target.length === 1 &&
          row.target[0] === target[0] &&
          (row.gitBranch ?? undefined) === gitBranch
        );
      }),
    )
  ) {
    throw new Error("Vercel did not confirm all sensitive environment variable updates.");
  }
}

export async function triggerVercelHook(api: VercelApi, hook: URL) {
  const { status, body } = await api.request({
    endpoint: "/v1/integrations/deploy/{projectId}/{hook}",
    url: hook,
    method: "POST",
  });
  const id = object(object(body)?.job)?.id;
  if ((status !== 200 && status !== 201) || typeof id !== "string" || !hookJobIdPattern.test(id)) {
    throw new Error("Vercel did not confirm receipt of the deploy hook request.");
  }
  return id;
}

/** Resolve a hook's job to an exact deployment. A nearby or unrelated READY build is never proof. */
export async function vercelHookDeployment(
  api: VercelApi,
  selection: VercelSelection,
  token: string,
  jobId: string,
  requestedAt: Date,
) {
  const url = vercelUrl("/v7/deployments", selection.teamId);
  url.searchParams.set("projectId", selection.projectId);
  url.searchParams.set("since", String(requestedAt.getTime() - 10_000));
  url.searchParams.set("limit", "100");
  if (selection.gitBranch) url.searchParams.set("branch", selection.gitBranch);
  const { status, body } = await api.request({ endpoint: "/v7/deployments", url, token });
  if (status === "network_error" || status === 429 || status >= 500) return null;
  const rows = object(body)?.deployments;
  if (status !== 200 || !Array.isArray(rows)) throw new Error("Vercel deployment status is unavailable.");
  const matching = rows
    .map(object)
    .filter(
      (row) =>
        row?.source === "git-deploy-hook" &&
        (row.uid === jobId || object(row.meta)?.deployHookJobId === jobId),
    );
  if (!matching.length) return null;
  const row = matching[0];
  if (
    matching.length !== 1 ||
    row?.projectId !== selection.projectId ||
    (selection.target === "production"
      ? row.target !== "production"
      : row.target != null || row.customEnvironment != null) ||
    typeof row.uid !== "string" ||
    !deploymentIdPattern.test(row.uid)
  ) {
    throw new Error("Vercel reported an unexpected deployment for the deploy hook.");
  }
  if (row.readyState === "ERROR" || row.readyState === "CANCELED")
    throw new Error("The Vercel deployment failed or was canceled.");
  return row.readyState === "READY" ? row.uid : null;
}
