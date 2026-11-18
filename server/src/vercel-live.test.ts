// Opt-in checks against disposable Vercel projects. See docs/design/front-door.md §3.10.5.
import { expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { sha256Hex } from "@ark-stack/shared";

import {
  deploymentIdPattern,
  deployHookBranch,
  deployHookUrl,
  object,
  projectIdPattern,
  readScopeProbes,
  reviewedVercelScopeProof,
  teamIdPattern,
  triggerVercelHook,
  upsertVercelVariable,
  VercelApi,
  type VercelScopeProof,
  type VercelSelection,
  verifiedScope,
  vercelHookDeployment,
  vercelUrl,
} from "./modules/vercel-api.ts";

const env = process.env;
const projectId = env.ARK_TEST_VERCEL_PROJECT_ID ?? "";
const teamId = env.ARK_TEST_VERCEL_TEAM_ID ?? "";
const otherProjectId = env.ARK_TEST_VERCEL_OTHER_PROJECT_ID ?? "";
const projectToken = env.ARK_TEST_VERCEL_PROJECT_TOKEN ?? "";
const refusalTokens = {
  team: env.ARK_TEST_VERCEL_TEAM_TOKEN,
  account: env.ARK_TEST_VERCEL_ACCOUNT_TOKEN,
  crossProject: env.ARK_TEST_VERCEL_OTHER_PROJECT_TOKEN,
  expired: env.ARK_TEST_VERCEL_EXPIRED_TOKEN,
  noExpiry: env.ARK_TEST_VERCEL_NO_EXPIRY_TOKEN,
};
const scopeCredentials = projectToken && projectId && teamId && otherProjectId;
const api = new VercelApi();
const selection: VercelSelection = { projectId, teamId, otherProjectId, target: "production" };

function validateSelection() {
  if (
    !projectIdPattern.test(projectId) ||
    !projectIdPattern.test(otherProjectId) ||
    !teamIdPattern.test(teamId) ||
    projectId === otherProjectId
  )
    throw new Error("Supply a selected project, its team and a distinct comparison project from that team.");
}

type ScopeResponses = Awaited<ReturnType<typeof readScopeProbes>>;
type Probe = ScopeResponses[number];
const dynamicIdentifier = /^(?:prj|team|dpl|vcp|hook|tok|usr)_/i;

function proofSensitiveValues(token: string) {
  return [
    token,
    projectId,
    teamId,
    otherProjectId,
    env.ARK_TEST_VERCEL_DEPLOY_HOOK?.split("/").at(-1)?.split("?")[0] ?? "",
  ];
}

function denialCode(response: Probe, token: string) {
  const code = object(object(response.body)?.error)?.code;
  return typeof code === "string" &&
    /^[a-z][a-z0-9_]{0,79}$/.test(code) &&
    !dynamicIdentifier.test(code) &&
    !proofSensitiveValues(token).some((secret) => secret && code.includes(secret))
    ? code
    : null;
}

type FieldShape =
  | string
  | { type: "array"; entries: FieldShape[] }
  | { type: "object"; fields: Record<string, FieldShape>; redacted: number };

function metadataShape(value: unknown, sensitive: string[], depth = 0, budget = { fields: 120 }): FieldShape {
  if (value === null) return "null";
  if (Array.isArray(value)) {
    if (depth >= 5 || budget.fields <= 0) return "array";
    return {
      type: "array",
      entries: value.slice(0, 4).map((entry) => metadataShape(entry, sensitive, depth + 1, budget)),
    };
  }
  const row = object(value);
  if (!row || depth >= 5 || budget.fields <= 0) return typeof value;
  const fields: Record<string, FieldShape> = Object.create(null);
  let redacted = 0;
  for (const key of Object.keys(row).slice(0, 32)) {
    // Emit schema-like names. Dynamic IDs, credential-shaped names and known fixture values
    // are suppressed even when the provider uses them as property names.
    if (
      !/^[A-Za-z][A-Za-z0-9_]{0,39}$/.test(key) ||
      dynamicIdentifier.test(key) ||
      /[a-zA-Z0-9]{24,}/.test(key) ||
      sensitive.some((secret) => secret && key.includes(secret))
    ) {
      redacted++;
    } else {
      if (budget.fields <= 0) break;
      budget.fields--;
      fields[key] = metadataShape(row[key], sensitive, depth + 1, budget);
    }
  }
  return { type: "object", fields, redacted };
}

function scopeProof(label: string, [metadata, selected, list, other]: ScopeResponses, token: string) {
  const row = object(object(metadata.body)?.token);
  const scopes = Array.isArray(row?.scopes) ? row.scopes : [];
  const sensitive = proofSensitiveValues(token);
  return {
    checkedAt: new Date().toISOString(),
    fixture: label,
    "GET /v5/user/tokens/current": {
      status: metadata.status,
      metadataFields: metadataShape(metadata.body, sensitive),
      scopeCount: Array.isArray(row?.scopes) ? scopes.length : null,
      firstScopeIsProject: object(scopes[0])?.type === "project",
      scopeBindsSelectedProjectAndTeam:
        scopes.length === 1 &&
        object(scopes[0])?.projectId === projectId &&
        object(scopes[0])?.teamId === teamId,
      expiryIsFutureEpochMs:
        typeof row?.expiresAt === "number" &&
        Number.isSafeInteger(row.expiresAt) &&
        row.expiresAt > Date.now(),
    },
    "GET /v9/projects/{selectedProjectId}?teamId={teamId}": {
      status: selected.status,
      idAndAccountMatch:
        object(selected.body)?.id === projectId && object(selected.body)?.accountId === teamId,
    },
    "GET /v9/projects?teamId={teamId}": { status: list.status, denialCode: denialCode(list, token) },
    "GET /v9/projects/{knownOtherProjectId}?teamId={teamId}": {
      status: other.status,
      denialCode: denialCode(other, token),
    },
  };
}

function logProof(label: string, probes: ScopeResponses, token: string) {
  console.log("[FD-29 live scope proof]", JSON.stringify(scopeProof(label, probes, token)));
}

test("live proof reports new metadata field names and types without credential values or dynamic keys", () => {
  const token = "vcp_CanaryProof";
  const project = "prj_CanaryProof";
  const hook = "https://api.vercel.com/v1/integrations/deploy/prj_CanaryProof/HookCanaryProof";
  const probes: ScopeResponses = [
    {
      status: 200,
      body: {
        token: {
          expiryMillis: 123,
          projectScopes: [{ projectBinding: project, nestedBinding: { account: "team_CanaryProof" } }],
          [token]: "credential-key",
          [project]: true,
          [hook]: true,
          hookRef: hook,
        },
      },
    },
    { status: 200, body: { id: project } },
    { status: 403, body: { error: { code: "project_scope_denied" } } },
    { status: 403, body: { error: { code: "prj_hiddenid" } } },
  ];
  const proof = JSON.stringify(scopeProof("mock", probes, token));
  expect(proof).toContain('"expiryMillis":"number"');
  expect(proof).toContain('"projectBinding":"string"');
  expect(proof).toContain('"account":"string"');
  expect(proof).toContain("project_scope_denied");
  expect(proof).not.toContain("prj_hiddenid");
  for (const privateValue of [token, project, "team_CanaryProof", "HookCanaryProof", "credential-key"])
    expect(proof).not.toContain(privateValue);
});

let projectProbes: Promise<ScopeResponses> | undefined;
function readProjectProbes() {
  validateSelection();
  return (projectProbes ??= readScopeProbes(api, selection, projectToken));
}

function observedDenials(result: ScopeResponses): VercelScopeProof {
  return (
    reviewedVercelScopeProof() ?? {
      evidence: "opt-in test only",
      listDenialCode: denialCode(result[2], projectToken) ?? "",
      otherProjectDenialCode: denialCode(result[3], projectToken) ?? "",
    }
  );
}

test.skipIf(!scopeCredentials)(
  "live Vercel scope proof (requires ARK_TEST_VERCEL_{PROJECT_TOKEN,PROJECT_ID,TEAM_ID,OTHER_PROJECT_ID})",
  async () => {
    const result = await readProjectProbes();
    logProof("selected project", result, projectToken);
    expect(
      !!verifiedScope(result, selection, observedDenials(result), new Date()),
      "Live responses must prove the selected project and exact scope denials before enabling connect.",
    ).toBe(true);
  },
  30_000,
);

for (const [label, token] of Object.entries(refusalTokens)) {
  test.skipIf(!scopeCredentials || !token)(
    `live Vercel refuses ${label} (requires scope credentials and the corresponding refusal fixture token)`,
    async () => {
      const selected = await readProjectProbes();
      const result = await readScopeProbes(api, selection, token!);
      logProof(label, result, token!);
      expect(verifiedScope(result, selection, observedDenials(selected), new Date()) === null).toBe(true);
    },
    30_000,
  );
}

const deployHook = env.ARK_TEST_VERCEL_DEPLOY_HOOK;
test.skipIf(!scopeCredentials || !deployHook)(
  "live Vercel correlates a deploy hook with its deployment (requires ARK_TEST_VERCEL_DEPLOY_HOOK and scope credentials)",
  async () => {
    const [, selected] = await readProjectProbes();
    const hook = deployHookUrl(deployHook!, projectId);
    const project = object(selected.body);
    const branch = hook && project && deployHookBranch(project, hook, selection);
    if (!hook || !branch)
      throw new Error("The scratch production hook must match the selected project and branch.");
    const requestedAt = new Date();
    const jobId = await triggerVercelHook(api, hook);
    while (Date.now() - requestedAt.getTime() < 30 * 60_000) {
      const ready = await vercelHookDeployment(
        api,
        { ...selection, gitBranch: branch },
        projectToken,
        jobId,
        requestedAt,
      );
      if (ready) {
        console.log(
          "[FD-29 live hook proof] The exact hook job produced a matching READY production deployment.",
        );
        return;
      }
      await Bun.sleep(5_000);
    }
    throw new Error("No matching READY deployment could be established for the hook job.");
  },
  31 * 60_000,
);

const redeployToken = env.ARK_TEST_VERCEL_REDEPLOY_TOKEN || projectToken;
const baselineId = env.ARK_TEST_VERCEL_BASELINE_DEPLOYMENT_ID;
const baselineCanary = env.ARK_TEST_VERCEL_CANARY_BASELINE;
const bypass = env.ARK_TEST_VERCEL_AUTOMATION_BYPASS;
const canaryPath = "/api/ark-fd29-canary";
const canaryName = "ARK_FD29_REDEPLOY_CANARY";

async function readCanary(host: unknown) {
  if (typeof host !== "string" || !/^[a-z0-9-]+\.vercel\.app$/.test(host))
    throw new Error("The scratch deployment must have a generated vercel.app hostname.");
  const response = await fetch(new URL(canaryPath, `https://${host}`), {
    headers: bypass ? { "x-vercel-protection-bypass": bypass } : {},
    redirect: "error",
    cache: "no-store",
    signal: AbortSignal.timeout(10_000),
  }).catch(() => null);
  const digest = response?.ok ? (await response.text().catch(() => "")).trim() : "";
  if (!/^[a-f0-9]{64}$/.test(digest))
    throw new Error("The scratch deployment did not return a canary digest.");
  return digest;
}

async function deployment(id: string, token: string) {
  const response = await api.request({
    endpoint: "/v13/deployments/{idOrUrl}",
    url: vercelUrl(`/v13/deployments/${id}`, teamId),
    token,
  });
  if (
    response.status === 404 ||
    response.status === 429 ||
    response.status === "network_error" ||
    response.status >= 500
  )
    return null;
  const row = object(response.body);
  if (response.status !== 200 || row?.id !== id || row.projectId !== projectId || row.target !== "production")
    throw new Error("Vercel returned an unexpected scratch deployment.");
  return row;
}

test.skipIf(!redeployToken || !projectId || !teamId || !baselineId || !baselineCanary)(
  "live Vercel deploymentId env inheritance (requires test project, token, BASELINE_DEPLOYMENT_ID and CANARY_BASELINE)",
  async () => {
    if (
      !projectIdPattern.test(projectId) ||
      !teamIdPattern.test(teamId) ||
      !deploymentIdPattern.test(baselineId!)
    )
      throw new Error("Supply IDs for the disposable project, team and production baseline deployment.");
    const baseline = await deployment(baselineId!, redeployToken);
    if (
      baseline?.readyState !== "READY" ||
      typeof baseline.name !== "string" ||
      (await readCanary(baseline.url)) !== sha256Hex(baselineCanary!)
    )
      throw new Error(
        "The production baseline must be READY and already return the configured canary digest.",
      );

    const updatedCanary = randomBytes(32).toString("hex");
    try {
      await upsertVercelVariable(api, selection, redeployToken, canaryName, updatedCanary);
      const { status, body } = await api.request({
        endpoint: "/v13/deployments",
        url: vercelUrl("/v13/deployments", teamId),
        method: "POST",
        token: redeployToken,
        body: {
          name: baseline.name,
          project: projectId,
          deploymentId: baselineId,
          withLatestCommit: true,
          target: "production",
        },
      });
      const id = object(body)?.id;
      if (
        (status !== 200 && status !== 201) ||
        typeof id !== "string" ||
        !deploymentIdPattern.test(id) ||
        id === baselineId
      )
        throw new Error("Vercel did not create a new deployment from the baseline.");

      const deadline = Date.now() + 30 * 60_000;
      while (Date.now() < deadline) {
        const row = await deployment(id, redeployToken);
        if (row?.readyState === "ERROR" || row?.readyState === "CANCELED")
          throw new Error("The scratch redeployment failed or was canceled.");
        if (row?.readyState === "READY") {
          const observed = await readCanary(row.url);
          if (observed !== sha256Hex(updatedCanary) && observed !== sha256Hex(baselineCanary!))
            throw new Error("A different canary was observed; env inheritance could not be established.");
          console.log(
            "[FD-29 live redeploy proof]",
            JSON.stringify({
              endpoint: "POST /v13/deployments",
              usesDeploymentId: true,
              withLatestCommit: true,
              ready: true,
              pickedUpChangedEnv: observed === sha256Hex(updatedCanary),
            }),
          );
          return;
        }
        await Bun.sleep(5_000);
      }
      throw new Error("The scratch redeployment did not become READY within 30 minutes.");
    } finally {
      await upsertVercelVariable(api, selection, redeployToken, canaryName, baselineCanary!);
    }
  },
  31 * 60_000,
);
