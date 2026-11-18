import { expect, test } from "bun:test";

import {
  deployHookBranch,
  upsertVercelVariables,
  VercelApi,
  vercelHookDeployment,
  type VercelSelection,
} from "./modules/vercel-api.ts";

const selection: VercelSelection = {
  projectId: "prj_Selected",
  teamId: "team_Selected",
  otherProjectId: "prj_Other",
  target: "preview",
  gitBranch: "preview",
};
const hook = new URL("https://api.vercel.com/v1/integrations/deploy/prj_Selected/FixtureHook");

const project = (deployHooks: object[]) => ({ link: { productionBranch: "main", deployHooks } });
const envResponse = (created: unknown) =>
  new VercelApi(async () => Response.json({ created, failed: [] }, { status: 201 }));

test("an env batch requires one sensitive acknowledgement per key at the requested target and branch", async () => {
  const variables = [
    { key: "ARK_DB_CLIENT_CERT_B64", value: "mock-cert" },
    { key: "ARK_DB_CLIENT_KEY_B64", value: "mock-key" },
  ];
  const [cert, privateKey] = variables.map(({ key }) => ({
    key,
    type: "sensitive",
    target: ["preview"],
    gitBranch: selection.gitBranch,
  }));
  await expect(
    upsertVercelVariables(envResponse([privateKey, cert]), selection, "mock-token", variables),
  ).resolves.toBeUndefined();
  for (const created of [
    cert,
    [cert],
    [cert, cert],
    [cert, { ...privateKey, type: "plain" }],
    [cert, { ...privateKey, target: ["production"] }],
    [cert, { ...privateKey, gitBranch: "other" }],
  ]) {
    await expect(
      upsertVercelVariables(envResponse(created), selection, "mock-token", variables),
    ).rejects.toThrow(/did not confirm every sensitive environment variable update/);
  }
});

test("deploy hook verification refuses the wrong ref, target and duplicate hooks", () => {
  const valid = { url: hook.href, ref: "preview" };
  expect(deployHookBranch(project([valid]), hook, selection)).toBe("preview");
  expect(deployHookBranch(project([{ ...valid, ref: "other" }]), hook, selection)).toBeNull();
  expect(
    deployHookBranch(project([{ ...valid, ref: "main" }]), hook, {
      ...selection,
      gitBranch: undefined,
    }),
  ).toBeNull();
  expect(
    deployHookBranch(project([valid, { ...valid, url: hook.href + "?buildCache=false" }]), hook, selection),
  ).toBeNull();
});

test("a hook receipt cannot prove an ambiguous, wrong-project or wrong-target deployment", async () => {
  const jobId = "HookJobTestFixture";
  const match = {
    uid: "dpl_Matching",
    source: "git-deploy-hook",
    projectId: selection.projectId,
    target: null,
    meta: { deployHookJobId: jobId },
    readyState: "READY",
  };
  for (const deployments of [
    [match, { ...match, uid: "dpl_AnotherMatching" }],
    [{ ...match, projectId: selection.otherProjectId }],
    [{ ...match, target: "production" }],
    [{ ...match, customEnvironment: { id: "env_Other" } }],
  ]) {
    const api = new VercelApi(async () => Response.json({ deployments }));
    await expect(vercelHookDeployment(api, selection, "mock-token", jobId, new Date())).rejects.toThrow(
      /unexpected deployment/,
    );
  }
});
