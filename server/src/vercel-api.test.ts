import { expect, test } from "bun:test";

import {
  deployHookBranch,
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
