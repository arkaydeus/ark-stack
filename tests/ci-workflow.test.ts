import { expect, test } from "bun:test";
import { join } from "node:path";

test("the CI gate depends on every other workflow job", async () => {
  const workflow = Bun.YAML.parse(
    await Bun.file(join(import.meta.dir, "../.github/workflows/ci.yml")).text(),
  ) as { jobs: Record<string, { needs?: string | string[] }> };
  const { ci, ...otherJobs } = workflow.jobs;
  expect(ci).toBeDefined();
  const needs = typeof ci?.needs === "string" ? [ci.needs] : (ci?.needs ?? []);
  expect(needs.toSorted()).toEqual(Object.keys(otherJobs).toSorted());
});
