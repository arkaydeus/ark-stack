import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { imageSource } from "./check-image-plan";
import { isolatedDockerConfig } from "./publish-images";

// Opt-in live check; creates and deletes one uniquely named smoke package.
const token = process.env.GHCR_TOKEN;
const user = process.env.GHCR_USER;
const repository = process.env.GITHUB_REPOSITORY;
const runId = process.env.GITHUB_RUN_ID;
const attempt = process.env.GITHUB_RUN_ATTEMPT;
assert(
  token && user && repository && runId && attempt,
  "Run via the GHCR publish check workflow with explicit credentials.",
);
assert.equal(
  `https://github.com/${repository}`,
  imageSource,
  "Smoke check must use the repository named by the Bake source annotation.",
);
const [owner, repo] = repository.split("/");
assert(owner && repo);
const packageName = `${repo}-publish-check-${runId}-${attempt}`.toLowerCase();
const ref = `ghcr.io/${owner.toLowerCase()}/${packageName}:smoke`;
const scratch = await mkdtemp(join(tmpdir(), "ark-ghcr-check-"));
let packageEndpoint: string | undefined;
let pushAttempted = false;

async function api(path: string, method = "GET") {
  return fetch(`https://api.github.com${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
}

try {
  const context = join(scratch, "context");
  const config = join(scratch, "docker");
  await mkdir(context);
  await mkdir(config);
  const dockerEnv = await isolatedDockerConfig(config);
  async function docker(args: string[], input?: string) {
    const child = Bun.spawn(["docker", ...args], {
      cwd: join(import.meta.dir, ".."),
      env: { ...process.env, ...dockerEnv },
      stdin: input === undefined ? "ignore" : new Blob([input]),
      stdout: "pipe",
      stderr: "inherit",
    });
    const [code, output] = await Promise.all([child.exited, new Response(child.stdout).text()]);
    assert.equal(code, 0, `docker ${args.slice(0, 2).join(" ")} failed`);
    return output;
  }
  const ownerResponse = await api(`/users/${owner}`);
  assert(ownerResponse.ok, `Cannot resolve package owner: ${ownerResponse.status}`);
  const ownerInfo = (await ownerResponse.json()) as { type: string };
  packageEndpoint =
    ownerInfo.type === "Organization"
      ? `/orgs/${owner}/packages/container/${encodeURIComponent(packageName)}`
      : `/users/${owner}/packages/container/${encodeURIComponent(packageName)}`;
  // Refuse to overwrite or delete any pre-existing package, including a repeated job run.
  const existing = await api(packageEndpoint);
  assert.equal(existing.status, 404, "Smoke package must not already exist.");
  await docker(["login", "ghcr.io", "--username", user, "--password-stdin"], token);
  await writeFile(join(context, "Dockerfile"), "FROM scratch\nCOPY probe /probe\n");
  await writeFile(join(context, "probe"), "GHCR integration probe\n");
  const override = join(scratch, "smoke.hcl");
  await writeFile(
    override,
    `target "smoke" {\n  inherits = ["_common"]\n  context = ${JSON.stringify(context)}\n  dockerfile = "Dockerfile"\n  tags = [${JSON.stringify(ref)}]\n}\n`,
  );
  pushAttempted = true;
  await docker(["buildx", "bake", "-f", "docker-bake.hcl", "-f", override, "smoke", "--push", "--no-cache"]);
  const index = JSON.parse(await docker(["buildx", "imagetools", "inspect", "--raw", ref])) as {
    annotations?: Record<string, string>;
    manifests?: { annotations?: Record<string, string> }[];
  };
  assert.equal(index.annotations?.["org.opencontainers.image.source"], imageSource);
  assert(
    index.manifests?.some(
      (manifest) => manifest.annotations?.["vnd.docker.reference.type"] === "attestation-manifest",
    ),
    "Missing attestation manifest in pushed index",
  );
  const provenance = JSON.parse(
    await docker(["buildx", "imagetools", "inspect", "--format", "{{json .Provenance.SLSA}}", ref]),
  ) as { buildType?: string; buildDefinition?: { buildType?: string } };
  assert(provenance?.buildType || provenance?.buildDefinition?.buildType, "Missing SLSA provenance");
  const response = await api(packageEndpoint);
  assert(response.ok, `Cannot read smoke package: ${response.status}`);
  const metadata = (await response.json()) as { repository?: { full_name?: string } };
  assert.equal(
    metadata.repository?.full_name?.toLowerCase(),
    repository.toLowerCase(),
    "GHCR package is not linked to the source repository",
  );
  console.log("GHCR login, push permissions, index annotation, provenance and repository linkage verified.");
} finally {
  try {
    if (pushAttempted && packageEndpoint) {
      const response = await api(packageEndpoint, "DELETE");
      assert([204, 404].includes(response.status), `Smoke package cleanup failed: ${response.status}`);
    }
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}
