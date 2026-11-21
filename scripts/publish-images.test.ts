import { afterEach, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { digestReferences, imageNames } from "./publish-images";

const fixtures: string[] = [];
afterEach(async () => {
  await Promise.all(fixtures.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

const revision = "a".repeat(40);
const digest = `sha256:${"b".repeat(64)}`;
const stub = `#!${process.execPath}
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
const command = basename(process.argv[1]);
const args = process.argv.slice(2);
const env = process.env;
const record = { command, args, config: env.DOCKER_CONFIG, builder: env.BUILDX_CONFIG,
  registry: env.REGISTRY, tags: env.TAGS, platforms: env.PLATFORMS, revision: env.REVISION };
if (command === "docker" && args[0] === "login") {
  record.stdin = await Bun.stdin.text();
  record.settings = JSON.parse(readFileSync(join(env.DOCKER_CONFIG, "config.json"), "utf8"));
  record.context = readFileSync(join(env.DOCKER_CONFIG, "contexts", "fixture"), "utf8");
  writeFileSync(join(env.DOCKER_CONFIG, "config.json"), JSON.stringify({ auths: { "ghcr.io": { auth: "test-secret" } } }));
}
appendFileSync(env.STUB_LOG, JSON.stringify(record) + "\\n");
if (env.FAIL_COMMAND && (command + " " + args.slice(0, 2).join(" ")).startsWith(env.FAIL_COMMAND)) {
  console.error("controlled command failure"); process.exit(9);
}
if (command === "git") console.log(args[0] === "status" ? (env.DIRTY ? " M file" : "") : "${revision}");
if (command === "gh") {
  if (args[0] === "auth") console.log(env.EMPTY_TOKEN ? "" : "cli-token");
  else {
    if (env.GH_TOKEN !== "cli-token" || env.GITHUB_TOKEN) throw new Error("wrong API credentials");
    console.log(args.includes("--include") ? "HTTP/2 200\\r\\nX-OAuth-Scopes: " + (env.SCOPES ?? "repo, write:packages") + "\\r\\n\\r\\n{}" : "cli-user");
  }
}
if (command === "docker" && args[1] === "bake" && args.includes("--print") && env.PLAN) {
  console.log(env.PLAN.replaceAll("TAG", env.TAGS));
}
if (command === "docker" && args[1] === "imagetools" && args[2] === "inspect") {
  console.log(JSON.stringify({ mediaType: "application/vnd.oci.image.index.v1+json", digest: "${digest}" }));
}
if (command === "docker" && args.includes("--push")) {
  writeFileSync(args[args.indexOf("--metadata-file") + 1], env.METADATA ?? JSON.stringify({ app: {
    "containerimage.digest": "${digest}", "image.name": env.REGISTRY + "/ark-stack:" + env.TAGS.split(",")[0]
  } }));
}
`;

type RecordEntry = {
  command: string;
  args: string[];
  config?: string;
  builder?: string;
  registry?: string;
  tags?: string;
  platforms?: string;
  revision?: string;
  stdin?: string;
  settings?: {
    auths: object;
    credsStore?: string;
    credHelpers?: object;
    currentContext?: string;
    cliPluginsExtraDirs?: string[];
  };
  context?: string;
};

async function publish(args: string[] = [], overrides: Record<string, string | undefined> = {}) {
  const fixture = await mkdtemp(join(tmpdir(), "ark-publish-test-"));
  fixtures.push(fixture);
  const bin = join(fixture, "bin");
  const original = join(fixture, "docker");
  await mkdir(bin);
  await mkdir(join(original, "contexts"), { recursive: true });
  await writeFile(join(original, "contexts", "fixture"), "context-data");
  const config = JSON.stringify({
    auths: { existing: { auth: "old-secret" } },
    credsStore: "desktop",
    credHelpers: { "ghcr.io": "desktop" },
    currentContext: "desktop-linux",
    cliPluginsExtraDirs: ["/custom/plugins"],
  });
  await writeFile(join(original, "config.json"), config);
  for (const name of ["git", "gh", "docker"]) {
    const path = join(bin, name);
    await writeFile(path, stub);
    await chmod(path, 0o755);
  }
  const log = join(fixture, "commands.jsonl");
  const child = Bun.spawn([process.execPath, join(import.meta.dir, "publish-images.ts"), ...args], {
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      DOCKER_CONFIG: original,
      BUILDX_CONFIG: undefined,
      GHCR_TOKEN: undefined,
      GHCR_USER: undefined,
      EMPTY_TOKEN: undefined,
      GH_TOKEN: undefined,
      GITHUB_TOKEN: undefined,
      GH_HOST: "enterprise.example",
      ARK_IMAGE_REGISTRY: undefined,
      ARK_IMAGE_PLATFORMS: undefined,
      DIRTY: undefined,
      SCOPES: undefined,
      FAIL_COMMAND: undefined,
      METADATA: undefined,
      PLAN: undefined,
      STUB_LOG: log,
      ...overrides,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  const records: RecordEntry[] = (await Bun.file(log).exists())
    ? (await readFile(log, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line))
    : [];
  expect(await readFile(join(original, "config.json"), "utf8")).toBe(config);
  for (const record of records.filter(
    (entry) => entry.command === "docker" && !entry.args.includes("--print"),
  )) {
    expect(record.config).not.toBe(original);
    expect(await Bun.file(join(record.config!, "config.json")).exists()).toBe(false);
    expect(await Bun.file(join(record.config!, "metadata.json")).exists()).toBe(false);
  }
  return { code, stdout, stderr, records, original };
}

test("explicit token requires a username before any gh or Docker command", async () => {
  for (const user of [undefined, " "]) {
    const result = await publish([], { GHCR_TOKEN: "explicit-token", GHCR_USER: user });
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("GHCR_USER is required");
    expect(result.records.every((record) => record.command === "git")).toBe(true);
  }
});

test("explicit credentials publish without a gh login and use isolated Docker configuration", async () => {
  const result = await publish([], { GHCR_TOKEN: "explicit-token", GHCR_USER: "explicit-user" });
  expect(result.code).toBe(0);
  expect(result.records.some((record) => record.command === "gh")).toBe(false);
  const login = result.records.find((record) => record.args[0] === "login")!;
  expect(login.args).toEqual(["login", "ghcr.io", "--username", "explicit-user", "--password-stdin"]);
  expect(login.stdin).toBe("explicit-token");
  expect(login.settings).toEqual({
    auths: { "ghcr.io": {} },
    currentContext: "desktop-linux",
    cliPluginsExtraDirs: ["/custom/plugins", join(result.original, "cli-plugins")],
  });
  expect(login.context).toBe("context-data");
  const push = result.records.find((record) => record.args.includes("--push"))!;
  expect(push.config).toBe(login.config);
  expect(push.builder).toBe(join(result.original, "buildx"));
  expect(push.tags).toBe(`${revision.slice(0, 12)},latest`);
  expect(push.platforms).toBe("linux/amd64");
  expect(result.stdout).toContain(`ghcr.io/arkaydeus/ark-stack@${digest}`);
  expect(result.stdout).not.toContain("explicit-token");
});

test("CLI fallback pins token and host, parses case-insensitive comma-separated scopes", async () => {
  const result = await publish([], {
    SCOPES: "repo,  write:packages , read:org",
    GH_TOKEN: "ambient-token",
    GITHUB_TOKEN: "other-token",
  });
  expect(result.code).toBe(0);
  const gh = result.records.filter((record) => record.command === "gh");
  expect(gh).toHaveLength(3);
  expect(gh.every((record) => record.args.includes("github.com"))).toBe(true);
  const login = result.records.find((record) => record.args[0] === "login")!;
  expect(login.stdin).toBe("cli-token");
  expect(login.args).toContain("cli-user");
});

test("missing or near-match package scopes reject CLI credentials before login", async () => {
  for (const scopes of ["", "repo, read:packages", "repo, write:packages-extra"]) {
    const result = await publish([], { SCOPES: scopes });
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("gh auth refresh");
    expect(result.records.some((record) => record.command === "docker")).toBe(false);
  }
});

test("dry run selects tags, platforms and registry without accessing credentials", async () => {
  const result = await publish(
    ["--dry-run", "--tag", "v1", "--no-latest", "--platform", "linux/amd64,linux/arm64"],
    { ARK_IMAGE_REGISTRY: "ghcr.io/team/subgroup", ARK_IMAGE_PLATFORMS: "linux/arm64" },
  );
  expect(result.code).toBe(0);
  const bake = result.records.at(-1)!;
  expect(bake.args).toEqual(["buildx", "bake", "--print"]);
  expect(bake.tags).toBe("v1");
  expect(bake.platforms).toBe("linux/amd64,linux/arm64");
  expect(bake.registry).toBe("ghcr.io/team/subgroup");
  expect(bake.revision).toBe(revision);
  expect(result.records.some((record) => record.command === "gh")).toBe(false);
  expect(
    (await publish(["--dry-run"], { ARK_IMAGE_PLATFORMS: "linux/arm64" })).records.at(-1)?.platforms,
  ).toBe("linux/arm64");
  expect((await publish(["--dry-run", "--tag", "latest"])).records.at(-1)?.tags).toBe("latest");
});

test("dirty trees require opt-in, suffix explicit tags and revision, and omit latest", async () => {
  const denied = await publish([], { DIRTY: "1" });
  expect(denied.code).toBe(1);
  expect(denied.stderr).toContain("--allow-dirty");
  for (const args of [["--dry-run"], ["--dry-run", "--tag", "v1"], ["--allow-dirty", "--tag", "v1-dirty"]]) {
    const result = await publish(args, { DIRTY: "1", GHCR_TOKEN: "token", GHCR_USER: "user" });
    expect(result.code).toBe(0);
    const bake = result.records.find((record) => record.args[0] === "buildx")!;
    expect(bake.tags).toBe(args.length === 1 ? `${revision.slice(0, 12)}-dirty` : "v1-dirty");
    expect(bake.revision).toBe(`${revision}-dirty`);
  }
  const latest = await publish(["--allow-dirty", "--tag", "latest"], { DIRTY: "1" });
  expect(latest.code).toBe(1);
  expect(latest.stderr).toContain("cannot publish the latest");
});

test("invalid registry and tags fail before login", async () => {
  for (const registry of [
    "registry.example.com/team",
    "https://ghcr.io/team",
    "ghcr.io/Team",
    "ghcr.io/team/",
    "ghcr.io",
  ]) {
    const result = await publish([], { ARK_IMAGE_REGISTRY: registry });
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("ARK_IMAGE_REGISTRY");
    expect(result.records).toEqual([]);
  }
  expect((await publish(["--tag", "bad/tag"])).stderr).toContain("Invalid Docker tag");
  expect((await publish(["--dry-run", "--tag", "a".repeat(128)], { DIRTY: "1" })).stderr).toContain(
    "128 characters",
  );
});

test("command failures propagate and cleanup runs for login, push, and metadata failures", async () => {
  for (const command of ["git status", "gh auth", "gh api", "docker login", "docker buildx bake"]) {
    const result = await publish([], { FAIL_COMMAND: command });
    expect(result.code).toBe(1);
    expect(result.stderr).toMatch(/failed|exited 9/);
    expect(result.stdout).not.toContain("Pushed");
  }
  for (const metadata of ["not json", "{}", '{"app":{"image.name":"image:v1"}}']) {
    const result = await publish([], { METADATA: metadata });
    expect(result.code).toBe(1);
    expect(result.stdout).not.toContain("Pushed");
  }
  // Eight publisher processes, each with stubbed git, gh and docker: more than the 5 s default.
}, 20_000);

test("metadata produces immutable references for every target and rejects invalid shapes", () => {
  expect(
    digestReferences({
      app: {
        "containerimage.digest": digest,
        "image.name": "host:5000/team/app:v1,host:5000/team/app:latest",
      },
      worker: { "containerimage.digest": digest, "image.name": "ghcr.io/team/worker:v1" },
    }),
  ).toEqual([
    `  app               host:5000/team/app@${digest}`,
    `  worker            ghcr.io/team/worker@${digest}`,
  ]);
  for (const metadata of [
    null,
    [],
    {},
    { app: null },
    { app: [] },
    { app: { "containerimage.digest": "sha256:bad", "image.name": "app:v1" } },
    { app: { "containerimage.digest": digest, "image.name": 1 } },
    { app: { "containerimage.digest": digest, "image.name": "" } },
  ]) {
    expect(() => digestReferences(metadata)).toThrow();
  }
});

test("Bake plan guard rejects missing targets, source annotations and disabled provenance", async () => {
  const { checkImagePlan, imageSource, imageTargets } = await import("./check-image-plan");
  const plan = {
    group: { default: { targets: [...imageTargets] } },
    target: Object.fromEntries(
      imageTargets.map((name) => [
        name,
        {
          annotations: [`index:org.opencontainers.image.source=${imageSource}`],
          labels: { "org.opencontainers.image.source": imageSource },
          attest: [{ type: "provenance", mode: "min", disabled: false }],
        },
      ]),
    ),
  };
  expect(() => checkImagePlan(plan)).not.toThrow();
  for (const alter of [
    (copy: typeof plan) => {
      copy.group.default.targets.pop();
    },
    (copy: typeof plan) => {
      copy.target.app!.annotations = [];
    },
    (copy: typeof plan) => {
      copy.target.app!.attest[0]!.mode = "max";
    },
    (copy: typeof plan) => {
      copy.target.app!.attest[0]!.disabled = true;
    },
  ]) {
    const copy = structuredClone(plan);
    alter(copy);
    expect(() => checkImagePlan(copy)).toThrow();
  }
});

test("empty token and empty tag fail directly", async () => {
  const result = await publish([], { EMPTY_TOKEN: "1" });
  expect(result.code).toBe(1);
  expect(result.stderr).toContain("empty token");
  expect(result.records.some((record) => record.args[0] === "api")).toBe(false);
  expect((await publish(["--tag", ""])).stderr).toContain("Invalid Docker tag");
});

const plan = JSON.stringify({
  target: {
    app: { tags: ["ghcr.io/arkaydeus/ark-stack:TAG"] },
    "edge-caddy": { tags: ["ghcr.io/arkaydeus/ark-edge-caddy:TAG"] },
  },
});

test("merge combines per-platform tags into one annotated index per image", async () => {
  const tag = revision.slice(0, 12);
  const result = await publish(["--tag", tag, "--merge", `${tag}-amd64,${tag}-arm64`], {
    GHCR_TOKEN: "token",
    GHCR_USER: "user",
    PLAN: plan,
  });
  expect(result.code).toBe(0);
  expect(result.records.some((record) => record.args.includes("--push"))).toBe(false);
  const print = result.records.find((record) => record.args.includes("--print"))!;
  expect(print.tags).toBe(`${tag}-amd64`);
  const creates = result.records.filter((record) => record.args[2] === "create");
  expect(creates.map((record) => record.args.slice(3))).toEqual([
    [
      "--annotation",
      "index:org.opencontainers.image.source=https://github.com/arkaydeus/ark-stack",
      "--tag",
      `ghcr.io/arkaydeus/ark-stack:${tag}`,
      "--tag",
      "ghcr.io/arkaydeus/ark-stack:latest",
      `ghcr.io/arkaydeus/ark-stack:${tag}-amd64`,
      `ghcr.io/arkaydeus/ark-stack:${tag}-arm64`,
    ],
    [
      "--annotation",
      "index:org.opencontainers.image.source=https://github.com/arkaydeus/ark-stack",
      "--tag",
      `ghcr.io/arkaydeus/ark-edge-caddy:${tag}`,
      "--tag",
      "ghcr.io/arkaydeus/ark-edge-caddy:latest",
      `ghcr.io/arkaydeus/ark-edge-caddy:${tag}-amd64`,
      `ghcr.io/arkaydeus/ark-edge-caddy:${tag}-arm64`,
    ],
  ]);
  const login = result.records.find((record) => record.args[0] === "login")!;
  expect(creates.every((record) => record.config === login.config)).toBe(true);
  expect(result.stdout).toContain(`ghcr.io/arkaydeus/ark-edge-caddy@${digest}`);

  const noLatest = await publish(["--tag", "v1", "--no-latest", "--merge", "v1-a,v1-b"], {
    GHCR_TOKEN: "token",
    GHCR_USER: "user",
    PLAN: plan,
  });
  expect(noLatest.code).toBe(0);
  expect(noLatest.records.find((record) => record.args[2] === "create")!.args).not.toContain(
    "ghcr.io/arkaydeus/ark-stack:latest",
  );
});

test("merge refuses bad source lists before credentials", async () => {
  for (const args of [
    ["--merge", "only-one"],
    ["--merge", "a,a"],
    ["--merge", "a,bad/tag"],
    ["--merge", "a,b", "--dry-run"],
    ["--tag", "v1", "--merge", "v1,v1-arm64"],
    ["--tag", "v1", "--merge", "latest,v1-arm64"],
  ]) {
    const result = await publish(args, { PLAN: plan });
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("--merge");
    expect(result.records.some((record) => record.command === "gh" || record.args[0] === "login")).toBe(
      false,
    );
  }
});

test("image names come from each target's first tag and reject plans without that tag", () => {
  expect(
    imageNames(
      { target: { b: { tags: ["ghcr.io/x/b:t", "ghcr.io/x/b:latest"] }, a: { tags: ["ghcr.io/x/a:t"] } } },
      "t",
    ),
  ).toEqual([
    ["a", "ghcr.io/x/a"],
    ["b", "ghcr.io/x/b"],
  ]);
  for (const bad of [
    null,
    {},
    { target: {} },
    { target: { a: { tags: ["ghcr.io/x/a:other"] } } },
    { target: { a: {} } },
  ]) {
    expect(() => imageNames(bad, "t")).toThrow();
  }
});
