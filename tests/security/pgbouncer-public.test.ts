import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = join(import.meta.dir, "..", "..");
const composeFile = join(root, "infra", "platform", "docker-compose.yml");
// CVE-2026-6664 (unauthenticated crash via a malformed SCRAM packet) is fixed in 1.25.2.
const minimumVersion = [1, 25, 2] as const;
const pinnedImage = /^(?<repo>[a-z0-9./_-]+\/pgbouncer):(?<tag>[^@\s]+)@sha256:[a-f0-9]{64}$/;
// Image references only: `../../tmp/pgbouncer:/var/...` bind mounts have no `\w` tag.
const pgbouncerReference =
  /(?<![\w./-])[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9._-]+)*\/pgbouncer:\w[\w.-]*(?:@sha256:[a-f0-9]+)?/g;

type Service = {
  image?: string;
  entrypoint?: string | string[];
  command?: string | string[];
  environment?: Record<string, string> | string[];
  user?: string;
  ports?: string[];
  volumes?: string[];
  cap_drop?: string[];
  security_opt?: string[];
  networks?: string[] | Record<string, unknown>;
};

function pgbouncerVersion(tag: string) {
  const match = /^v?(\d+)\.(\d+)\.(\d+)(?:-p\d+)?$/.exec(tag);
  return match ? ([Number(match[1]), Number(match[2]), Number(match[3])] as const) : undefined;
}

function atLeast(version: readonly number[], minimum: readonly number[]) {
  for (let index = 0; index < minimum.length; index += 1) {
    if (version[index]! !== minimum[index]!) return version[index]! > minimum[index]!;
  }
  return true;
}

/** Returns every way `pgbouncer-public` departs from the hardened, directly-launched shape. */
function pgbouncerPublicViolations(service: Service | undefined) {
  if (!service) return ["pgbouncer-public service is missing"];
  const problems: string[] = [];
  const pin = pinnedImage.exec(service.image ?? "");
  if (!pin) {
    problems.push(`image must be <repo>/pgbouncer:<version>@sha256:<digest>, got ${service.image}`);
  } else {
    const version = pgbouncerVersion(pin.groups!.tag!);
    if (!version) problems.push(`image tag ${pin.groups!.tag} is not a readable PgBouncer version`);
    else if (!atLeast(version, minimumVersion)) {
      problems.push(`PgBouncer ${version.join(".")} is older than ${minimumVersion.join(".")}`);
    }
  }
  const entrypoint = typeof service.entrypoint === "string" ? [service.entrypoint] : service.entrypoint;
  if (!entrypoint?.length || !/(^|\/)pgbouncer$/.test(entrypoint[0]!)) {
    problems.push("entrypoint must run the pgbouncer binary directly, not the image's entrypoint script");
  }
  const command = typeof service.command === "string" ? [service.command] : (service.command ?? []);
  if (![...(entrypoint ?? []), ...command].includes("/var/lib/ark/pgbouncer/pgbouncer.ini")) {
    problems.push("pgbouncer must be launched with /var/lib/ark/pgbouncer/pgbouncer.ini");
  }
  const environment = Array.isArray(service.environment)
    ? service.environment.map((item) => item.split("=")[0]!)
    : Object.keys(service.environment ?? {});
  const generated = environment.filter((name) => /^(DB_|DATABASE_URL$|AUTH_|POOL_MODE$|LISTEN_)/.test(name));
  if (generated.length) problems.push(`env-driven config generation variables set: ${generated.join(", ")}`);
  if (service.user !== "1000:1000") problems.push("user must be 1000:1000 to read Ark's 0600 config files");
  if (!service.cap_drop?.includes("ALL")) problems.push("cap_drop must include ALL");
  if (!service.security_opt?.includes("no-new-privileges:true")) {
    problems.push("security_opt must include no-new-privileges:true");
  }
  // FD-26: edge-l4's fe_pg5432 owns public 5432 and reaches PgBouncer over pgbouncer-ingress.
  if (service.ports?.length) {
    problems.push(
      `pgbouncer-public must publish no port (edge-l4 owns 5432), got ${JSON.stringify(service.ports)}`,
    );
  }
  for (const mount of ["/var/lib/ark/pgbouncer", "/var/lib/ark/certs"]) {
    if (!service.volumes?.some((volume) => volume.endsWith(`:${mount}:ro`))) {
      problems.push(`${mount} must be mounted read-only`);
    }
  }
  if (!service.volumes?.includes("ark_pgbouncer_socket:/var/run/pgbouncer")) {
    problems.push("the admin socket volume ark_pgbouncer_socket must be mounted at /var/run/pgbouncer");
  }
  return problems;
}

function networksOf(service: Service | undefined) {
  return Array.isArray(service?.networks) ? service.networks : Object.keys(service?.networks ?? {});
}

async function loadCompose() {
  return Bun.YAML.parse(await Bun.file(composeFile).text()) as { services: Record<string, Service> };
}

// Git enumerates repository files regardless of directory or extension, without scanning
// ignored build output, dependencies or local review artifacts.
async function staleImages(repository: string) {
  const listed = Bun.spawnSync(["git", "ls-files", "-z"], { cwd: repository });
  if (listed.exitCode !== 0) throw new Error(listed.stderr.toString());
  const offenders: string[] = [];
  for (const name of listed.stdout.toString().split("\0").filter(Boolean)) {
    const text = await Bun.file(join(repository, name)).text();
    if (text.includes("\0")) continue;
    for (const reference of text.match(pgbouncerReference) ?? []) {
      const tag = reference.split("@")[0]!.split(":").at(-1)!;
      const version = pgbouncerVersion(tag);
      if (!version || !atLeast(version, minimumVersion)) offenders.push(`${name}: ${reference}`);
    }
  }
  return offenders;
}

describe("pgbouncer-public compose service", () => {
  test("runs a patched PgBouncer directly on Ark's generated config", async () => {
    const compose = await loadCompose();
    expect(pgbouncerPublicViolations(compose.services["pgbouncer-public"])).toEqual([]);
  });

  test("rejects the image entrypoint, missing pins and vulnerable versions", () => {
    const repository = "edoburu/pgbouncer";
    const digest = `sha256:${"a".repeat(64)}`;
    const good: Service = {
      image: `${repository}:v1.25.2-p0@${digest}`,
      entrypoint: ["/usr/bin/pgbouncer"],
      command: ["/var/lib/ark/pgbouncer/pgbouncer.ini"],
      user: "1000:1000",
      volumes: [
        "../../tmp/pgbouncer:/var/lib/ark/pgbouncer:ro",
        "../../tmp/certs:/var/lib/ark/certs:ro",
        "ark_pgbouncer_socket:/var/run/pgbouncer",
      ],
      cap_drop: ["ALL"],
      security_opt: ["no-new-privileges:true"],
    };
    expect(pgbouncerPublicViolations(good)).toEqual([]);
    const cases: Array<[Partial<Service>, RegExp]> = [
      [{ entrypoint: undefined }, /entrypoint/],
      [{ entrypoint: ["/entrypoint.sh"] }, /entrypoint/],
      [{ image: `${repository}:v1.9.0@${digest}` }, /1\.9\.0 is older/],
      [{ image: `${repository}:v1.25.1-p0@${digest}` }, /1\.25\.1 is older/],
      [{ image: "edoburu/pgbouncer:v1.26.1-p0" }, /sha256/],
      [{ image: `edoburu/pgbouncer@${digest}` }, /sha256/],
      [{ image: `${repository}:latest@${digest}` }, /readable PgBouncer version/],
      [{ command: ["/etc/pgbouncer/pgbouncer.ini"] }, /pgbouncer\.ini/],
      [{ environment: { DB_HOST: "app-postgres" } }, /DB_HOST/],
      [{ user: undefined }, /1000:1000/],
      [{ cap_drop: [] }, /cap_drop/],
      [{ security_opt: [] }, /no-new-privileges/],
      [{ ports: ["15432:5432"] }, /publish no port/],
      [{ ports: ["127.0.0.1:15432:5432"] }, /publish no port/],
      [
        {
          volumes: [
            "../../tmp/pgbouncer:/var/lib/ark/pgbouncer",
            "../../tmp/certs:/var/lib/ark/certs:ro",
            "ark_pgbouncer_socket:/var/run/pgbouncer",
          ],
        },
        /read-only/,
      ],
      [
        {
          volumes: ["../../tmp/pgbouncer:/var/lib/ark/pgbouncer:ro", "../../tmp/certs:/var/lib/ark/certs:ro"],
        },
        /admin socket/,
      ],
    ];
    for (const [change, expected] of cases) {
      const problems = pgbouncerPublicViolations({ ...good, ...change });
      expect(problems.some((problem) => expected.test(problem))).toBe(true);
    }
  });

  test("no repository file references a PgBouncer image older than 1.25.2", async () => {
    expect(await staleImages(root)).toEqual([]);
  });

  test("finds stale images in root files and directories outside infra, scripts and CI", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ark-image-scan-"));
    try {
      const repository = "edoburu/pgbouncer";
      const oldImage = `${repository}:v${[1, 24, 1].join(".")}-p1`;
      await mkdir(join(directory, "deploy"));
      await Bun.write(join(directory, "Dockerfile"), `FROM ${oldImage}\n`);
      await Bun.write(join(directory, "deploy", "pooler.conf"), `image: ${oldImage}\n`);
      for (const args of [
        ["init", "--quiet"],
        ["add", "."],
      ]) {
        const command = Bun.spawnSync(["git", ...args], { cwd: directory });
        expect(command.exitCode).toBe(0);
      }
      expect(await staleImages(directory)).toEqual([
        `Dockerfile: ${oldImage}`,
        `deploy/pooler.conf: ${oldImage}`,
      ]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("keeps backend networking internal; only edge-ts reaches PgBouncer, over pgbouncer-ingress", async () => {
    const compose = Bun.YAML.parse(await Bun.file(composeFile).text()) as {
      services: Record<string, Service & { network_mode?: string }>;
      networks: Record<string, { internal?: boolean }>;
    };
    expect(compose.networks["database-management"]?.internal).toBe(true);
    expect(compose.networks["pgbouncer-ingress"]?.internal).toBe(true);
    // The pre-FD-26 loopback publish bridge is gone.
    expect(compose.networks["database-loopback"]).toBeUndefined();
    expect(compose.services["pgbouncer-public"]?.networks).toEqual([
      "database-management",
      "pgbouncer-ingress",
    ]);
    const members = Object.entries(compose.services)
      .filter(([, service]) => networksOf(service).includes("pgbouncer-ingress"))
      .map(([name]) => name)
      .toSorted();
    expect(members).toEqual(["edge-ts", "pgbouncer-public"]);
    // The edge namespace (edge-ts, and edge/edge-l4 inside it) never joins database-management, so it
    // can never reach app-postgres (§3.8.3).
    expect(networksOf(compose.services["edge-ts"])).not.toContain("database-management");
    expect(compose.services["edge-l4"]?.network_mode).toBe("service:edge-ts");
    expect(compose.services["edge-ts"]?.ports).toContain("5432:5432");
  });

  test("database-ingress is only the nft reconciler: no 5432 relay or loopback publish", async () => {
    const compose = await loadCompose();
    const ingress = compose.services["database-ingress"]!;
    const environment = ingress.environment as Record<string, string>;
    expect(Object.keys(environment)).not.toContain("ARK_PGBOUNCER_LOOPBACK_PORT");
    expect(Object.keys(environment)).not.toContain("ARK_PUBLIC_DB_PORT");
    const source = await Bun.file(join(root, "scripts", "database-ingress.ts")).text();
    expect(source).not.toMatch(/createServer|\.listen\(|startListener/);
    expect(JSON.stringify(compose)).not.toContain("15432");
  });

  test("shares the admin socket only between pgbouncer-public and database-worker", async () => {
    const compose = Bun.YAML.parse(await Bun.file(composeFile).text()) as {
      services: Record<string, Service>;
      volumes: Record<string, { driver?: string; driver_opts?: Record<string, string> } | null>;
    };
    const users = Object.entries(compose.services)
      .filter(([, service]) => service.volumes?.some((volume) => volume.startsWith("ark_pgbouncer_socket:")))
      .map(([name]) => name)
      .toSorted();
    expect(users).toEqual(["database-worker", "pgbouncer-public"]);
    for (const name of users) {
      expect(compose.services[name]?.volumes).toContain("ark_pgbouncer_socket:/var/run/pgbouncer");
    }
    // A tmpfs owned by uid 1000 (PgBouncer and the worker), closed to every other uid.
    const volume = compose.volumes.ark_pgbouncer_socket;
    expect(volume?.driver_opts?.type).toBe("tmpfs");
    expect(volume?.driver_opts?.o).toContain("uid=1000");
    expect(volume?.driver_opts?.o).toContain("mode=0700");
  });

  test("the database worker reloads over the admin socket with no Docker CLI or socket", async () => {
    const compose = await loadCompose();
    const worker = compose.services["database-worker"]!;
    const environment = worker.environment as Record<string, string>;
    expect(environment.ARK_PGBOUNCER_RELOAD).toBe("1");
    expect(environment.ARK_PGBOUNCER_SOCKET_DIR).toBe("/var/run/pgbouncer");
    expect(environment.ARK_PGBOUNCER_ADMIN_PASSWORD).toMatch(/^\$\{ARK_PGBOUNCER_ADMIN_PASSWORD:\?/);
    expect(Object.keys(environment).filter((name) => name.startsWith("DOCKER_"))).toEqual([]);
    expect(worker.volumes?.some((volume) => volume.includes("docker.sock"))).toBe(false);
    // The database-worker image stage installs nftables only: no Docker CLI.
    const dockerfile = await Bun.file(join(root, "Dockerfile")).text();
    const stage = dockerfile.slice(
      dockerfile.indexOf("AS database-worker"),
      dockerfile.indexOf("\nFROM ", dockerfile.indexOf("AS database-worker")),
    );
    expect(stage).toContain("nftables");
    expect(stage).not.toMatch(/docker/i);
    // The reload code path has no Docker invocation left.
    for (const file of ["server/src/modules/pgbouncer.ts", "server/src/modules/providers.ts"]) {
      const source = await Bun.file(join(root, file)).text();
      expect(source).not.toMatch(/exec\(\s*"docker"/);
      expect(source).not.toContain('"kill", "-s", "HUP"');
    }
  });

  test("CI runs the disposable bootstrap and TLS/SCRAM smoke test", async () => {
    const workflow = Bun.YAML.parse(await Bun.file(join(root, ".github/workflows/ci.yml")).text()) as {
      jobs: Record<string, { steps?: Array<{ run?: string }> }>;
    };
    const runs = Object.values(workflow.jobs)
      .flatMap((job) => job.steps ?? [])
      .flatMap(({ run }) => [
        ...(run ?? "").matchAll(
          /(?:^|[;&|])[ \t]*bun[ \t]+scripts\/test-pgbouncer-public\.ts(?=$|[ \t;&|])/gm,
        ),
      ]);
    expect(runs).toHaveLength(1);
  });
});
