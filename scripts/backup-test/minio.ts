// Disposable MinIO fixture for the FD-21 backup tests (docs/design/front-door.md §3.18, FD-21).
//
// MinIO listens on the same port inside its container and on the host loopback, so one endpoint URL
// (`http://127.0.0.1:<port>`) works from the host (canary, S3 client) and from containers that join
// MinIO's network namespace (`--network container:<minio>`, used for restic). It never touches Docker
// resources it did not create, and `stop()` removes only its own container.
import { randomBytes } from "node:crypto";
import { createServer } from "node:net";

// Official MinIO images are no longer published anonymously (Docker Hub and quay.io refuse pulls), so
// the fixture uses Pigsty's maintained community build of the upstream MinIO server and client,
// pinned by multi-arch index digest like every other image in infra/.
export const MINIO_IMAGE =
  "pgsty/minio:RELEASE.2026-08-04T00-00-00Z@sha256:b6bfe7239bfc83fb90d31612d9704d86039dd714f7904b3f1ad68f211e602372";
export const MC_IMAGE =
  "pgsty/mc:RELEASE.2026-11-12T00-00-00Z@sha256:b532278b7a3747dbab6fe45eebb40a653efa704e6758e24e9d9ec54fc96c1800";
export const RESTIC_IMAGE =
  "restic/restic:0.19.1@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510";
/** FD-30: the home machine's server, as docs/guides/backups.md recommends (V-18 used 0.14.0). */
export const REST_SERVER_IMAGE =
  "restic/rest-server:0.14.0@sha256:d2aff06f47eb38637dff580c3e6bce4af98f386c396a25d32eb6727ec96214a5";

export type Run = { status: number; stdout: string; stderr: string };

export async function run(
  argv: string[],
  options: { allowFailure?: boolean; env?: Record<string, string | undefined>; stdin?: string } = {},
): Promise<Run> {
  const child = Bun.spawn(argv, {
    env: { ...process.env, ...options.env } as Record<string, string>,
    stdin: options.stdin === undefined ? "ignore" : Buffer.from(options.stdin),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (status !== 0 && !options.allowFailure) {
    throw new Error(
      `${argv.slice(0, 5).join(" ")} … failed (${status}):\n${(stderr || stdout).slice(-3000)}`,
    );
  }
  return { status, stdout: stdout.trim(), stderr: stderr.trim() };
}

export async function freePort() {
  return new Promise<number>((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() =>
        typeof address === "object" && address ? resolve(address.port) : reject(new Error("no port")),
      );
    });
  });
}

export type MinioFixture = {
  container: string;
  port: number;
  endpoint: string;
  rootUser: string;
  rootPassword: string;
  /** Run `mc` against this MinIO with alias `ark`. */
  mc: (args: string[], options?: { allowFailure?: boolean; stdin?: string }) => Promise<Run>;
  createUser: (
    name: string,
    policyName: string,
    policy: unknown,
  ) => Promise<{ accessKeyId: string; secretAccessKey: string }>;
  stop: () => Promise<void>;
};

export async function startMinio(label: string): Promise<MinioFixture> {
  const port = await freePort();
  const container = `ark-fd21-minio-${label}-${randomBytes(3).toString("hex")}`;
  const rootUser = `root${randomBytes(4).toString("hex")}`;
  const rootPassword = randomBytes(18).toString("base64url");
  await run([
    "docker",
    "run",
    "--detach",
    "--name",
    container,
    "--label",
    "ark.test=fd21-backups",
    "--publish",
    `127.0.0.1:${port}:${port}`,
    "--env",
    `MINIO_ROOT_USER=${rootUser}`,
    "--env",
    `MINIO_ROOT_PASSWORD=${rootPassword}`,
    "--tmpfs",
    "/data:rw,size=2g",
    "--entrypoint",
    "minio",
    MINIO_IMAGE,
    "server",
    "/data",
    "--address",
    `:${port}`,
    "--console-address",
    `127.0.0.1:${port + 1 > 65535 ? port - 1 : port + 1}`,
  ]);
  const endpoint = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 60_000;
  while (true) {
    const ready = await fetch(`${endpoint}/minio/health/ready`)
      .then((response) => response.ok)
      .catch(() => false);
    if (ready) break;
    if (Date.now() > deadline) throw new Error(`MinIO ${container} did not become ready`);
    await Bun.sleep(500);
  }
  const mcBase = (entrypoint: string[]) => [
    "docker",
    "run",
    "--rm",
    "--interactive",
    "--network",
    `container:${container}`,
    "--env",
    `MC_HOST_ark=http://${rootUser}:${rootPassword}@127.0.0.1:${port}`,
    ...entrypoint,
    MC_IMAGE,
  ];
  const mc = (args: string[], options: { allowFailure?: boolean; stdin?: string } = {}) =>
    run([...mcBase([]), ...args], options);
  const createUser = async (name: string, policyName: string, policy: unknown) => {
    const secretAccessKey = `key-${randomBytes(18).toString("base64url")}`;
    await mc(["admin", "user", "add", "ark", name, secretAccessKey]);
    if (typeof policy !== "string") {
      await run(
        [
          ...mcBase(["--entrypoint", "/bin/sh"]),
          "-c",
          `cat > /tmp/policy.json && mc admin policy create ark ${policyName} /tmp/policy.json`,
        ],
        { stdin: JSON.stringify(policy) },
      );
    }
    await mc([
      "admin",
      "policy",
      "attach",
      "ark",
      typeof policy === "string" ? policy : policyName,
      "--user",
      name,
    ]);
    return { accessKeyId: name, secretAccessKey };
  };
  return {
    container,
    port,
    endpoint,
    rootUser,
    rootPassword,
    mc,
    createUser,
    stop: async () => {
      await run(["docker", "rm", "--force", "--volumes", container], { allowFailure: true });
    },
  };
}

/** The "full-access" negative fixture: every S3 action on one bucket. */
export function fullAccessPolicy(bucket: string) {
  return {
    Version: "2012-10-17",
    Statement: [
      { Effect: "Allow", Action: ["s3:*"], Resource: [`arn:aws:s3:::${bucket}`, `arn:aws:s3:::${bucket}/*`] },
    ],
  };
}

/** Read-only recovery credential: list and read, nothing else (restic restore runs with --no-lock). */
export function readOnlyPolicy(bucket: string, prefix: string) {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: ["s3:ListBucket", "s3:GetBucketLocation"],
        Resource: [`arn:aws:s3:::${bucket}`],
      },
      { Effect: "Allow", Action: ["s3:GetObject"], Resource: [`arn:aws:s3:::${bucket}/${prefix}/*`] },
    ],
  };
}
