import { spawn } from "node:child_process";

import { generateInstallSecrets } from "@ark-stack/shared";
import postgres from "postgres";

const root = new URL("..", import.meta.url).pathname;
const sourceUrl = process.env.DATABASE_URL;
if (!sourceUrl) throw new Error("DATABASE_URL is required for the disposable browser harness.");
const parsed = new URL(sourceUrl);
if (!["127.0.0.1", "localhost", "::1"].includes(parsed.hostname)) {
  throw new Error("Browser tests refuse a non-loopback PostgreSQL endpoint.");
}
const suffix = crypto.randomUUID().replaceAll("-", "").slice(0, 12);
const databaseName = `ark_e2e_${suffix}`;
const port = 32_000 + Math.floor(Math.random() * 1_000);
const baseUrl = `http://127.0.0.1:${port}`;
if (!/^ark_e2e_[a-f0-9]{12}$/.test(databaseName)) throw new Error("Unsafe disposable database name.");
const databaseUrl = new URL(sourceUrl);
databaseUrl.pathname = `/${databaseName}`;
const secrets = generateInstallSecrets();
const serverEnv = {
  ...process.env,
  ...secrets,
  DATABASE_URL: databaseUrl.toString(),
  ARK_LISTEN_PORT: String(port),
  BETTER_AUTH_URL: baseUrl,
  BETTER_AUTH_TRUSTED_ORIGINS: baseUrl,
  ARK_DNS_STUB: "1",
  ARK_EMBEDDED_WORKERS: "0",
};
const admin = postgres(sourceUrl, { max: 1 });
let server: ReturnType<typeof spawn> | undefined;

function run(args: string[], env = serverEnv) {
  return new Promise<void>((resolve, reject) => {
    const child = spawn("bun", args, { cwd: root, env, stdio: "inherit" });
    child.once("exit", (code) =>
      code === 0 ? resolve() : reject(new Error(`bun ${args.join(" ")} exited ${code}`)),
    );
  });
}

try {
  await admin.unsafe(`CREATE DATABASE "${databaseName}"`);
  await run(["server/src/migrate.ts"]);
  server = spawn("bun", ["server/src/index.ts"], { cwd: root, env: serverEnv, stdio: "inherit" });
  for (let attempt = 0; attempt < 50; attempt++) {
    if (
      await fetch(`${baseUrl}/api/health`)
        .then((response) => response.ok)
        .catch(() => false)
    ) {
      break;
    }
    if (attempt === 49) throw new Error("Disposable Ark API did not become healthy.");
    await Bun.sleep(100);
  }
  await run(["x", "playwright", "test"], {
    ...serverEnv,
    ARK_E2E_BASE_URL: baseUrl,
    ARK_E2E_SETUP_TOKEN: secrets.ARK_SETUP_TOKEN,
    ARK_E2E_OWNER_PASSWORD: "Browser-Acceptance-Password-123!",
    ARK_E2E_DOMAIN: `e2e-${suffix}.arkstack.dev`,
  });
} finally {
  server?.kill("SIGTERM");
  await admin`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ${databaseName} AND pid <> pg_backend_pid()`;
  const exists = await admin`SELECT 1 FROM pg_database WHERE datname = ${databaseName}`;
  if (exists.length) await admin.unsafe(`DROP DATABASE "${databaseName}"`);
  await admin.end();
}
