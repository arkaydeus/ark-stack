// `ARK_ALLOWLIST_HELPER` for hosts that apply the tcp/5432 nft policy (`inet ark_db_ingress`, FD-18
// per-source limits) without the `database-ingress` reconciler. Since FD-26 nothing here opens or closes
// the public port: HAProxy's `fe_pg5432` owns 5432 and renders `be_pgbouncer` only while a database is
// published (docs/design/front-door.md §3.8.3).
import { existsSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { writeFile } from "node:fs/promises";

import { dbIngressAllowlistEnforced, sha256Hex } from "@ark-stack/shared";

const file = process.argv[2] ?? join(process.cwd(), "tmp", "pgbouncer", "allowlist.nft");
const dir = join(file, "..");
const statusFile = join(dir, "allowlist.status");

if (!existsSync(file)) {
  console.error(`Allowlist file not found: ${file}`);
  process.exit(1);
}

function run(command: string, args: string[]) {
  return new Promise<string>((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.on("data", (chunk) => {
      output += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      output += String(chunk);
    });
    child.on("exit", (code) => {
      if (code === 0) resolve(output);
      else reject(new Error(`${command} exited ${code}: ${output.slice(0, 1000)}`));
    });
  });
}

const rules = await Bun.file(file).text();
try {
  await run("nft", ["-f", file]);
  const listed = await run("nft", ["list", "table", "inet", "ark_db_ingress"]);
  if (!listed.includes("ark_db")) throw new Error("nft readback did not show ark_db_ingress");
  // An empty allowlist installs only the per-source limits, so the table exists but no CIDR
  // allowlist is enforced. Report that honestly rather than claiming enforcement.
  await writeFile(
    statusFile,
    `applied=true\nenforced=${dbIngressAllowlistEnforced(rules)}\npolicy_hash=${sha256Hex(rules)}\nerror=\n`,
    { mode: 0o600 },
  );
} catch (error) {
  await writeFile(
    statusFile,
    `applied=false\nenforced=false\npolicy_hash=${sha256Hex(rules)}\nerror=${error instanceof Error ? error.message : "failed"}\n`,
    { mode: 0o600 },
  );
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
}
