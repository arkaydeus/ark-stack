import { existsSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";

const file = process.argv[2] ?? join(process.cwd(), "tmp", "pgbouncer", "allowlist.nft");
if (!existsSync(file)) {
  console.error(`Allowlist file not found: ${file}`);
  process.exit(1);
}

const child = spawn("nft", ["-f", file], { stdio: "inherit" });
child.on("exit", (code) => {
  process.exit(code ?? 1);
});
