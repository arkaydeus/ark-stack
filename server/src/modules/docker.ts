import { existsSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { omitSensitiveLabels, redactLogLine, validateComposeSource } from "@ark-stack/shared";

const exec = promisify(execFile);

export function composeDir(serviceId: string) {
  return process.env.ARK_COMPOSE_DIR
    ? join(process.env.ARK_COMPOSE_DIR, serviceId)
    : join(process.cwd(), "tmp", "compose", serviceId);
}

export async function writeApprovedCompose(serviceId: string, source: string) {
  const policy = validateComposeSource(source);
  if (!policy.ok) throw new Error(policy.violations.map((item) => item.message).join(" "));
  const dir = composeDir(serviceId);
  await mkdir(dir, { recursive: true });
  const file = join(dir, "compose.yml");
  await Bun.write(file, source);
  return { file, policy };
}

async function docker(args: string[]) {
  return exec("docker", args, {
    timeout: 60_000,
    env: { PATH: process.env.PATH ?? "/usr/bin:/usr/local/bin" },
  });
}

export async function deployCompose(project: string, file: string) {
  const { stdout, stderr } = await docker([
    "compose",
    "-f",
    file,
    "-p",
    project,
    "up",
    "-d",
    "--no-build",
    "--pull",
    "never",
  ]);
  return redactLogLine(`${stdout}\n${stderr}`);
}

export async function serviceAction(project: string, service: string, action: "start" | "stop" | "restart") {
  const { stdout, stderr } = await docker(["compose", "-p", project, action, service]);
  return redactLogLine(`${stdout}\n${stderr}`);
}

export async function inspectService(project: string, service: string) {
  const { stdout } = await docker(["compose", "-p", project, "ps", "--format", "json", service]);
  const parsed = JSON.parse(stdout || "{}") as Record<string, unknown>;
  if (parsed.Labels && typeof parsed.Labels === "object") {
    parsed.Labels = omitSensitiveLabels(parsed.Labels as Record<string, string>);
  }
  delete parsed.Environment;
  return parsed;
}

export async function serviceLogs(project: string, service: string, tail = 200) {
  const { stdout, stderr } = await docker([
    "compose",
    "-p",
    project,
    "logs",
    "--no-color",
    "--timestamps",
    "--tail",
    String(Math.min(tail, 500)),
    service,
  ]);
  return redactLogLine(`${stdout}\n${stderr}`).split("\n").filter(Boolean).slice(-500);
}

export async function serviceStats(project: string, service: string) {
  const { stdout } = await docker(["compose", "-p", project, "ps", "--format", "json", service]);
  const parsed = JSON.parse(stdout.trim().split("\n")[0] || "{}") as Record<string, unknown>;
  const id = String(parsed.ID ?? parsed.Id ?? "");
  if (!id) return { service, available: false };
  const stats = await docker(["stats", "--no-stream", "--format", "{{json .}}", id]);
  const row = JSON.parse(stats.stdout || "{}") as Record<string, unknown>;
  return {
    service,
    cpu: row.CPUPerc,
    memory: row.MemUsage,
    net: row.NetIO,
    block: row.BlockIO,
    pids: row.PIDs,
  };
}

export async function discoverContainers() {
  if (!dockerAvailable()) return [];
  const { stdout } = await docker(["ps", "-a", "--format", "{{json .}}"]);
  return stdout
    .split("\n")
    .filter(Boolean)
    .map(
      (line) =>
        JSON.parse(line) as { ID: string; Names: string; Image: string; State: string; Labels: string },
    )
    .map((row) => ({
      id: row.ID,
      name: row.Names,
      image: row.Image,
      state: row.State,
      labels: Object.fromEntries(
        (row.Labels ?? "")
          .split(",")
          .filter(Boolean)
          .map((item) => {
            const eq = item.indexOf("=");
            return [item.slice(0, eq), item.slice(eq + 1)];
          }),
      ) as Record<string, string>,
    }))
    .map((row) => ({ ...row, labels: omitSensitiveLabels(row.labels) }));
}

export function dockerAvailable() {
  return Boolean(
    process.env.DOCKER_HOST || process.env.ARK_DOCKER === "1" || existsSync("/var/run/docker.sock"),
  );
}
