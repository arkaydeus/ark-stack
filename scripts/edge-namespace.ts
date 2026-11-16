// Puts `network_mode: service:` dependents (today `edge`, later `edge-l4`) back into their owner's
// live namespace. A restarted or recreated `edge-ts` leaves `edge` running with only loopback, so the
// public edge stops serving until `edge` is recreated (docs/design/front-door.md §3.6).
//
// `mise run maintain` runs this after every applied release; `mise run edge:rejoin` runs it on demand,
// for example after enrolling the edge node or after `edge-ts` restarted on its own.
import { join } from "node:path";

import { type NamespaceContainer, staleNamespaceDependents } from "@ark-stack/shared";

async function capture(args: string[]) {
  const child = Bun.spawn(args, { stdout: "pipe", stderr: "pipe" });
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (status !== 0) throw new Error(`${args.slice(0, 3).join(" ")} failed: ${stderr.trim()}`);
  return stdout;
}

/** Inspects every container of a Compose project, running or not. */
export async function projectContainers(project: string): Promise<NamespaceContainer[]> {
  const ids = (
    await capture([
      "docker",
      "ps",
      "--all",
      "--quiet",
      "--filter",
      `label=com.docker.compose.project=${project}`,
    ])
  )
    .split("\n")
    .filter(Boolean);
  if (!ids.length) return [];
  const inspected = JSON.parse(await capture(["docker", "inspect", ...ids])) as Array<{
    Id: string;
    Config: { Labels?: Record<string, string> };
    HostConfig: { NetworkMode: string };
    State: { Running: boolean; StartedAt: string };
  }>;
  return inspected.map((container) => ({
    service: container.Config.Labels?.["com.docker.compose.service"] ?? container.Id,
    id: container.Id,
    networkMode: container.HostConfig.NetworkMode,
    running: container.State.Running,
    startedAt: container.State.StartedAt,
  }));
}

export type RejoinOptions = {
  project: string;
  /** Global `docker compose` arguments that select the project, such as `-f <file> -p <project>`. */
  composeArgs: string[];
  log?: (line: string) => void;
};

/**
 * Recreates every dependent whose namespace owner was restarted or replaced. The owners themselves
 * must already be running (`docker compose up` starts them); nothing else in the project is touched.
 */
export async function rejoinNamespaceDependents({ project, composeArgs, log = console.log }: RejoinOptions) {
  const containers = await projectContainers(project);
  const stale = staleNamespaceDependents(containers);
  if (!stale.length) {
    log(`${project}: every network_mode: service: dependent is in its owner's live namespace.`);
    return stale;
  }
  for (const dependent of stale) {
    const owner = containers.find((container) => container.service === dependent.parent);
    if (owner && !owner.running) {
      throw new Error(
        `${dependent.service} shares ${owner.service}'s namespace, but ${owner.service} is not running. Start it first.`,
      );
    }
    log(`${project}: recreating ${dependent.service} (${dependent.reason.replaceAll("-", " ")}).`);
  }
  const services = [...new Set(stale.map((dependent) => dependent.service))];
  const child = Bun.spawn(
    [
      "docker",
      "compose",
      ...composeArgs,
      "up",
      "--detach",
      "--no-deps",
      "--force-recreate",
      "--no-build",
      "--pull",
      "never",
      "--wait",
      "--wait-timeout",
      "120",
      ...services,
    ],
    { stdout: "inherit", stderr: "inherit" },
  );
  const status = await child.exited;
  if (status !== 0)
    throw new Error(`Recreating ${services.join(", ")} failed (docker compose exited ${status}).`);
  const remaining = staleNamespaceDependents(await projectContainers(project));
  if (remaining.length) {
    throw new Error(
      `Still outside their owner's namespace: ${remaining.map((item) => item.service).join(", ")}.`,
    );
  }
  return stale;
}

if (import.meta.main) {
  const project = process.env.ARK_PLATFORM_PROJECT ?? "ark-platform";
  const compose =
    process.env.ARK_PLATFORM_COMPOSE ??
    join(import.meta.dir, "..", "infra", "platform", "docker-compose.yml");
  await rejoinNamespaceDependents({ project, composeArgs: ["-f", compose, "-p", project] });
}
