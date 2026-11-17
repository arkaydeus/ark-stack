// Watches a listener inside the edge-ts network namespace for `mise run test:edge`, such as Caddy's
// loopback-only HTTPS listener on 127.0.0.1:8443. `listener-probe.ts` runs in the pinned Bun image
// with `--network container:<edge-ts>` and reports each open/closed transition on stdout; this side
// timestamps a transition when its line arrives, so a measured time is never earlier than the real one.
// Probing the listener directly keeps HAProxy's connect handling on 443 out of listener timings; the
// suites still check the end-to-end outcome through 443 separately.
import { join } from "node:path";

import type { EdgeTestRuntime } from "./runtime.ts";

export type ListenerState = "open" | "closed";
export type ListenerTransition = { state: ListenerState; code?: string; at: number };

export type ListenerWatch = {
  /** Every transition seen so far, in order. */
  transitions: ListenerTransition[];
  /** Host time of the first transition to `state` seen at or after `since`, or null after `timeoutMs`. */
  next: (state: ListenerState, since: number, timeoutMs: number) => Promise<number | null>;
  stop: () => Promise<void>;
};

export async function watchListener(options: {
  runtime: EdgeTestRuntime;
  /** Container whose network namespace the prober joins (edge-ts). */
  namespace: string;
  /** Unique container name; it is registered with the runtime for cleanup. */
  name: string;
  image: string;
  host?: string;
  port?: number;
  intervalMs?: number;
}): Promise<ListenerWatch> {
  const { runtime, name } = options;
  runtime.containers.push(name);
  const child = Bun.spawn(
    [
      "docker",
      "run",
      "--rm",
      "--name",
      name,
      "--network",
      `container:${options.namespace}`,
      "--volume",
      `${join(import.meta.dir, "listener-probe.ts")}:/fixture/listener-probe.ts:ro`,
      options.image,
      "bun",
      "/fixture/listener-probe.ts",
      options.host ?? "127.0.0.1",
      String(options.port ?? 8443),
      String(options.intervalMs ?? 50),
    ],
    { stdout: "pipe", stderr: "pipe" },
  );
  const transitions: ListenerTransition[] = [];
  const waiters = new Set<() => void>();
  void (async () => {
    const decoder = new TextDecoder();
    let pending = "";
    const reader = child.stdout.getReader();
    for (;;) {
      const { done, value: chunk } = await reader.read();
      if (done) break;
      const at = Date.now();
      pending += decoder.decode(chunk, { stream: true });
      let newline = pending.indexOf("\n");
      while (newline >= 0) {
        const line = pending.slice(0, newline).trim();
        pending = pending.slice(newline + 1);
        newline = pending.indexOf("\n");
        if (!line) continue;
        try {
          const parsed = JSON.parse(line) as { state: ListenerState; code?: string };
          transitions.push({ ...parsed, at });
        } catch {
          // Not a probe line.
        }
      }
      for (const wake of waiters) wake();
    }
  })();

  const next = (state: ListenerState, since: number, timeoutMs: number) =>
    new Promise<number | null>((resolveNext) => {
      const check = () => {
        const found = transitions.find((transition) => transition.state === state && transition.at >= since);
        if (!found) return false;
        finish(found.at);
        return true;
      };
      const finish = (value: number | null) => {
        clearTimeout(timer);
        waiters.delete(wake);
        resolveNext(value);
      };
      const wake = () => void check();
      const timer = setTimeout(() => finish(null), timeoutMs);
      waiters.add(wake);
      check();
    });

  const stop = async () => {
    await runtime.docker("rm", "--force", name).catch(() => undefined);
    child.kill();
    await child.exited;
  };

  // Ready once the prober has seen the listener open (pulling the image, if needed, comes first).
  const opened = await next("open", 0, 60_000);
  if (opened === null) {
    await stop();
    const stderr = await new Response(child.stderr).text().catch(() => "");
    throw new Error(
      `Listener probe ${name} never saw ${options.host ?? "127.0.0.1"}:${options.port ?? 8443} open` +
        (transitions.length ? ` (last: ${JSON.stringify(transitions.at(-1))})` : "") +
        (stderr ? `: ${stderr.slice(0, 500)}` : ""),
    );
  }
  return { transitions, next, stop };
}
