// Restricted HAProxy configuration validator (docs/design/front-door.md §3.8.6, FD-25).
//
// Runs in the `haproxy-validator` image: the same pinned HAProxy build as edge-l4 (same digest), plus
// Bun for this daemon, as the image's non-root `haproxy` user with no capabilities, no network and no
// Docker access. It mounts the configuration directory read-only at the same absolute path as edge-l4
// and listens only on a Unix socket shared (group 4400, mode 0660) with the domain worker.
//
// It accepts exactly one request: `POST /v1/validate` with `{"generation":"<64 hex>"}`. It resolves
// that generation beneath `<root>/generations`, refuses symlinks and anything that is not a plain
// file or directory, re-computes the content hash (which must equal the ID), then runs the fixed argv
// `haproxy -c -f <root>/generations/<id>/haproxy.cfg` (and the closed variant) with a 10 s timeout and
// ARK_EDGE_L4_GENERATION set to that directory (the base of the generation's relative paths). It
// answers the hash and bounded diagnostics. No command, flag or path comes from the caller.
import { chmod, realpath, rm } from "node:fs/promises";
import { dirname, join } from "node:path";

import { EDGE_L4_GENERATION_ENV, GENERATION_ID, hashGenerationDir } from "@ark-stack/shared";

const root = process.env.ARK_EDGE_L4_DIR ?? "/usr/local/etc/haproxy";
const socket = process.env.ARK_HAPROXY_VALIDATOR_SOCKET ?? "/var/run/haproxy-validator/validate.sock";
const haproxy = process.env.ARK_HAPROXY_BIN ?? "/usr/local/sbin/haproxy";
const timeoutMs = 10_000;
const maxDiagnostics = 4_000;

const log = (line: string) => console.log(`${new Date().toISOString()} ${line}`);

async function check(config: string) {
  const child = Bun.spawn([haproxy, "-c", "-f", config], {
    cwd: dirname(config),
    // Relative paths resolve from the candidate generation, as they do from `current` when serving.
    env: {
      PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      [EDGE_L4_GENERATION_ENV]: dirname(config),
    },
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
    timeout: timeoutMs,
    killSignal: "SIGKILL",
  });
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return {
    ok: code === 0 && !child.signalCode,
    output: `${stdout}${stderr}`.trim(),
    signal: child.signalCode,
  };
}

async function validate(generation: string) {
  if (!GENERATION_ID.test(generation))
    return { status: 400, body: { ok: false, diagnostics: "invalid generation id" } };
  const generations = await realpath(join(root, "generations"));
  const requested = join(generations, generation);
  let resolved: string;
  try {
    resolved = await realpath(requested);
  } catch {
    return { status: 404, body: { ok: false, diagnostics: "no such generation" } };
  }
  // The generation directory itself must not be a symlink or escape the generations directory.
  if (resolved !== requested)
    return { status: 400, body: { ok: false, diagnostics: "generation path escapes" } };
  let hash: string;
  try {
    hash = await hashGenerationDir(resolved);
  } catch (error) {
    return { status: 422, body: { ok: false, diagnostics: (error as Error).message } };
  }
  if (hash !== generation) {
    return {
      status: 422,
      body: { ok: false, hash, diagnostics: "generation content does not match its id" },
    };
  }
  const diagnostics: string[] = [];
  for (const name of ["haproxy.cfg", "haproxy.closed.cfg"]) {
    const result = await check(join(resolved, name));
    const output = result.output.replace(/^Configuration file is valid\s*$/m, "").trim();
    if (output) diagnostics.push(`${name}: ${output}`);
    if (!result.ok) {
      return {
        status: 422,
        body: {
          ok: false,
          hash,
          diagnostics:
            (result.signal ? `${name}: haproxy -c timed out\n` : "") +
            diagnostics.join("\n").slice(-maxDiagnostics),
        },
      };
    }
  }
  return {
    status: 200,
    body: { ok: true, hash, diagnostics: diagnostics.join("\n").slice(-maxDiagnostics) },
  };
}

// One validation at a time: the work is bounded and the caller holds the edge lock anyway.
let queue: Promise<unknown> = Promise.resolve();

await rm(socket, { force: true });
const server = Bun.serve({
  unix: socket,
  async fetch(request) {
    const { pathname } = new URL(request.url);
    if (pathname !== "/v1/validate") return new Response("not found\n", { status: 404 });
    if (request.method !== "POST") return new Response("method not allowed\n", { status: 405 });
    const text = await request.text();
    if (text.length > 1_024)
      return Response.json({ ok: false, diagnostics: "request too large" }, { status: 413 });
    let generation = "";
    try {
      const body = JSON.parse(text) as { generation?: unknown };
      if (Object.keys(body).some((key) => key !== "generation")) throw new Error("unexpected field");
      generation = typeof body.generation === "string" ? body.generation : "";
    } catch {
      return Response.json({ ok: false, diagnostics: "invalid request" }, { status: 400 });
    }
    const run = queue.then(() => validate(generation));
    queue = run.catch(() => undefined);
    const result = await run.catch((error: Error) => ({
      status: 500,
      body: { ok: false, diagnostics: `validator error: ${error.message}` },
    }));
    log(`validate ${generation.slice(0, 12)}: ${result.body.ok ? "valid" : `refused (${result.status})`}`);
    return Response.json({ generation, ...result.body }, { status: result.status });
  },
});
// Group 4400 comes from the setgid socket directory; the domain worker connects through the group.
await chmod(socket, 0o660);
log(`haproxy validator on ${socket}; generations under ${root}/generations`);

const shutdown = () => {
  void server.stop(true);
  process.exit(0);
};
process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);
