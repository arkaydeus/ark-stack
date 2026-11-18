// Control of the HAProxy SNI router (`edge-l4`) over its shared Unix sockets (docs/design/front-door.md
// §3.8.6, FD-25): the master CLI (`show proc`, `reload`, `@!<pid>` worker commands), the admin socket,
// the restricted validator and the immutable generation directory. Nothing here uses Docker.
//
// - `HaproxyWithdrawalAdapter` is the FD-06 `EdgeWithdrawalAdapter` for HAProxy. Admission first:
//   in every worker that still accepts connections it disables each denied tailnet server, then shuts
//   its sessions down; in leaving workers (listeners already closed, where server commands answer
//   "Proxy is disabled.") it shuts each affected session down individually. It re-enumerates `show
//   proc` until the worker set is stable and verifies with worker-local `show servers state` and
//   `show sess` that no affected session remains. Success is never inferred from one socket.
// - `installEdgeL4Generation` writes a complete immutable generation, has the validator check it,
//   verifies no byte changed, swaps `current` atomically and reloads through the master CLI. An
//   invalid candidate never changes `current` and no reload is sent.
// - `HaproxyMaster.reload` serialises every reloader on one `flock(2)` file shared with the edge-l4
//   launch guard and confirms an unanswered reload from the workers (see its comment for the race).

import {
  lstat,
  mkdir,
  readdir,
  readFile,
  readlink,
  rename,
  rm,
  symlink,
  chmod,
  writeFile,
} from "node:fs/promises";
import { closeSync, constants, fchmodSync, openSync } from "node:fs";
import { createConnection } from "node:net";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

import {
  allowedServerIndex,
  GENERATION_ID,
  generationId,
  haproxyHttpHostname,
  haproxyServerDenied,
  haproxyServerProtected,
  loopTargetServer,
  edgeL4ConfigVersion,
  parseReload,
  parseServersState,
  parseShowInfoVersion,
  parseShowProc,
  parseShowSess,
  parseShowStat,
  type SessionInfo,
  SERVER_FORCED_MAINT,
  type EdgeL4Generation,
  type HaproxyProcess,
  type ServerState,
} from "./edge-l4.ts";
import type { EdgeWithdrawalAdapter, WithdrawalResult } from "./edge-withdrawal.ts";

export type HaproxyCli = (socket: string, command: string, timeoutMs?: number) => Promise<string>;

/** One non-interactive CLI command: write the line, read until HAProxy closes the connection. */
export const haproxyCli: HaproxyCli = (socket, command, timeoutMs = 3_000) =>
  new Promise((resolve, reject) => {
    if (/[\r\n]/.test(command)) {
      reject(new Error("HAProxy CLI commands are a single line"));
      return;
    }
    const connection = createConnection(socket);
    const chunks: Buffer[] = [];
    const timer = setTimeout(() => {
      connection.destroy();
      reject(new Error(`HAProxy CLI ${command.split(" ").slice(0, 3).join(" ")} timed out`));
    }, timeoutMs);
    connection.on("connect", () => connection.end(`${command}\n`));
    connection.on("data", (chunk: Buffer) => chunks.push(chunk));
    connection.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    connection.on("close", () => {
      clearTimeout(timer);
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
  });

/** Errors a worker command may answer with; everything else non-empty is unexpected. */
const PROXY_STOPPED = /Proxy is disabled/i;
const WORKER_GONE = /Can't find the target PID|Can't connect to the target CLI/i;

export class WorkerGoneError extends Error {}

/** Thin master-CLI client used by the adapter, the domain worker and tests. */
export class HaproxyMaster {
  private readonly options: HaproxyMasterOptions;

  constructor(
    readonly socket: string,
    private readonly cli: HaproxyCli = haproxyCli,
    private readonly timeoutMs = 3_000,
    options: HaproxyMasterOptions = {},
  ) {
    // A lock only means something next to a real master socket; injected CLIs (tests) opt in.
    const lock =
      options.lock === undefined ? (cli === haproxyCli ? haproxyReloadLockPath(socket) : null) : options.lock;
    this.options = { ...options, lock };
  }

  command(command: string, timeoutMs = this.timeoutMs) {
    return this.cli(this.socket, command, timeoutMs);
  }

  /** Current and leaving workers (the master and external programs excluded). */
  async workers(): Promise<HaproxyProcess[]> {
    // The Unix listener can refuse a connect briefly while the master re-execs on reload.
    // Retry within the watchdog pass without treating a failed inspection as verified.
    let text: string;
    for (let attempt = 0; ; attempt++) {
      try {
        text = await this.command("show proc");
        break;
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (attempt >= 3 || (code !== "ECONNREFUSED" && code !== "ENOENT")) throw error;
        await new Promise((resolve) => setTimeout(resolve, 75));
      }
    }
    if (!/<PID>|master/.test(text)) throw new Error(`unexpected show proc answer: ${text.slice(0, 120)}`);
    const workers = parseShowProc(text).filter((process) => process.type === "worker");
    if (!workers.length) throw new Error("show proc returned no inspectable worker");
    return workers;
  }

  async worker(pid: number, command: string) {
    const text = await this.command(`@!${pid} ${command}`);
    if (WORKER_GONE.test(text)) throw new WorkerGoneError(`worker ${pid} has exited`);
    return text;
  }

  async servers(pid: number): Promise<ServerState[]> {
    const text = await this.worker(pid, "show servers state");
    if (!/^#.*be_id.*srv_name/m.test(text)) throw new Error("incomplete show servers state answer");
    const servers = parseServersState(text);
    if (
      !text.endsWith("\n") ||
      !servers.length ||
      servers.some(
        (server) =>
          !server.backend ||
          !server.server ||
          !Number.isInteger(server.port) ||
          !Number.isInteger(server.adminState) ||
          !Number.isInteger(server.operState),
      )
    ) {
      throw new Error("incomplete show servers state answer");
    }
    return servers;
  }

  async sessions(pid: number) {
    const text = await this.worker(pid, "show sess");
    const sessions = parseShowSess(text);
    // Worker-local CLI inspection itself appears as GLOBAL. A missing/truncated dump is not
    // evidence that the protected sessions disappeared during a racing master reload.
    if (
      !text.endsWith("\n") ||
      !sessions.some((session) => session.frontend === "GLOBAL") ||
      text.split("\n").filter((line) => line.trim()).length !== sessions.length
    ) {
      throw new Error("incomplete show sess answer");
    }
    return sessions;
  }

  async stat(pid: number) {
    return parseShowStat(await this.worker(pid, "show stat"));
  }

  /** The content version (`EDGE_L4_VERSION_MARKER`) a worker loaded, or null when it is unmarked. */
  async loadedVersion(pid: number) {
    const text = await this.worker(pid, "show info");
    // A connection dropped by a racing reload answers nothing; that is not an unmarked worker.
    if (!/^Pid: \d+/m.test(text)) throw new Error("incomplete show info answer");
    return parseShowInfoVersion(text);
  }

  /**
   * Synchronous master reload: `Success=1` once the new worker is up, `Success=0` otherwise.
   *
   * Every reloader (this method, so `edge.l4_apply`, and the edge-l4 launch guard) holds the shared
   * reload lock (`haproxyReloadLockPath`) for the whole request, so two reloads never meet at the master.
   * Why that matters (FD-25, HAProxy 3.2): the master re-executes itself as soon as it parses a
   * `reload`. Only the connection that sent it survives the exec and is answered. Every other master
   * CLI connection the old master had accepted is closed with no reply, including a second `reload`,
   * which is never executed at all (two concurrent reloads advance the master's reload count by one).
   * That is how `edge.l4_apply` used to fail with "the master CLI did not answer the reload" while the
   * launch guard's own reopen reload succeeded on the very configuration the worker had just swapped in.
   *
   * A request that lost such a race ends one of three ways, depending on when it reached the master,
   * and in none of them did it run: the connection closes with no bytes (accepted by the old master),
   * the connect is refused (during the exec), or the new master answers `Success=0` with "Another
   * reload is still in progress." (before the new worker is ready). The last one is not an invalid
   * configuration and is handled like the first two.
   *
   * Such a request (unanswered, refused, timed out or refused as busy) is ambiguous, not a failure:
   * a reloader outside the lock can still cause it. It is confirmed from the workers instead. It counts
   * as succeeded only when every current worker is new since the request and reports the `expect`ed
   * content version in `show info`. Without `expect` (an unmarked configuration) nothing can prove
   * which configuration a new worker read, so the request is only sent again. Either way an unconfirmed
   * request is sent again, up to `reloadAttempts` times with doubling backoff. An answered `Success=0`
   * (an invalid configuration: the old workers keep serving) is returned at once and never retried or
   * confirmed into a success.
   */
  async reload(options: { expect?: string | null; timeoutMs?: number } = {}): Promise<ReloadOutcome> {
    const release = this.options.lock
      ? await acquireReloadLock(this.options.lock, this.options.lockWaitMs)
      : null;
    try {
      return await this.reloadLocked(options.expect ?? null, options.timeoutMs ?? 60_000);
    } finally {
      release?.();
    }
  }

  private async reloadLocked(expect: string | null, timeoutMs: number): Promise<ReloadOutcome> {
    const attempts = Math.max(1, this.options.reloadAttempts ?? 5);
    const problems: string[] = [];
    for (let attempt = 1; attempt <= attempts; attempt++) {
      // Taken after the caller's file changes: a worker missing here parsed the configuration later.
      const before = await this.processIds().catch(() => null);
      let text = "";
      let problem = "";
      try {
        text = await this.command("reload", timeoutMs);
      } catch (error) {
        problem = (error as Error).message;
      }
      const answer = parseReload(text);
      if (answer.answered && !RELOAD_BUSY.test(answer.log)) {
        return { ...answer, confirmedBy: "answer", attempts: attempt };
      }
      problems.push(
        problem ||
          (answer.answered
            ? "another reload was still in progress"
            : text
              ? `answer without Success= (${text.length} bytes)`
              : "connection closed without an answer"),
      );
      if (await this.confirmReload(before, expect)) {
        return {
          success: true,
          answered: false,
          log: "",
          confirmedBy: "workers",
          attempts: attempt,
        };
      }
      if (attempt < attempts) {
        await sleep(Math.min((this.options.backoffMs ?? 250) * 2 ** (attempt - 1), 2_000));
      }
    }
    throw new Error(
      `the master CLI did not answer the reload and no worker confirmed it after ${attempts} attempt(s): ${problems.join("; ")}`,
    );
  }

  /** Every listed process ID (master, current and leaving workers). */
  private async processIds() {
    const text = await this.command("show proc");
    if (!/<PID>|master/.test(text)) throw new Error("unexpected show proc answer");
    return new Set(parseShowProc(text).map((process) => process.pid));
  }

  /**
   * True once every current worker started after `before` was taken (when that snapshot exists) and
   * serves the `expect`ed content version. A failed reload never starts a new worker, so it is never
   * confirmed. Worker turnover alone is not proof: a racing reload may have read the files before the
   * caller changed them, so an unmarked configuration is never confirmed this way.
   */
  private async confirmReload(before: Set<number> | null, expect: string | null) {
    if (!expect) return false;
    const deadline = Date.now() + (this.options.confirmMs ?? 10_000);
    for (;;) {
      try {
        const current = (await this.workers()).filter((worker) => worker.section === "current");
        if (current.length && current.every((worker) => !before?.has(worker.pid))) {
          const versions = await Promise.all(current.map((worker) => this.loadedVersion(worker.pid)));
          if (versions.every((version) => version === expect)) return true;
        }
      } catch {
        // The master may still be re-executing; keep asking until the deadline.
      }
      if (Date.now() >= deadline) return false;
      await sleep(100);
    }
  }
}

/** HAProxy 3.2's answer to a `reload` that arrived while another one was still starting its worker. */
const RELOAD_BUSY = /^Another reload is still in progress\.?$/m;

export type ReloadOutcome = ReturnType<typeof parseReload> & {
  /** `answer`: HAProxy's `Success=` line; `workers`: an unanswered request confirmed from the workers. */
  confirmedBy: "answer" | "workers";
  /** Reload requests sent, including unanswered ones. */
  attempts: number;
};

export type HaproxyMasterOptions = {
  /** Shared reload lock file; null disables it. Defaults to `haproxyReloadLockPath` for a real socket. */
  lock?: string | null;
  /** How long `reload` waits for the lock. */
  lockWaitMs?: number;
  /** Reload requests per `reload` call when a request stays unanswered and unconfirmed. */
  reloadAttempts?: number;
  /** How long an unanswered request is confirmed from the workers before it is sent again. */
  confirmMs?: number;
  /** First retry delay; it doubles per attempt. */
  backoffMs?: number;
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// ---- Reload lock ----------------------------------------------------------------------------------------

/**
 * The lock file every master-CLI reloader holds, beside the master socket on the shared
 * `ark_haproxy_run` tmpfs (uid 99, group 4400, mode 2770): the domain worker (uid 1000) and the
 * edge-l4 launch guard (uid 99, BusyBox `flock`) both open it. It is an advisory `flock(2)` lock, so
 * the kernel releases it when a holder exits or crashes; there is no stale lock to recover.
 */
export const HAPROXY_RELOAD_LOCK_NAME = "reload.lock";

export function haproxyReloadLockPath(masterSocket: string) {
  return join(dirname(masterSocket), HAPROXY_RELOAD_LOCK_NAME);
}

const LOCK_EX = 2;
const LOCK_NB = 4;
const LOCK_UN = 8;
let flockCall: Promise<(fd: number, operation: number) => number> | undefined;

/** libc `flock(2)` through Bun's FFI (glibc, musl or macOS). Loaded only by a reloader. */
function loadFlock() {
  flockCall ??= (async () => {
    const { dlopen, FFIType } = await import("bun:ffi");
    const arch = process.arch === "arm64" ? "aarch64" : process.arch === "x64" ? "x86_64" : process.arch;
    const libraries =
      process.platform === "darwin"
        ? ["libSystem.B.dylib", "/usr/lib/libSystem.B.dylib"]
        : ["libc.so.6", `libc.musl-${arch}.so.1`, `/lib/ld-musl-${arch}.so.1`];
    for (const library of libraries) {
      try {
        const { symbols } = dlopen(library, {
          flock: { args: [FFIType.i32, FFIType.i32], returns: FFIType.i32 },
        });
        return (fd: number, operation: number) => Number(symbols.flock(fd, operation));
      } catch {
        // Try the next C library name.
      }
    }
    throw new Error("flock(2) is unavailable: no C library could be loaded");
  })();
  flockCall.catch(() => (flockCall = undefined));
  return flockCall;
}

/**
 * Takes the exclusive reload lock, waiting up to `waitMs`, and returns its release function. Locks
 * are per open file, so two holders in one process exclude each other as two processes do.
 */
export async function acquireReloadLock(path: string, waitMs = 120_000) {
  const flock = await loadFlock();
  // Read-only is enough for flock(2), whichever of uid 1000 and uid 99 created the file.
  const fd = openSync(path, constants.O_RDONLY | constants.O_CREAT, 0o660);
  try {
    fchmodSync(fd, 0o660);
  } catch {
    // Owned by the other identity; its group bits already allow reading.
  }
  const deadline = Date.now() + waitMs;
  for (let delay = 10; ; delay = Math.min(delay * 2, 200)) {
    if (flock(fd, LOCK_EX | LOCK_NB) === 0) break;
    if (Date.now() >= deadline) {
      closeSync(fd);
      throw new Error(`the HAProxy reload lock ${path} is still held after ${waitMs} ms`);
    }
    await sleep(delay);
  }
  let released = false;
  return () => {
    if (released) return;
    released = true;
    flock(fd, LOCK_UN);
    closeSync(fd);
  };
}

/** Verification passes per enforcement; a racing reload or a slow session close gets this many tries. */
const ENFORCE_PASSES = 20;

function legacyCaddyServer(server: Pick<ServerState, "backend" | "server">) {
  return server.backend === "be_caddy" && server.server === "caddy";
}

function sessionName(session: SessionInfo) {
  return `${session.backend}/${session.server}`;
}

function workerSet(workers: HaproxyProcess[]) {
  return workers
    .map((worker) => `${worker.pid}/${worker.section}`)
    .toSorted()
    .join(",");
}

export class HaproxyWithdrawalAdapter implements EdgeWithdrawalAdapter {
  readonly proxy = "haproxy";
  readonly master: HaproxyMaster;
  /** Workers inspected by the latest enforcement pass; `stop` acts on these only. */
  private inspected = new Set<number>();

  constructor(masterSocket: string, cli: HaproxyCli = haproxyCli, timeoutMs = 2_000) {
    this.master = new HaproxyMaster(masterSocket, cli, timeoutMs);
  }

  /** Tailnet backends served by any worker, current or leaving. */
  async activeBackends() {
    const keys = new Set<string>();
    for (const worker of await this.master.workers()) {
      for (const server of await this.master.servers(worker.pid).catch(() => [])) {
        if (server.key) keys.add(server.key);
      }
    }
    return [...keys].toSorted();
  }

  async enforce(allowed: ReadonlySet<string>): Promise<WithdrawalResult> {
    const index = allowedServerIndex(allowed);
    return this.enforceServers((server) => haproxyServerDenied(server, index));
  }

  /** Fences removed or revoked HTTP identities without touching L4 or platform HTTPS. */
  async enforceHttp(allowed: ReadonlySet<string>) {
    const index = allowedServerIndex(allowed);
    return this.enforceServers(
      (server) => haproxyHttpHostname(server) !== null && haproxyServerDenied(server, index),
    );
  }

  /** The first scoped generation retires sockets accepted by the old shared HTTP backend. */
  async retireLegacyHttp() {
    return this.enforceServers(legacyCaddyServer, { retireLegacy: true });
  }

  /** The watchdog leaves legacy admission intact and lets Caddy stop and recover under its lease. */
  async ensureHttpControl() {
    return !(await this.hasLegacyHttp());
  }

  /** A legacy backend can hold connections whose route cannot be determined at layer 4. */
  async hasLegacyHttp() {
    const workers = await this.master.workers();
    const hasCurrent = workers.some((worker) => worker.section === "current");
    if (!hasCurrent) return true;
    const legacy = await Promise.all(
      workers.map(async (worker) => {
        try {
          if (!(await this.master.servers(worker.pid)).some(legacyCaddyServer)) return false;
          return (
            worker.section === "current" ||
            (await this.master.sessions(worker.pid)).some((session) => session.backend === "be_caddy")
          );
        } catch (error) {
          if (error instanceof WorkerGoneError && worker.section === "old") return false;
          throw error;
        }
      }),
    );
    return legacy.some(Boolean);
  }

  private async enforceServers(
    denies: (server: ServerState) => boolean,
    { retireLegacy = false } = {},
  ): Promise<WithdrawalResult> {
    const active = new Set<string>();
    const withdrawn = new Set<string>();
    let workers: HaproxyProcess[];
    this.inspected = new Set();
    try {
      workers = await this.master.workers();
    } catch (error) {
      return {
        proxy: this.proxy,
        active: [],
        withdrawn: [],
        unreachable: true,
        error: `HAProxy master CLI unreachable: ${(error as Error).message}`,
      };
    }
    let problem = "";
    for (let pass = 0; pass < ENFORCE_PASSES; pass++) {
      problem = "";
      let clean = true;
      if (retireLegacy) {
        const current = workers.filter((worker) => worker.section === "current");
        try {
          const servers = await Promise.all(current.map((worker) => this.master.servers(worker.pid)));
          if (
            !servers.length ||
            servers.some(
              (entries) =>
                entries.some(legacyCaddyServer) ||
                !entries.some(
                  (server) => server.backend === "be_caddy" && server.server === "caddy_platform",
                ),
            )
          )
            throw new Error("no confirmed scoped accepting worker");
        } catch (error) {
          return {
            proxy: this.proxy,
            active: [...active].toSorted(),
            withdrawn: [...withdrawn].toSorted(),
            error: `Legacy HTTP retirement requires an accepting scoped generation: ${(error as Error).message}`,
          };
        }
      }
      await Promise.all(
        workers
          .filter((worker) => !retireLegacy || worker.section === "old")
          .map(async (worker) => {
            this.inspected.add(worker.pid);
            try {
              const outcome = await this.enforceWorker(worker.pid, denies, active, withdrawn);
              if (!outcome.clean) {
                clean = false;
                problem = outcome.problem;
              }
            } catch (error) {
              if (error instanceof WorkerGoneError) return;
              clean = false;
              problem = `worker ${worker.pid}: ${(error as Error).message}`;
            }
          }),
      );
      // Re-enumerate: a worker started or left while we were working must be covered too.
      let after: HaproxyProcess[];
      try {
        after = await this.master.workers();
      } catch (error) {
        problem = `HAProxy master CLI failed mid-withdrawal: ${(error as Error).message}`;
        await new Promise((resolve) => setTimeout(resolve, 50));
        continue;
      }
      const stable = workerSet(after) === workerSet(workers);
      workers = after;
      if (clean && stable) {
        return { proxy: this.proxy, active: [...active].toSorted(), withdrawn: [...withdrawn].toSorted() };
      }
      if (!stable && !problem) problem = "the worker set changed during withdrawal";
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return {
      proxy: this.proxy,
      active: [...active].toSorted(),
      withdrawn: [...withdrawn].toSorted(),
      error: `withdrawal failed: ${problem || "affected sessions remain"}`,
    };
  }

  /**
   * Fences and drains one worker. Returns `clean` only when every denied server is fenced (or the
   * worker no longer admits connections) and no session to a denied server remains.
   */
  private async enforceWorker(
    pid: number,
    denies: (server: ServerState) => boolean,
    active: Set<string>,
    withdrawn: Set<string>,
  ) {
    const servers = await this.master.servers(pid);
    const denied = servers.filter(denies);
    for (const server of servers) {
      const key = server.key ?? haproxyHttpHostname(server);
      if (key) active.add(key);
    }
    if (!denied.length) return { clean: true, problem: "" };
    // A loop server has no tailnet address. Report it under its target's backend key.
    const keyFor = (server: ServerState) =>
      server.key ??
      haproxyHttpHostname(server) ??
      servers.find((item) => item.server === loopTargetServer(server.server) && item.key)?.key ??
      server.backend;
    let leaving = false;
    // 1. Admission: disable every denied server in an accepting worker before touching sessions.
    for (const server of denied) {
      if (server.adminState & SERVER_FORCED_MAINT) continue;
      const answer = (
        await this.master.worker(pid, `disable server ${server.backend}/${server.server}`)
      ).trim();
      if (PROXY_STOPPED.test(answer)) leaving = true;
      else if (answer) throw new Error(`disable server ${server.backend}/${server.server}: ${answer}`);
      else withdrawn.add(keyFor(server));
    }
    // 2. Sessions: per server where the proxy runs, per session where it is stopping.
    const deniedNames = new Set(denied.map((server) => `${server.backend}/${server.server}`));
    // Each HTTP backend has one server. Include connections assigned to the backend that are
    // still waiting for its server, as well as connections already attached to that server.
    const httpByBackend = new Map(
      denied
        .filter((server) => haproxyHttpHostname(server) !== null || legacyCaddyServer(server))
        .map((server) => [server.backend, keyFor(server)]),
    );
    const matches = (session: SessionInfo) =>
      deniedNames.has(sessionName(session)) || httpByBackend.has(session.backend);
    const sessions = (await this.master.sessions(pid)).filter(matches);
    const keyOf = new Map(denied.map((server) => [`${server.backend}/${server.server}`, keyFor(server)]));
    for (const name of new Set(sessions.map(sessionName))) {
      const matching = sessions.filter((session) => sessionName(session) === name);
      withdrawn.add(keyOf.get(name) ?? httpByBackend.get(matching[0]!.backend)!);
      if (!leaving && deniedNames.has(name)) {
        const answer = (await this.master.worker(pid, `shutdown sessions server ${name}`)).trim();
        if (!answer) continue;
        if (!PROXY_STOPPED.test(answer)) throw new Error(`shutdown sessions server ${name}: ${answer}`);
        leaving = true;
      }
      // A leaving worker's proxies are stopped and refuse server commands; end each session instead.
      for (const session of matching) {
        const answer = (await this.master.worker(pid, `shutdown session ${session.id}`)).trim();
        if (answer && !/not found|no such|unknown session/i.test(answer)) {
          throw new Error(`shutdown session: ${answer}`);
        }
      }
    }
    // 3. Verify with worker-local inspection.
    const fencedAfter = await this.master.servers(pid);
    const unfenced = fencedAfter.filter(
      (server) =>
        deniedNames.has(`${server.backend}/${server.server}`) && !(server.adminState & SERVER_FORCED_MAINT),
    );
    if (unfenced.length && !leaving) {
      return {
        clean: false,
        problem: `worker ${pid}: ${unfenced.length} denied server(s) still admit connections`,
      };
    }
    const remaining = (await this.master.sessions(pid)).filter(matches);
    if (remaining.length) {
      return {
        clean: false,
        problem: `worker ${pid}: ${remaining.length} session(s) to withdrawn backends remain`,
      };
    }
    return { clean: true, problem: "" };
  }

  /** Fail closed for tailnet backends only; public HTTP is never collateral to a CLI failure.
   * If inspection or fencing fails, the latched launch guard kills the container.
   */
  async stop() {
    if (!this.inspected.size) {
      throw new Error(
        "HAProxy could not be inspected; its launch guard stops it while enforcement is unverified",
      );
    }
    const workers = (await this.master.workers()).filter((worker) => this.inspected.has(worker.pid));
    for (const worker of workers) {
      try {
        const servers = (await this.master.servers(worker.pid)).filter(haproxyServerProtected);
        const names = new Set(servers.map((server) => `${server.backend}/${server.server}`));
        for (const server of servers) {
          const answer = (
            await this.master.worker(worker.pid, `disable server ${server.backend}/${server.server}`)
          ).trim();
          if (answer && !PROXY_STOPPED.test(answer)) throw new Error(answer);
        }
        if (!names.size) continue;
        for (const session of await this.master.sessions(worker.pid)) {
          if (!names.has(`${session.backend}/${session.server}`)) continue;
          const answer = (await this.master.worker(worker.pid, `shutdown session ${session.id}`)).trim();
          if (answer && !/not found|no such|unknown session/i.test(answer)) throw new Error(answer);
        }
      } catch (error) {
        if (!(error instanceof WorkerGoneError)) throw error;
      }
    }
  }
}

// ---- Validator client ---------------------------------------------------------------------------------

export type ValidationAnswer = { ok: boolean; generation: string; hash?: string; diagnostics?: string };

/** `POST /v1/validate` on the restricted validator's Unix socket. */
export async function validateGeneration(socket: string, generation: string, timeoutMs = 25_000) {
  const response = await fetch("http://haproxy-validator/v1/validate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ generation }),
    unix: socket,
    signal: AbortSignal.timeout(timeoutMs),
  } as RequestInit);
  const body = (await response.json().catch(() => ({}))) as Partial<ValidationAnswer>;
  return {
    ok: response.ok && body.ok === true,
    generation,
    hash: typeof body.hash === "string" ? body.hash : undefined,
    diagnostics:
      typeof body.diagnostics === "string"
        ? body.diagnostics.slice(0, 4_000)
        : `validator returned ${response.status}`,
  } satisfies ValidationAnswer;
}

// ---- Generation directory -----------------------------------------------------------------------------

/**
 * Reads every regular file under a generation directory and returns its content hash. Symlinks,
 * devices and anything else that is not a plain file or directory make it invalid.
 */
export async function hashGenerationDir(directory: string) {
  const files: Record<string, Uint8Array> = {};
  const walk = async (relative: string) => {
    for (const entry of await readdir(join(directory, relative), { withFileTypes: true })) {
      const path = relative ? `${relative}/${entry.name}` : entry.name;
      const info = await lstat(join(directory, path));
      if (info.isSymbolicLink()) throw new Error(`generation contains a symlink: ${path}`);
      if (info.isDirectory()) await walk(path);
      else if (info.isFile()) files[path] = new Uint8Array(await readFile(join(directory, path)));
      else throw new Error(`generation contains a non-regular file: ${path}`);
    }
  };
  await walk("");
  return generationId(files);
}

/** Generation directories are `2750`, files `0640`: the worker writes, the shared group reads (§3.8.6). */
const DIR_MODE = 0o2750;
const FILE_MODE = 0o640;

/** Writes a complete generation under `<root>/generations/<id>` (atomically, by rename). */
export async function writeGeneration(root: string, generation: EdgeL4Generation) {
  const generations = join(root, "generations");
  await mkdir(generations, { recursive: true });
  const target = join(generations, generation.id);
  const existing = await hashGenerationDir(target).catch(() => null);
  if (existing === generation.id) return { path: target, reused: true };
  if (existing !== null || (await lstat(target).catch(() => null)))
    await rm(target, { recursive: true, force: true });
  const staging = join(generations, `.staging-${randomBytes(6).toString("hex")}`);
  await mkdir(staging, { mode: DIR_MODE });
  await chmod(staging, DIR_MODE).catch(() => undefined);
  try {
    for (const [path, content] of Object.entries(generation.files)) {
      const parts = path.split("/");
      for (let depth = 1; depth < parts.length; depth++) {
        const dir = join(staging, ...parts.slice(0, depth));
        await mkdir(dir, { recursive: true, mode: DIR_MODE });
        await chmod(dir, DIR_MODE).catch(() => undefined);
      }
      await writeFile(join(staging, path), content, { mode: FILE_MODE });
      await chmod(join(staging, path), FILE_MODE);
    }
    const written = await hashGenerationDir(staging);
    if (written !== generation.id)
      throw new Error(`generation ${generation.id} hashed to ${written} after writing`);
    await rename(staging, target);
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
  return { path: target, reused: false };
}

/** The generation `current` points at, or null. */
export async function currentGeneration(root: string) {
  const link = await readlink(join(root, "current")).catch(() => null);
  const match = link ? /^generations\/([a-f0-9]{64})$/.exec(link) : null;
  return match ? match[1]! : null;
}

/** Atomically points `current` at a generation (a relative symlink, renamed over the old one). */
export async function pointCurrent(root: string, id: string) {
  if (!GENERATION_ID.test(id)) throw new Error("invalid generation id");
  const next = join(root, `.current-${randomBytes(6).toString("hex")}`);
  await symlink(`generations/${id}`, next);
  try {
    await rename(next, join(root, "current"));
  } catch (error) {
    await rm(next, { force: true });
    throw error;
  }
}

/** Removes generations other than `keep` (only when no worker is leaving, so none still needs them). */
export async function pruneGenerations(root: string, keep: string[]) {
  const generations = join(root, "generations");
  const removed: string[] = [];
  for (const entry of await readdir(generations).catch(() => [])) {
    if (keep.includes(entry)) continue;
    if (!GENERATION_ID.test(entry) && !entry.startsWith(".staging-")) continue;
    await rm(join(generations, entry), { recursive: true, force: true });
    removed.push(entry);
  }
  return removed;
}

export type InstallResult = {
  generation: string;
  previous: string | null;
  changed: boolean;
  reloaded: boolean;
  reloadLog?: string;
  /** `workers` when HAProxy's answer was lost and the reload was confirmed from the serving worker. */
  reloadConfirmedBy?: ReloadOutcome["confirmedBy"];
  reloadAttempts?: number;
  pruned: string[];
};

export class InvalidGenerationError extends Error {
  constructor(
    readonly generation: string,
    readonly diagnostics: string,
  ) {
    super(`HAProxy refused generation ${generation.slice(0, 12)}: ${diagnostics.slice(0, 500)}`);
  }
}

/**
 * The apply sequence of §3.8.6. The caller holds the edge lock.
 * 1. write the complete immutable generation;
 * 2. the restricted validator checks it (`haproxy -c` on the same build) and returns its hash;
 * 3. re-hash: no byte may have changed since validation;
 * 4. swap `current` atomically, then `reload` on the master CLI under the shared reload lock; an
 *    unanswered request is confirmed from the serving worker's content version or sent again;
 * 5. Any failed or unconfirmed reload restores `current` and leaves a durable retry marker.
 */
export async function installEdgeL4Generation(input: {
  root: string;
  generation: EdgeL4Generation;
  validatorSocket: string;
  master?: HaproxyMaster;
  validate?: typeof validateGeneration;
  /** Reload even when `current` already points at this generation. */
  force?: boolean;
}): Promise<InstallResult> {
  const { root, generation } = input;
  const previous = await currentGeneration(root);
  await writeGeneration(root, generation);
  const verdict = await (input.validate ?? validateGeneration)(input.validatorSocket, generation.id);
  if (!verdict.ok || verdict.hash !== generation.id) {
    // Never leave a refused candidate where a later restart could pick it up by mistake.
    if (generation.id !== previous)
      await rm(join(root, "generations", generation.id), { recursive: true, force: true });
    throw new InvalidGenerationError(
      generation.id,
      verdict.diagnostics ?? "validator refused the generation",
    );
  }
  const rehash = await hashGenerationDir(join(root, "generations", generation.id));
  if (rehash !== generation.id) throw new Error(`generation ${generation.id} changed after validation`);
  const pending = await lstat(join(root, "reload-pending")).catch(() => null);
  if (previous === generation.id && !input.force && !pending) {
    return { generation: generation.id, previous, changed: false, reloaded: false, pruned: [] };
  }
  if (input.master) await writeFile(join(root, "reload-pending"), generation.id, { mode: FILE_MODE });
  await pointCurrent(root, generation.id);
  if (!input.master) {
    return { generation: generation.id, previous, changed: true, reloaded: false, pruned: [] };
  }
  let reload: ReloadOutcome;
  try {
    // The version stamped into the generation lets an unanswered reload be confirmed from the
    // worker that serves (unmarked hand-written generations fall back to worker turnover alone).
    reload = await input.master.reload({ expect: edgeL4ConfigVersion(generation.files["haproxy.cfg"]) });
    if (!reload.success)
      throw new Error(`HAProxy reload failed (old workers keep serving): ${reload.log.slice(-1_000)}`);
  } catch (error) {
    // A timeout is ambiguous: keep both generations and force the next apply to reload, even
    // after a process restart or a same-generation forced reload. Never treat the link as proof.
    if (previous) await pointCurrent(root, previous);
    else await rm(join(root, "current"), { force: true });
    throw error;
  }
  await rm(join(root, "reload-pending"), { force: true });
  // Keep every generation while a previous worker is still draining; prune once it has left.
  const workers = await input.master.workers().catch(() => null);
  const pruned =
    workers && workers.length <= 1
      ? await pruneGenerations(root, [generation.id, ...(previous ? [previous] : [])])
      : [];
  return {
    generation: generation.id,
    previous,
    changed: true,
    reloaded: true,
    reloadLog: reload.log,
    reloadConfirmedBy: reload.confirmedBy,
    reloadAttempts: reload.attempts,
    pruned,
  };
}

/** Admin-socket `show stat` (the current worker only), for status and tests. */
export async function adminShowStat(socket: string, cli: HaproxyCli = haproxyCli) {
  return parseShowStat(await cli(socket, "show stat"));
}
