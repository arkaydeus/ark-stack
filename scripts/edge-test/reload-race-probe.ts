// Test-only: the domain worker's reload side for `scripts/test-edge-reload-race.ts` (FD-25 reload
// safety). Bundled with Bun.build and run in the pinned Bun image as uid 1000 with `--group-add 4400`,
// a read-only root, no capabilities and no network, with the production mounts: the configuration
// root read-write and the HAProxy socket directory (which holds the shared reload lock). Every command
// prints one JSON line.
//
//   seed                       install generation A without a reload (edge-l4 starts from it)
//   publish <rounds>           rounds x installEdgeL4Generation (force), alternating A and B, each
//                              checked against the version the current worker serves
//   reload <rounds>            rounds x HaproxyMaster.reload() (a second reloader that changes nothing)
//   invalid                    an invalid configuration through the same installer
//   proc                       master reload counters and the serving workers' versions
import {
  currentGeneration,
  edgeL4ConfigVersion,
  generationId,
  HaproxyMaster,
  installEdgeL4Generation,
  renderEdgeL4Generation,
} from "@ark-stack/shared";

const root = process.env.ARK_EDGE_L4_DIR ?? "/usr/local/etc/haproxy";
const masterSocket = process.env.ARK_HAPROXY_MASTER_SOCKET ?? "/var/run/haproxy/master.sock";
const master = new HaproxyMaster(masterSocket);
const [command = "", argument = ""] = process.argv.slice(2);

// The restricted validator is exercised by scripts/test-edge-l4.ts; here only the reload path is
// under test, so candidates are accepted as validated.
const trusted = async (_socket: string, generation: string) => ({
  ok: true,
  generation,
  hash: generation,
  diagnostics: "",
});

const generations = {
  a: renderEdgeL4Generation({ httpHostnames: ["a.reload-race.example.com"] }),
  b: renderEdgeL4Generation({ httpHostnames: ["b.reload-race.example.com"] }),
};

/** Master counters and workers, once the master answers (a racing reload may be re-executing it). */
async function proc() {
  const deadline = Date.now() + 5_000;
  for (;;) {
    try {
      return await procOnce();
    } catch (error) {
      if (Date.now() >= deadline) throw error;
      await Bun.sleep(50);
    }
  }
}

async function procOnce() {
  const text = await master.command("show proc");
  const line = text.split("\n").find((item) => /\bmaster\b/.test(item));
  if (!line) throw new Error(`incomplete show proc answer (${text.length} bytes)`);
  const workers = await master.workers();
  const current = workers.filter((worker) => worker.section === "current");
  return {
    reloads: Number(/master\s+(\d+)/.exec(line)?.[1] ?? -1),
    failed: Number(/failed: (\d+)/.exec(line)?.[1] ?? -1),
    workers: await Promise.all(
      workers.map(async (worker) => ({
        pid: worker.pid,
        section: worker.section,
        version: await master.loadedVersion(worker.pid).catch(() => null),
      })),
    ),
    serving: await Promise.all(current.map((worker) => master.loadedVersion(worker.pid))),
  };
}

/** The versions current workers serve. */
async function servingVersions() {
  return (await proc()).serving;
}

async function publish(rounds: number) {
  const results: Array<{
    round: number;
    ms: number;
    confirmedBy?: string;
    attempts?: number;
    error?: string;
    serving?: string;
  }> = [];
  for (let round = 0; round < rounds; round++) {
    const generation = round % 2 ? generations.b : generations.a;
    const started = Date.now();
    try {
      const result = await installEdgeL4Generation({
        root,
        generation,
        validatorSocket: "/unused",
        validate: trusted,
        master,
        force: true,
      });
      const ms = Date.now() - started;
      // The end state, independently of how the reload was confirmed: every current worker serves
      // this generation's version (other reloaders reload the same `current`, so it cannot change).
      const serving = await servingVersions();
      const ok =
        result.reloaded && serving.length > 0 && serving.every((item) => item === generation.version);
      results.push({
        round,
        ms,
        confirmedBy: result.reloadConfirmedBy,
        attempts: result.reloadAttempts,
        ...(ok ? {} : { error: `serving ${JSON.stringify(serving)}, expected ${generation.version}` }),
        serving: serving[0]?.slice(0, 12),
      });
    } catch (error) {
      results.push({ round, ms: Date.now() - started, error: (error as Error).message });
    }
  }
  return {
    rounds,
    succeeded: results.filter((item) => !item.error).length,
    failures: results.filter((item) => item.error),
    confirmedByWorkers: results.filter((item) => item.confirmedBy === "workers").length,
    retried: results.filter((item) => (item.attempts ?? 1) > 1).length,
    requests: results.reduce((total, item) => total + (item.attempts ?? 0), 0),
    maxMs: Math.max(...results.map((item) => item.ms)),
  };
}

async function reload(rounds: number) {
  const outcomes: Array<{ success: boolean; confirmedBy?: string; attempts?: number; error?: string }> = [];
  for (let round = 0; round < rounds; round++) {
    try {
      outcomes.push(await master.reload());
    } catch (error) {
      outcomes.push({ success: false, error: (error as Error).message });
    }
  }
  return {
    rounds,
    succeeded: outcomes.filter((item) => item.success).length,
    answered: outcomes.filter((item) => item.confirmedBy === "answer").length,
    failures: outcomes.filter((item) => !item.success),
    requests: outcomes.reduce((total, item) => total + (item.attempts ?? 0), 0),
  };
}

/** HAProxy refuses this at reload, as it would any configuration the validator could not catch. */
function brokenGeneration() {
  const config = `global\n    this-is-not-a-directive ${Date.now()}\n`;
  const files = { "haproxy.cfg": config, "haproxy.closed.cfg": config, "manifest.json": "{}\n" };
  return {
    id: generationId(files),
    files,
    manifest: { version: 2 as const, httpHostnames: [], sniPorts: [], routes: [] },
  };
}

async function invalid() {
  const previous = await currentGeneration(root);
  const before = await proc();
  let error = "";
  let installed = false;
  try {
    await installEdgeL4Generation({
      root,
      generation: brokenGeneration(),
      validatorSocket: "/unused",
      validate: trusted,
      master,
    });
    installed = true;
  } catch (cause) {
    error = (cause as Error).message;
  }
  return {
    installed,
    error,
    restored: (await currentGeneration(root)) === previous,
    previousVersion: previous === generations.a.id ? generations.a.version : generations.b.version,
    before,
    after: await proc(),
  };
}

async function run(): Promise<unknown> {
  switch (command) {
    case "seed": {
      const result = await installEdgeL4Generation({
        root,
        generation: generations.a,
        validatorSocket: "/unused",
        validate: trusted,
      });
      return {
        ...result,
        versions: { a: generations.a.version, b: generations.b.version },
        marked: edgeL4ConfigVersion(generations.a.files["haproxy.cfg"]) === generations.a.version,
      };
    }
    case "publish":
      return publish(Number(argument));
    case "reload":
      return reload(Number(argument));
    case "invalid":
      return invalid();
    case "proc":
      return proc();
    default:
      throw new Error(`unknown command ${command}`);
  }
}

try {
  console.log(JSON.stringify(await run()));
} catch (error) {
  console.log(JSON.stringify({ error: (error as Error).message }));
}
