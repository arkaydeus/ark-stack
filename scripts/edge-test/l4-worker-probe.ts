// Test-only: the domain worker's edge-l4 side for `mise run test:edge` (FD-25). Bundled with Bun.build
// and run in the pinned Bun image as the worker's uid 1000 with `--group-add 4400`, every capability
// dropped, no-new-privileges, a read-only root and no Docker socket, with the production mounts: the
// configuration volume read-write, the validator socket directory and the HAProxy socket directory.
// Every command prints one JSON line.
//
//   apply '<EdgeL4Input JSON>' [force]   writeEdgeL4 as edge.l4_apply runs it (validate, swap, reload)
//   invalid                              an invalid candidate through the same installer
//   broken-reload                        a broken file reaching HAProxy (bypassing the validator)
//   reload | proc | stat | servers | sessions | sessions-raw | sockets
//   withdraw '<allowed identity keys JSON>'
//   stop                                 the adapter's stop fallback
import { lstat, stat, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  adminShowStat,
  currentGeneration,
  generationId,
  HaproxyMaster,
  HaproxyWithdrawalAdapter,
  installEdgeL4Generation,
  InvalidGenerationError,
  pointCurrent,
  writeGeneration,
} from "@ark-stack/shared";

import { writeEdgeL4 } from "../../server/src/modules/edge-l4.ts";

const root = process.env.ARK_EDGE_L4_DIR ?? "/usr/local/etc/haproxy";
const masterSocket = process.env.ARK_HAPROXY_MASTER_SOCKET ?? "/var/run/haproxy/master.sock";
const adminSocket = process.env.ARK_HAPROXY_ADMIN_SOCKET ?? "/var/run/haproxy/admin.sock";
const validatorSocket =
  process.env.ARK_HAPROXY_VALIDATOR_SOCKET ?? "/var/run/haproxy-validator/validate.sock";
const master = new HaproxyMaster(masterSocket);
const [command = "", argument = "", flag = ""] = process.argv.slice(2);

async function masterReloads() {
  const text = await master.command("show proc");
  const line = text.split("\n").find((item) => /\bmaster\b/.test(item)) ?? "";
  return {
    reloads: Number(/master\s+(\d+)/.exec(line)?.[1] ?? -1),
    failed: Number(/failed: (\d+)/.exec(line)?.[1] ?? -1),
  };
}

function brokenGeneration(marker: string) {
  const config = `global\n    this-is-not-a-directive ${marker}\n`;
  const files = { "haproxy.cfg": config, "haproxy.closed.cfg": config, "manifest.json": "{}\n" };
  return {
    id: generationId(files),
    files,
    manifest: { version: 2 as const, httpHostnames: [], sniPorts: [], routes: [] },
  };
}

async function describe(path: string) {
  const info = await lstat(path).catch(() => null);
  if (!info) return null;
  return { mode: (info.mode & 0o7777).toString(8), uid: info.uid, gid: info.gid, socket: info.isSocket() };
}

async function run(): Promise<unknown> {
  switch (command) {
    case "apply": {
      const result = await writeEdgeL4(JSON.parse(argument), { ...process.env, NODE_ENV: "production" });
      if (flag === "force" && result.applied && !result.reloaded)
        return { ...result, forced: await master.reload() };
      return result;
    }
    case "invalid": {
      const before = { current: await currentGeneration(root), ...(await masterReloads()) };
      const candidate = brokenGeneration(String(Date.now()));
      let refused = false;
      let diagnostics = "";
      try {
        await installEdgeL4Generation({ root, generation: candidate, validatorSocket, master });
      } catch (error) {
        refused = error instanceof InvalidGenerationError;
        diagnostics = (error as Error).message;
      }
      const after = { current: await currentGeneration(root), ...(await masterReloads()) };
      const kept = await stat(join(root, "generations", candidate.id)).then(
        () => true,
        () => false,
      );
      return { refused, diagnostics, before, after, candidate: candidate.id, candidateKept: kept };
    }
    case "broken-reload": {
      const previous = await currentGeneration(root);
      const broken = brokenGeneration(`reload-${Date.now()}`);
      await writeGeneration(root, broken);
      await pointCurrent(root, broken.id);
      const reload = await master.reload();
      if (previous) await pointCurrent(root, previous);
      return {
        reload,
        restored: (await currentGeneration(root)) === previous,
        workers: await master.workers(),
        ...(await masterReloads()),
      };
    }
    case "guard-reload-fault": {
      const path = join(root, "current", "haproxy.cfg");
      const backup = join(root, "guard-fault-backup");
      if (argument === "restore") await writeFile(path, await readFile(backup));
      else {
        const text = await readFile(path, "utf8");
        await writeFile(backup, text);
        await writeFile(path, text + "\ninvalid-guard-reload-fault\n");
      }
      return { injected: argument !== "restore" };
    }
    case "reload":
      return { reload: await master.reload(), workers: await master.workers() };
    case "proc":
      return { workers: await master.workers(), ...(await masterReloads()) };
    case "stat":
      return (await adminShowStat(adminSocket)).map((row) => ({
        pxname: row.pxname,
        svname: row.svname,
        scur: row.scur,
        status: row.status,
      }));
    case "servers": {
      const out: Record<string, unknown> = {};
      for (const worker of await master.workers())
        out[worker.pid] = { section: worker.section, servers: await master.servers(worker.pid) };
      return out;
    }
    case "sessions": {
      const out: Record<string, unknown> = {};
      for (const worker of await master.workers())
        out[worker.pid] = (await master.sessions(worker.pid)).filter((s) => s.frontend !== "GLOBAL");
      return out;
    }
    case "sessions-raw": {
      // Raw `show sess` lines (with src=) per worker, for FD-14's PROXY-loop source check.
      const out: Record<string, string[]> = {};
      for (const worker of await master.workers())
        out[worker.pid] = (await master.worker(worker.pid, "show sess")).split("\n").filter(Boolean);
      return out;
    }
    case "sockets":
      return {
        uid: process.getuid?.(),
        gid: process.getgid?.(),
        groups: process.getgroups?.(),
        haproxyRun: await describe("/var/run/haproxy"),
        master: await describe(masterSocket),
        admin: await describe(adminSocket),
        validatorRun: await describe("/var/run/haproxy-validator"),
        validator: await describe(validatorSocket),
        root: await describe(root),
        generations: await describe(join(root, "generations")),
        currentConfig: await describe(join(root, "current", "haproxy.cfg")),
      };
    case "withdraw":
      return new HaproxyWithdrawalAdapter(masterSocket).enforce(new Set(JSON.parse(argument) as string[]));
    case "stop":
      await new HaproxyWithdrawalAdapter(masterSocket).stop();
      return { stopped: true };
    default:
      throw new Error(`unknown command ${command}`);
  }
}

try {
  console.log(JSON.stringify(await run()));
} catch (error) {
  console.log(
    JSON.stringify({ error: (error as Error).message, code: (error as NodeJS.ErrnoException).code ?? null }),
  );
}
