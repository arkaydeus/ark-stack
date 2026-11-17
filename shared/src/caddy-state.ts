// Durable coordination for Caddy adapters in the API, drain operations and edge watchdog.
import { mkdir, readdir, readFile, writeFile, rename, rm } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

import { CADDY_STOP_MARKER } from "./edge-withdrawal.ts";

export const CADDY_PENDING_STOP_DIR = "caddy-pending-stops";

export function caddyState(dir: string) {
  // One immutable record per intent: finishing a stop cannot erase an intent published after it.
  const observed = new Set<string>();
  const pendingDir = join(dir, CADDY_PENDING_STOP_DIR);
  const read = async (name: string) =>
    readFile(join(dir, name), "utf8").catch((error) => {
      if (error.code === "ENOENT") return "";
      throw error;
    });
  const write = async (name: string, text: string) => {
    const path = join(dir, name);
    const temporary = `${path}.${randomUUID()}.next`;
    await writeFile(temporary, text, { mode: 0o640 });
    await rename(temporary, path);
  };
  return {
    appliedStopAt: async () => {
      const at = Number(await read(CADDY_STOP_MARKER));
      return Number.isFinite(at) && at > 0 ? at : null;
    },
    recordStop: () => write(CADDY_STOP_MARKER, String(Date.now())),
    pendingStreams: async (): Promise<string[]> => {
      const names = await readdir(pendingDir).catch((error) => {
        if (error.code === "ENOENT") return [];
        throw error;
      });
      const keys = new Set<string>();
      for (const name of names.filter((entry) => entry.endsWith(".json"))) {
        const text = await readFile(join(pendingDir, name), "utf8").catch((error) => {
          if (error.code === "ENOENT") return "[]"; // Another adapter completed this intent.
          throw error;
        });
        observed.add(name);
        for (const key of JSON.parse(text) as string[]) keys.add(key);
      }
      return [...keys];
    },
    markPendingStreams: async (keys: string[]) => {
      await mkdir(pendingDir, { recursive: true, mode: 0o750 });
      const name = `${randomUUID()}.json`;
      await write(join(CADDY_PENDING_STOP_DIR, name), JSON.stringify(keys));
      observed.add(name);
    },
    clearPendingStreams: async () => {
      for (const name of observed) {
        await rm(join(pendingDir, name), { force: true });
        observed.delete(name);
      }
    },
    configFiles: async () => ({ full: await read("Caddyfile"), closed: await read("Caddyfile.closed") }),
  };
}
