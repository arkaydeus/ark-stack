// Durable coordination for Caddy adapters in the API, drain operations and edge watchdog.
import { readFile, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

import { CADDY_STOP_MARKER } from "./edge-withdrawal.ts";

export function caddyState(dir: string) {
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
    configFiles: async () => ({ full: await read("Caddyfile"), closed: await read("Caddyfile.closed") }),
  };
}
