import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { routeIdentityKey } from "@ark-stack/shared";

import { writeEdge } from "./providers.ts";

const originalFetch = globalThis.fetch;
const saved = {
  ARK_EDGE_DIR: process.env.ARK_EDGE_DIR,
  ARK_EDGE_RELOAD_URL: process.env.ARK_EDGE_RELOAD_URL,
  ARK_ACME_WEBROOT: process.env.ARK_ACME_WEBROOT,
};
const temporaryDirectories: string[] = [];

afterEach(async () => {
  globalThis.fetch = originalFetch;
  for (const [key, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  for (const directory of temporaryDirectories.splice(0)) await rm(directory, { recursive: true });
});

type Captured = { url: string; headers: Headers; body: string };

async function prepare(
  adaptStatus = 200,
  loadStatus = 200,
  running: { config?: unknown; upstreams?: unknown } = {},
) {
  const directory = await mkdtemp(join(tmpdir(), "ark-edge-write-"));
  temporaryDirectories.push(directory);
  process.env.ARK_EDGE_DIR = directory;
  process.env.ARK_EDGE_RELOAD_URL = "http://edge-admin:2019/";
  process.env.ARK_ACME_WEBROOT = "/var/lib/ark/acme";
  const requests: Captured[] = [];
  const adapted = { apps: { http: { servers: {} } } };
  globalThis.fetch = (async (input, init) => {
    const url = String(input);
    requests.push({ url, headers: new Headers(init?.headers), body: String(init?.body) });
    if (url.endsWith("/adapt")) {
      return Response.json({ result: adapted, warnings: [] }, { status: adaptStatus });
    }
    if (url.endsWith("/config/")) {
      return Response.json(running.config ?? { apps: {} });
    }
    if (url.endsWith("/reverse_proxy/upstreams")) return Response.json(running.upstreams ?? []);
    return new Response(null, { status: loadStatus });
  }) as typeof fetch;
  return { directory, requests, adapted };
}

describe("writeEdge", () => {
  test("adapts, then loads the adapted config with Cache-Control: must-revalidate", async () => {
    const { directory, requests, adapted } = await prepare();
    const result = await writeEdge({
      adminMode: "public",
      adminHostname: "admin.example.com",
      certificates: [
        { hostname: "admin.example.com", status: "issued" },
        { hostname: "app.example.com", status: "pending" },
      ],
      appRoutes: [{ hostname: "app.example.com" }],
    });
    expect(result.applied).toBe(true);
    // The running config is read first: removed routes may hold WebSockets (FD-09).
    expect(requests.map((request) => request.url)).toEqual([
      "http://edge-admin:2019/config/",
      "http://edge-admin:2019/adapt",
      "http://edge-admin:2019/load",
    ]);
    const [, adapt, load] = requests;
    expect(adapt?.headers.get("content-type")).toBe("text/caddyfile");
    expect(adapt?.headers.get("cache-control")).toBeNull();
    expect(load?.headers.get("cache-control")).toBe("must-revalidate");
    expect(load?.headers.get("content-type")).toBe("application/json");
    // /adapt wraps the config as `{ result, warnings }`; /load must receive only the config.
    expect(JSON.parse(load?.body ?? "")).toEqual(adapted);

    const caddyfile = await readFile(join(directory, "Caddyfile"), "utf8");
    expect(caddyfile).toBe(adapt?.body);
    expect(caddyfile).toContain(
      "tls /var/lib/ark/certs/admin.example.com/fullchain.pem /var/lib/ark/certs/admin.example.com/privkey.pem",
    );
    expect(caddyfile).not.toContain("app.example.com");
  });

  test("a rejected /load fails the apply and keeps the previous Caddyfile", async () => {
    const { directory, requests } = await prepare(200, 400);
    await expect(writeEdge({ adminMode: "tailnet" })).rejects.toThrow("Caddy reload failed: 400");
    expect(requests.at(-1)?.headers.get("cache-control")).toBe("must-revalidate");
    expect(await Bun.file(join(directory, "Caddyfile")).exists()).toBe(false);
  });

  test("a rejected /adapt never reaches /load", async () => {
    const { requests } = await prepare(400);
    await expect(writeEdge({ adminMode: "tailnet" })).rejects.toThrow(
      "Caddy rejected candidate configuration: 400",
    );
    expect(requests.map((request) => request.url)).toEqual([
      "http://edge-admin:2019/config/",
      "http://edge-admin:2019/adapt",
    ]);
  });

  // A running route the new render drops, with stream_close_delay (as FD-09 renders it).
  const removed = {
    id: "rt_gone",
    hostname: "gone.example.com",
    stableId: "nGONE",
    ip: "100.101.102.103",
    port: 3000,
  };
  const runningConfig = {
    apps: {
      http: {
        servers: {
          srv0: {
            routes: [
              {
                match: [{ host: [removed.hostname] }],
                handle: [
                  { handler: "vars", ark_tailnet_route: routeIdentityKey(removed) },
                  {
                    handler: "reverse_proxy",
                    stream_close_delay: 300_000_000_000,
                    upstreams: [{ dial: "100.101.102.103:3000" }],
                  },
                ],
              },
            ],
          },
        },
      },
    },
  };

  test("loads a removal without issuing a stop to Caddy", async () => {
    const { directory, requests } = await prepare(200, 200, { config: runningConfig });
    const result = await writeEdge({ adminMode: "tailnet" });
    expect(result.applied).toBe(true);
    expect(requests.map((request) => new URL(request.url).pathname)).toEqual(["/config/", "/adapt", "/load"]);
    expect(await Bun.file(join(directory, "Caddyfile")).text()).not.toContain(removed.hostname);
  });

  test("failed active-config inspection aborts before adapt/load and preserves the current files", async () => {
    const { directory, requests } = await prepare();
    await Bun.write(join(directory, "Caddyfile"), "old configuration");
    const fetcher = globalThis.fetch;
    globalThis.fetch = (async (url, init) =>
      String(url).endsWith("/config/")
        ? new Response(null, { status: 502 })
        : fetcher(url, init)) as typeof fetch;
    await expect(writeEdge({ adminMode: "tailnet" })).rejects.toThrow("GET /config/ returned 502");
    expect(requests).toEqual([]);
    expect(await Bun.file(join(directory, "Caddyfile")).text()).toBe("old configuration");
  });

  test("apply during an expected restart aborts safely before changing active config", async () => {
    await prepare();
    globalThis.fetch = Object.assign(
      async (): Promise<Response> => {
        throw new Error("ECONNREFUSED");
      },
      { preconnect: originalFetch.preconnect },
    );
    await expect(writeEdge({ adminMode: "tailnet" })).rejects.toThrow("ECONNREFUSED");
  });
});
