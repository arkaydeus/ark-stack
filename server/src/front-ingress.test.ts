import { expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DB_INGRESS_LIMIT_DEFAULTS, sha256Hex } from "@ark-stack/shared";
import { applyFrontIngress, frontIngressRules } from "./modules/front-ingress.ts";

test("host publication waits for exact successful acknowledgement; stale and failed replies cannot open listeners", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ark-front-ingress-"));
  const env = { ARK_FRONT_INGRESS_DIR: dir, ARK_FRONT_INGRESS_TIMEOUT_MS: "300" };
  try {
    await writeFile(join(dir, "policy.status"), "applied=true\npolicy_hash=stale\nerror=\n");
    await expect(applyFrontIngress({ httpHostnames: [] }, DB_INGRESS_LIMIT_DEFAULTS, env)).rejects.toThrow(
      "not acknowledged",
    );
    const rules = await readFile(join(dir, "policy.nft"), "utf8");
    const hash = sha256Hex(rules);
    let outcome = "nft failed";
    const reply = setInterval(() => {
      void (async () => {
        const request = JSON.parse(await readFile(join(dir, "policy.request"), "utf8"));
        await writeFile(
          join(dir, "policy.status"),
          `applied=${!outcome}\npolicy_hash=${hash}\nrequest_id=${request.id}\nerror=${outcome}\n`,
        );
      })();
    }, 5);
    try {
      await expect(applyFrontIngress({ httpHostnames: [] }, DB_INGRESS_LIMIT_DEFAULTS, env)).rejects.toThrow(
        "nft failed",
      );
      outcome = "";
      expect(await applyFrontIngress({ httpHostnames: [] }, DB_INGRESS_LIMIT_DEFAULTS, env)).toMatchObject({
        applied: true,
        hash,
      });
    } finally {
      clearInterval(reply);
      await Bun.sleep(20);
    }
    // Even the same policy hash needs a fresh acknowledgement; persisted success is insufficient.
    await expect(applyFrontIngress({ httpHostnames: [] }, DB_INGRESS_LIMIT_DEFAULTS, env)).rejects.toThrow(
      "not acknowledged",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("route-only limits and compatibility policies update and close removed ports", () => {
  const route = {
    id: "rt_pg",
    hostname: "pg.example.com",
    stableId: "node",
    ip: "100.64.1.1",
    port: 5432,
    policy: "a".repeat(16),
    sourceCidrs: ["198.51.100.7/32"],
    compatPort: 20007,
  };
  const first = frontIngressRules({ httpHostnames: [], postgresRoutes: [route] }, DB_INGRESS_LIMIT_DEFAULTS);
  expect(first).toContain("ct count over 128");
  expect(first).toContain("ct count over 256");
  expect(first).toContain("limit rate over 50/second burst 100 packets");
  expect(first).toContain("ct status dnat tcp dport 5432");
  expect(first).toContain("ip saddr 198.51.100.7/32 goto port_20007_limits");
  const next = frontIngressRules({ httpHostnames: [] }, DB_INGRESS_LIMIT_DEFAULTS, first);
  expect(next).toContain("# ark-front: port=20007 policy=closed");
  expect(next).not.toContain("set conn4_20007");
});

test("the combined policy covers enabled SNI ports and keeps shared limits independent of 5432", () => {
  const rules = frontIngressRules(
    { httpHostnames: [], sniPorts: [8883, 636, 8883] },
    DB_INGRESS_LIMIT_DEFAULTS,
    "",
    { maxConnectionsPerSource: 10, newConnectionsPerSecond: 3, newConnectionBurst: 8 },
  );
  expect(rules).toContain("tcp dport { 80, 443, 636, 8883 } jump shared_limits");
  expect(rules).toContain("ct count over 128");
  expect(rules).toContain("ct count over 10");
  expect(rules).toContain("limit rate over 3/second burst 8 packets");
  expect(() => frontIngressRules({ httpHostnames: [], sniPorts: [5432] }, DB_INGRESS_LIMIT_DEFAULTS)).toThrow(
    "Shared SNI port 5432 is not supported",
  );
});
