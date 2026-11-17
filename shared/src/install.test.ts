import { describe, expect, test } from "bun:test";
import { join } from "node:path";

import {
  applyEdgeAuthKey,
  assertNoPlaceholderSecrets,
  generateInstallSecrets,
  installEnvKeys,
  isPlaceholderValue,
  mergeInstallEnv,
  parseEnvFile,
} from "./install.ts";

describe("install secret merge", () => {
  test("fresh merge against .env.example replaces every published secret", async () => {
    const example = await Bun.file(join(import.meta.dir, "../../.env.example")).text();
    const generated = generateInstallSecrets();
    const merged = parseEnvFile(mergeInstallEnv(example, generated, { template: true }));
    for (const key of installEnvKeys) {
      expect(merged[key]).toBeDefined();
      expect(merged[key]).not.toBe(parseEnvFile(example)[key]);
      expect(isPlaceholderValue(key, merged[key] ?? "")).toBe(false);
      expect((merged[key] ?? "").length).toBeGreaterThan(16);
    }
    expect(merged.ARK_PGBOUNCER_DIR).not.toBe("./infra/database");
  });

  test("preserves genuinely customized existing secrets", () => {
    const generated = generateInstallSecrets();
    const merged = parseEnvFile(mergeInstallEnv("ARK_SETUP_TOKEN=keep-this-custom-token\n", generated));
    expect(merged.ARK_SETUP_TOKEN).toBe("keep-this-custom-token");
    expect(merged.ARK_INTERNAL_TOKEN).toBe(generated.ARK_INTERNAL_TOKEN);
  });

  test("generates ARK_EDGE_GATE_TOKEN over the published placeholder and keeps an existing one", async () => {
    const example = await Bun.file(join(import.meta.dir, "../../.env.example")).text();
    expect(parseEnvFile(example).ARK_EDGE_GATE_TOKEN).toBeDefined();
    const fresh = parseEnvFile(mergeInstallEnv(example, generateInstallSecrets(), { template: true }));
    expect(isPlaceholderValue("ARK_EDGE_GATE_TOKEN", fresh.ARK_EDGE_GATE_TOKEN ?? "")).toBe(false);
    expect((fresh.ARK_EDGE_GATE_TOKEN ?? "").length).toBeGreaterThanOrEqual(43);

    // An install from before FD-05 has no token yet: it is added.
    const upgraded = parseEnvFile(
      mergeInstallEnv("ARK_SETUP_TOKEN=keep-this-custom-token\n", generateInstallSecrets()),
    );
    expect(isPlaceholderValue("ARK_EDGE_GATE_TOKEN", upgraded.ARK_EDGE_GATE_TOKEN ?? "")).toBe(false);

    // A re-run never rotates it.
    const rerun = parseEnvFile(
      mergeInstallEnv("ARK_EDGE_GATE_TOKEN=existing-gate-token-value\n", generateInstallSecrets()),
    );
    expect(rerun.ARK_EDGE_GATE_TOKEN).toBe("existing-gate-token-value");

    // The published development placeholder is replaced, like every other secret.
    const placeholder = parseEnvFile(
      mergeInstallEnv("ARK_EDGE_GATE_TOKEN=dev-edge-gate-token\n", generateInstallSecrets()),
    );
    expect(placeholder.ARK_EDGE_GATE_TOKEN).not.toBe("dev-edge-gate-token");
  });

  test("documents TS_EDGE_AUTHKEY empty in .env.example and keeps it through the merge", async () => {
    const example = await Bun.file(join(import.meta.dir, "../../.env.example")).text();
    expect(parseEnvFile(example).TS_EDGE_AUTHKEY).toBe("");
    const merged = mergeInstallEnv(example, generateInstallSecrets(), { template: true });
    expect(parseEnvFile(merged).TS_EDGE_AUTHKEY).toBe("");
    const existing = mergeInstallEnv("TS_EDGE_AUTHKEY=tskey-auth-kept-secret\n", generateInstallSecrets());
    expect(parseEnvFile(existing).TS_EDGE_AUTHKEY).toBe("tskey-auth-kept-secret");
  });
});

describe("edge node auth key", () => {
  const key = "tskey-auth-kAbCdEf1CNTRL-0123456789abcdef";

  test("never overwrites an existing key", () => {
    const env = "ARK_SETUP_TOKEN=x\nTS_EDGE_AUTHKEY=tskey-auth-existing-1\n";
    expect(applyEdgeAuthKey(env, key)).toEqual({ env, status: "kept" });
    expect(applyEdgeAuthKey(env)).toEqual({ env, status: "kept" });
  });

  test("fills an empty entry in place", () => {
    const result = applyEdgeAuthKey("A=1\nTS_EDGE_AUTHKEY=\nB=2\n", ` ${key} `);
    expect(result.status).toBe("set");
    expect(result.env).toBe(`A=1\nTS_EDGE_AUTHKEY=${key}\nB=2\n`);
  });

  test("appends a missing entry", () => {
    expect(applyEdgeAuthKey("A=1", key)).toEqual({ env: `A=1\nTS_EDGE_AUTHKEY=${key}\n`, status: "set" });
    expect(applyEdgeAuthKey("", key)).toEqual({ env: `TS_EDGE_AUTHKEY=${key}\n`, status: "set" });
  });

  test("reports a missing key without changing the file", () => {
    expect(applyEdgeAuthKey("A=1\nTS_EDGE_AUTHKEY=\n")).toEqual({
      env: "A=1\nTS_EDGE_AUTHKEY=\n",
      status: "missing",
    });
    expect(applyEdgeAuthKey("A=1\n", "  ")).toEqual({ env: "A=1\n", status: "missing" });
  });

  test("refuses values that are not Tailscale auth keys or could inject .env lines", () => {
    for (const bad of [
      "not-a-key",
      "tskey-auth-abc\nARK_ROOT_KEY=evil",
      "tskey-auth abc",
      "tskey-auth-$(id)",
    ]) {
      expect(() => applyEdgeAuthKey("TS_EDGE_AUTHKEY=\n", bad)).toThrow(/Tailscale auth key/);
    }
  });
});

describe("startup gate token guard", () => {
  test("rejects a supplied public gate token and accepts the generated token", () => {
    const env = generateInstallSecrets();
    expect(() => assertNoPlaceholderSecrets(env)).not.toThrow();
    for (const value of ["dev-edge-gate-token", "change-me-now"]) {
      expect(() => assertNoPlaceholderSecrets({ ...env, ARK_EDGE_GATE_TOKEN: value })).toThrow(
        /ARK_EDGE_GATE_TOKEN/,
      );
    }
  });

  test("allows older API deployments that do not consume the gate token yet", () => {
    const env: Record<string, string> = generateInstallSecrets();
    delete env.ARK_EDGE_GATE_TOKEN;
    expect(() => assertNoPlaceholderSecrets(env)).not.toThrow();
    expect(() => assertNoPlaceholderSecrets({ ...env, ARK_EDGE_GATE_TOKEN: "" })).not.toThrow();
  });
});
