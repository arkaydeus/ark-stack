import { describe, expect, test } from "bun:test";
import { join } from "node:path";

import {
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
});
