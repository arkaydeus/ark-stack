import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: "list",
  use: {
    baseURL: process.env.ARK_E2E_BASE_URL ?? "http://127.0.0.1:3199",
    trace: "retain-on-failure",
  },
});
