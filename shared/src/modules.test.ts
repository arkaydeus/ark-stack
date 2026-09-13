import { describe, expect, test } from "bun:test";

import { legoArgs, renewalDue } from "./acme.ts";
import { backupCommand, nextBackupStatus } from "./backup-plan.ts";
import { buildMailDocuments, mailReadiness } from "./mail-state.ts";
import { buildProvisionPlan, publicPoolerAdmission } from "./provision-sql.ts";
import { mayAutoUpdate, rollbackSafe } from "./update-policy.ts";

describe("database provisioning SQL", () => {
  test("creates isolated roles and revokes PUBLIC", () => {
    const plan = buildProvisionPlan({
      name: "orders",
      passwords: { owner: "o", migration: "m", runtime: "r", readonly: "ro" },
      withPgvector: true,
      withTestDatabase: true,
    });
    expect(plan.database).toBe("orders");
    expect(plan.testDatabase).toBe("orders_test");
    expect(plan.statements.join("\n")).toContain("REVOKE ALL ON DATABASE");
    expect(plan.extensionStatements[0]).toContain("vector");
    expect(
      publicPoolerAdmission({ database: "orders", runtimeRole: "orders_runtime", exposure: "public" })
        .allowed,
    ).toBe(true);
    expect(
      publicPoolerAdmission({ database: "orders", runtimeRole: "orders_owner", exposure: "public" }).allowed,
    ).toBe(false);
  });
});

describe("mail readiness", () => {
  test("inbound can be ready while SES outbound stays paused", () => {
    const status = mailReadiness({
      domainVerified: true,
      mailboxProvisioned: true,
      listenerReady: true,
      certificateReady: true,
      sesProduction: false,
      relayCredential: false,
    });
    expect(status.inbound).toBe("ready");
    expect(status.outbound).toBe("paused");
    expect(status.independent).toBe(true);
    const docs = buildMailDocuments({
      version: 1,
      domains: [],
      mailboxes: [{ address: "a@example.com", displayName: "A", quotaGb: 1, lifecycle: "purged" }],
      aliases: [],
      outbound: { provider: "ses", paused: true },
    });
    expect(docs["mailboxes.yaml"].mailboxes).toHaveLength(0);
  });
});

describe("backups and updates", () => {
  test("keeps upload, integrity, and restore as separate statuses", () => {
    expect(nextBackupStatus("queued", "upload")).toBe("uploaded");
    expect(nextBackupStatus("uploaded", "integrity")).toBe("integrity_ok");
    expect(nextBackupStatus("integrity_ok", "restore")).toBe("restore_verified");
    expect(() => nextBackupStatus("uploaded", "restore")).toThrow(/separate/);
    expect(backupCommand("app-postgres", "app").argv[0]).toBe("pgbackrest");
  });

  test("blocks automatic rollback of stateful components", () => {
    expect(rollbackSafe("postgres")).toBe(false);
    expect(rollbackSafe("nginx")).toBe(true);
    expect(
      mayAutoUpdate({
        updatePolicy: "auto_stateless",
        image:
          "docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      }),
    ).toBe(true);
    expect(
      legoArgs({ email: "a@b.c", hostname: "db.example.com", webroot: "/w", path: "/p", staging: true }),
    ).toContain("run");
    expect(renewalDue(new Date(Date.now() + 5 * 24 * 60 * 60 * 1000))).toBe(true);
  });
});
