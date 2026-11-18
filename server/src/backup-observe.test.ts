// FD-30 against the migrated platform database (DATABASE_URL): backup-ts's own `source = 'backup'`
// observation, pinning the home target from it alone (never from the edge snapshot), identity and
// freshness checks before and during transfers, the REST subprocess's proxy scoping and the
// two-destination health. restic is a stand-in script; the runtime proof against real tailscaled,
// rest-server and restic is `mise run test:backups-tailnet`.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Socket } from "node:net";

import { TRANSFER_STOP_BOUND_MS } from "@ark-stack/shared";
import { and, eq, inArray, like } from "drizzle-orm";

import { mockStatusDocument, type MockLocalApiState } from "./mock-localapi.ts";
import { runRestCanary, type RestRequest } from "./modules/rest-canary.ts";

const { db, sql } = await import("./db.ts");
const { alerts, auditEvents, backupExports, backupTargets, secrets } = await import("./schema.ts");
const observer = await import("./modules/backup-observe.ts");
const offsite = await import("./modules/offsite-backups.ts");
const { commitTailnetGeneration, loadTailnetSnapshot } = await import("./modules/tailnet-snapshot.ts");

const suffix = Date.now().toString(36);
const tailnet = ".tail4fd30.ts.net";
const homeUrl = `http://backup-home${tailnet}:8000/ark`;
const backupSelf = {
  id: `nBACKUPTS${suffix}`,
  name: "ark-backup",
  ips: ["100.64.9.1"],
  tags: ["tag:ark-backup"],
};
const home = { id: `nHOME${suffix}`, name: "backup-home", ips: ["100.66.2.9"] };
const impostor = { id: `nIMPOSTOR${suffix}`, name: "backup-home", ips: ["100.66.2.9"] };
const edgeSelf = { id: `nEDGE${suffix}`, name: "ark-edge", ips: ["100.64.9.2"], tags: ["tag:ark-edge"] };

let work = "";
const created: string[] = [];
const ENV_KEYS = [
  "ARK_RESTIC_BIN",
  "ARK_BACKUP_SOCKS5_PROXY",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
  "no_proxy",
] as const;
const savedEnv = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));

const state = (peers: MockLocalApiState["peers"], self = backupSelf): MockLocalApiState => ({
  backendState: "Running",
  suffix: tailnet,
  self,
  peers,
  reachable: new Set(),
});
let view = state([home]);
const api = { status: async () => mockStatusDocument(view) };

async function observe(validityMs?: number) {
  return observer.observeBackupTailnet({ api, validityMs });
}

/** Commits an edge generation directly, as FD-06's edge.observe would. */
async function edgeSees(peers: MockLocalApiState["peers"]) {
  const { parseLocalApiStatus } = await import("@ark-stack/shared");
  const parsed = parseLocalApiStatus(mockStatusDocument(state(peers, edgeSelf)), {
    generation: `gen_edge_${Date.now()}`,
  });
  if (!parsed.ok) throw new Error(parsed.reason);
  const now = new Date();
  await commitTailnetGeneration("edge", {
    generation: parsed.self.generation,
    self: parsed.self,
    peers: parsed.peers,
    completedAt: now,
    validUntil: new Date(now.getTime() + 6 * 60_000),
  });
}

async function saveHome(name = `home-${suffix}`) {
  const target = await offsite.saveTailnetRestTarget({
    name,
    restUrl: homeUrl,
    recoveryWindowDays: 30,
    password: "htpasswd-secret-123",
    repositoryPassword: "repository-password-0123456789",
  });
  created.push(target.id);
  return target;
}

beforeAll(async () => {
  work = await mkdtemp(join(tmpdir(), "ark-fd30-"));
  // restic stand-in: records its proxy-relevant environment and arguments; `block` keeps a backup
  // running (writing its pid) until the file is removed or the process is killed.
  const restic = join(work, "restic");
  await writeFile(
    restic,
    `#!/bin/sh
for arg in "$@"; do last="$arg"; done
{
  printf 'ARGS=%s\\n' "$*"
  for name in HTTP_PROXY http_proxy HTTPS_PROXY https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy; do
    eval "value=\\\${$name-<unset>}"; printf '%s=%s\\n' "$name" "$value"
  done
  printf 'AWS_ACCESS_KEY_ID=%s\\nRESTIC_REST_USERNAME=%s\\nRESTIC_REST_PASSWORD_SET=%s\\nRESTIC_PASSWORD_SET=%s\\n' \\
    "\${AWS_ACCESS_KEY_ID-<unset>}" "\${RESTIC_REST_USERNAME-<unset>}" "\${RESTIC_REST_PASSWORD:+yes}" "\${RESTIC_PASSWORD:+yes}"
  echo ---
} >> "${work}/calls"
case "$*" in
  *"cat config"*) exit 0 ;;
esac
if [ -f "${work}/block" ] && [ -n "$RESTIC_REST_USERNAME" ] && echo "$*" | grep -q " backup "; then
  echo $$ > "${work}/pid"
  while [ -f "${work}/block" ]; do sleep 0.05; done
fi
echo "{\\"message_type\\":\\"summary\\",\\"snapshot_id\\":\\"snap$$\\",\\"path\\":\\"$last\\"}"
`,
  );
  await chmod(restic, 0o755);
  process.env.ARK_RESTIC_BIN = restic;
  delete process.env.ARK_BACKUP_SOCKS5_PROXY;
});

afterAll(async () => {
  if (created.length) {
    const rows = await db.select().from(backupTargets).where(inArray(backupTargets.id, created));
    await db.delete(backupExports).where(inArray(backupExports.targetId, created));
    await db.delete(backupTargets).where(inArray(backupTargets.id, created));
    const secretIds = rows.flatMap((row) => [row.credentialSecretId, row.repositorySecretId ?? ""]);
    await db.delete(secrets).where(inArray(secrets.id, secretIds));
    await db.delete(auditEvents).where(inArray(auditEvents.resourceId, created));
    for (const id of created) await db.delete(alerts).where(like(alerts.dedupKey, `%${id}%`));
  }
  await sql`DELETE FROM tailnet_nodes WHERE source IN ('backup', 'edge')`;
  await sql`DELETE FROM tailnet_snapshots WHERE source IN ('backup', 'edge')`;
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  await rm(work, { recursive: true, force: true });
});

async function waitUntil(predicate: () => boolean, timeoutMs: number) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate() && Date.now() < deadline) await Bun.sleep(5);
}

async function calls() {
  const text = await Bun.file(join(work, "calls"))
    .text()
    .catch(() => "");
  await rm(join(work, "calls"), { force: true });
  return text
    .split("---\n")
    .filter((block) => block.trim())
    .map((block) =>
      Object.fromEntries(
        block
          .trim()
          .split("\n")
          .map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]),
      ),
    );
}

describe("backup.observe: backup-ts's own generation (FD-30)", () => {
  test("commits a complete source=backup generation and never touches the edge snapshot", async () => {
    await edgeSees([]);
    view = state([home]);
    const result = await observe();
    expect(result.self.tags).toEqual(["tag:ark-backup"]);
    expect(result.peers).toBe(1);
    const nodes = await sql`SELECT source, stable_id, is_self FROM tailnet_nodes ORDER BY source, stable_id`;
    expect(
      nodes
        .filter((row) => row.source === "backup")
        .map((row) => row.stable_id)
        .toSorted(),
    ).toEqual([backupSelf.id, home.id].toSorted());
    expect(nodes.filter((row) => row.source === "edge").map((row) => row.stable_id)).toEqual([edgeSelf.id]);
  });

  test("a failed or partial read changes nothing and does not renew the lease", async () => {
    const [before] = await sql`SELECT generation, valid_until FROM tailnet_snapshots WHERE source = 'backup'`;
    view = { ...state([home]), backendState: "NeedsLogin" };
    await expect(observe()).rejects.toThrow(/backup node is not running/);
    const [after] = await sql`SELECT generation, valid_until FROM tailnet_snapshots WHERE source = 'backup'`;
    expect(after).toEqual(before!);
    view = state([home]);
  });
});

describe("pinning the home target from backup-ts's snapshot only", () => {
  test("disjoint grants: the edge sees the home machine, backup-ts does not -> rejected", async () => {
    await edgeSees([home]);
    view = state([]);
    await observe();
    await expect(saveHome(`edge-only-${suffix}`)).rejects.toThrow(/not a peer/);
  });

  test("disjoint grants: backup-ts sees it, the edge does not -> pinned from the backup generation", async () => {
    await edgeSees([]);
    view = state([home]);
    await observe();
    const target = await saveHome();
    expect(target.kind).toBe("tailnet_rest");
    expect(target.provider).toBe("rest_server");
    expect(target.targetNodeStableId).toBe(home.id);
    expect(target.targetIp).toBe("100.66.2.9");
    expect(target.prefix).toBe("ark");
    const [credential] = await db.select().from(secrets).where(eq(secrets.id, target.credentialSecretId));
    expect(credential!.ciphertext).not.toContain("htpasswd-secret-123");
    expect(JSON.stringify(offsite.publicTarget(target))).not.toContain("htpasswd-secret-123");
  });

  test("backup-ts itself and Ark-tagged nodes can never be a home target", async () => {
    view = state([
      home,
      { id: `nEDGEPEER${suffix}`, name: "edge-peer", ips: ["100.66.2.10"], tags: ["tag:ark-edge"] },
    ]);
    await observe();
    for (const restUrl of [`http://ark-backup${tailnet}:8000/ark`, `http://edge-peer${tailnet}:8000/ark`]) {
      await expect(
        offsite.saveTailnetRestTarget({
          name: `forbidden-${suffix}`,
          restUrl,
          recoveryWindowDays: 30,
          password: "htpasswd-secret-123",
          repositoryPassword: "repository-password-0123456789",
        }),
      ).rejects.toThrow(/cannot be|belong to the platform/);
    }
  });
});

describe("home target updates and coherent generations", () => {
  test("credential preservation, user changes, URL moves and re-pinning fence repository evidence", async () => {
    view = state([home]);
    await observe();
    const original = await saveHome(`updates-${suffix}`);
    const input = { id: original.id, name: original.name, restUrl: homeUrl, recoveryWindowDays: 30 };
    await expect(
      offsite.saveTailnetRestTarget({ ...input, repositoryPassword: "different-repository-password-012345" }),
    ).rejects.toThrow(/cannot change/);
    const same = await offsite.saveTailnetRestTarget(input);
    expect(same.repositoryRevision).toBe(original.repositoryRevision);
    expect(same.configRevision).not.toBe(original.configRevision);
    expect(same.credentialSecretId).toBe(original.credentialSecretId);
    expect(same.repositorySecretId).toBe(original.repositorySecretId);
    const otherUser = homeUrl.replace("/ark", "/other-user");
    await expect(offsite.saveTailnetRestTarget({ ...input, restUrl: otherUser })).rejects.toThrow(
      /user changed/,
    );
    const moved = await offsite.saveTailnetRestTarget({
      ...input,
      restUrl: otherUser,
      password: "new-htpasswd-password",
    });
    expect(moved.repositoryRevision).not.toBe(same.repositoryRevision);
    expect(moved.credentialSecretId).not.toBe(same.credentialSecretId);
    expect((await offsite.targetSecrets(moved)).username).toBe("other-user");
    const otherPath = await offsite.saveTailnetRestTarget({ ...input, restUrl: `${otherUser}/new-repo` });
    expect(otherPath.repositoryRevision).not.toBe(moved.repositoryRevision);
    view = state([impostor]);
    await observe();
    const repinned = await offsite.saveTailnetRestTarget({ ...input, restUrl: `${otherUser}/new-repo` });
    expect(repinned.targetNodeStableId).toBe(impostor.id);
    expect(repinned.repositoryRevision).not.toBe(otherPath.repositoryRevision);
    view = state([home]);
    await observe();
    await db.update(backupTargets).set({ enabled: false }).where(eq(backupTargets.id, original.id));
    // HTTPS must fail before credentials are used, including for internal callers.
    await expect(
      offsite.saveTailnetRestTarget({ ...input, restUrl: homeUrl.replace("http:", "https:") }),
    ).rejects.toThrow(/require http/);
  });

  test("legacy persisted HTTPS targets cannot start restic or send canary credentials", async () => {
    view = state([home]);
    await observe();
    const target = await saveHome(`legacy-https-${suffix}`);
    const legacy = { ...target, restUrl: homeUrl.replace("http:", "https:") };
    const keys = await offsite.targetSecrets(target);
    await calls();
    const previousDial = process.env.ARK_TEST_SOCKS5_DIAL;
    let connections = 0;
    const proxy = createServer((socket) => {
      connections++;
      socket.destroy();
    });
    await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
    process.env.ARK_TEST_SOCKS5_DIAL = `127.0.0.1:${(proxy.address() as { port: number }).port}`;
    try {
      await db.update(backupTargets).set({ restUrl: legacy.restUrl }).where(eq(backupTargets.id, target.id));
      await expect(offsite.runRestic(legacy, keys, ["snapshots", "--json"])).rejects.toThrow(/require http/);
      await expect(offsite.verifyTarget(target.id)).rejects.toThrow(/require http/);
      expect((await observer.currentTailnetIdentity(target.id)).ok).toBe(false);
      expect(connections).toBe(0);
      expect(await calls()).toEqual([]);
    } finally {
      await db.update(backupTargets).set({ enabled: false }).where(eq(backupTargets.id, target.id));
      proxy.close();
      if (previousDial === undefined) delete process.env.ARK_TEST_SOCKS5_DIAL;
      else process.env.ARK_TEST_SOCKS5_DIAL = previousDial;
    }
  });

  test("a refresh committed between header and nodes cannot abort an unchanged identity", async () => {
    view = state([home]);
    await observe();
    const target = await saveHome(`atomic-${suffix}`);
    const old = await loadTailnetSnapshot("backup");
    const loaded = await loadTailnetSnapshot("backup", async () => {
      await Bun.sleep(2);
      await observe();
    });
    expect(loaded.snapshot!.generation).toBe(old.snapshot!.generation);
    expect(loaded.self!.generation).toBe(loaded.snapshot!.generation);
    expect(loaded.peers.every((node) => node.generation === loaded.snapshot!.generation)).toBe(true);
    expect(observer.checkTailnetIdentity(target, loaded, new Date()).ok).toBe(true);
    expect((await loadTailnetSnapshot("backup")).snapshot!.generation).not.toBe(old.snapshot!.generation);
    await db.update(backupTargets).set({ enabled: false }).where(eq(backupTargets.id, target.id));
  });
});

describe("identity and freshness", () => {
  test("replaced, removed and expired identities are refused; an address change is followed", async () => {
    const [target] = await db
      .select()
      .from(backupTargets)
      .where(eq(backupTargets.name, `home-${suffix}`));
    view = state([home]);
    await observe();
    expect((await observer.currentTailnetIdentity(target!.id)).ok).toBe(true);

    view = state([impostor]);
    await observe();
    const replaced = await observer.currentTailnetIdentity(target!.id);
    expect(replaced.ok).toBe(false);
    if (!replaced.ok) expect(replaced.status).toBe("identity_mismatch");

    view = state([]);
    await observe();
    const removed = await observer.currentTailnetIdentity(target!.id);
    expect(removed.ok).toBe(false);
    if (!removed.ok) expect(removed.status).toBe("awaiting_acl");

    view = state([home]);
    await observe(1_000);
    expect((await observer.currentTailnetIdentity(target!.id)).ok).toBe(true);
    await Bun.sleep(1_100);
    const expired = await observer.currentTailnetIdentity(target!.id);
    expect(expired.ok).toBe(false);
    if (!expired.ok) expect(expired.status).toBe("observation_expired");

    view = state([{ ...home, ips: ["100.66.2.77"] }]);
    const result = await observe();
    expect(result.targets.find((item) => item.id === target!.id)?.identity).toBe("ip_changed");
    const [moved] = await db.select().from(backupTargets).where(eq(backupTargets.id, target!.id));
    expect(moved!.targetIp).toBe("100.66.2.77");
    const audits = await db
      .select()
      .from(auditEvents)
      .where(and(eq(auditEvents.resourceId, target!.id), eq(auditEvents.action, "backup.target_ip_changed")));
    expect(audits.length).toBe(1);
    view = state([home]);
    await observe();
  });
});

describe("transfers: proxy scoping, refusal and the watchdog", () => {
  test("only the REST subprocess gets the SOCKS5 proxy; S3 never inherits proxy settings", async () => {
    const s3 = await offsite.saveS3Target({
      name: `s3-${suffix}`,
      provider: "minio",
      endpoint: "http://127.0.0.1:9",
      region: "us-east-1",
      bucket: "fd30-bucket",
      prefix: "ark",
      pathStyle: true,
      recoveryWindowDays: 1,
      accessKeyId: "fd30-writer",
      secretAccessKey: "fd30-writer-secret",
      repositoryPassword: "repository-password-0123456789",
    });
    created.push(s3.id);
    // Conflicting proxy settings on the worker itself must reach neither subprocess.
    Object.assign(process.env, {
      HTTP_PROXY: "http://decoy.invalid:3128",
      HTTPS_PROXY: "http://decoy.invalid:3128",
      ALL_PROXY: "socks5://decoy.invalid:1080",
      NO_PROXY: "*",
      no_proxy: "*",
    });
    try {
      await calls();
      const results = await offsite.exportFiles(`volume:fd30-${suffix}`, work, []);
      const mine = results.filter((item) => created.includes(item.targetId));
      expect(mine.map((item) => item.error ?? "ok")).toEqual(["ok", "ok"]);
      const invocations = (await calls()).filter((item) => item.ARGS?.includes(" backup "));
      const rest = invocations.find((item) => item.RESTIC_REST_USERNAME === "ark")!;
      const s3Call = invocations.find((item) => item.AWS_ACCESS_KEY_ID === "fd30-writer")!;
      expect(rest.ARGS).toContain("-r rest:http://100.66.2.9:8000/ark/ ");
      expect(rest.HTTP_PROXY).toBe("socks5://backup-ts:1055");
      for (const name of [
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
      ])
        expect(rest[name]).toBe("<unset>");
      expect(rest.RESTIC_REST_PASSWORD_SET).toBe("yes");
      expect(rest.AWS_ACCESS_KEY_ID).toBe("<unset>");
      expect(s3Call.ARGS).toContain("-r s3:http://127.0.0.1:9/fd30-bucket/ark/restic");
      for (const name of [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
      ])
        expect(s3Call[name]).toBe("<unset>");
      expect(s3Call.RESTIC_REST_USERNAME).toBe("<unset>");
    } finally {
      for (const name of ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "no_proxy"])
        delete process.env[name];
      await db.update(backupTargets).set({ enabled: false }).where(eq(backupTargets.id, s3.id));
    }
  });

  test("with an expired observation a new transfer never starts and every source fails", async () => {
    const [target] = await db
      .select()
      .from(backupTargets)
      .where(eq(backupTargets.name, `home-${suffix}`));
    await observe(500);
    await Bun.sleep(600);
    await calls();
    await expect(offsite.exportTarget(target!.id)).rejects.toThrow(
      /not started: backup-ts's tailnet observation/,
    );
    expect(await calls()).toEqual([]);
    const rows = await db.select().from(backupExports).where(eq(backupExports.targetId, target!.id));
    const failed = rows.filter((row) => row.status === "failed" && row.source.startsWith("pg:"));
    expect(failed.length).toBe(2);
    expect(failed.every((row) => row.lastRecoverableAt === null)).toBe(true);
    const health = await offsite.backupHealth();
    const mine = health.targets.find((item) => item.id === target!.id)!;
    expect(mine.healthy).toBe(false);
    expect(health.alerts).toContainEqual(
      expect.objectContaining({ dedupKey: `backup-tailnet:${target!.id}`, severity: "critical" }),
    );
    view = state([home]);
    await observe();
  });

  for (const change of ["replaced", "removed", "expired"] as const) {
    test(`an active REST transfer stops within the bound when the identity is ${change}`, async () => {
      const [target] = await db
        .select()
        .from(backupTargets)
        .where(eq(backupTargets.name, `home-${suffix}`));
      view = state([home]);
      await observe(change === "expired" ? 3_000 : undefined);
      const block = join(work, "block");
      const pidPath = join(work, "pid");
      await rm(pidPath, { force: true });
      await writeFile(block, "");
      const running = offsite.exportFiles(`volume:fd30-guard-${suffix}`, work, []);
      // A setup error must still release the fake upload and wait for it before the next case.
      const settled = running.catch(() => undefined);
      try {
        const deadline = Date.now() + 5_000;
        let pid = 0;
        while (Date.now() < deadline) {
          pid = Number(await readFile(pidPath, "utf8").catch(() => ""));
          if (Number.isInteger(pid) && pid > 0) break;
          await Bun.sleep(20);
        }
        if (!Number.isInteger(pid) || pid <= 0) throw new Error("The REST upload did not start.");
        expect(process.kill(pid, 0)).toBe(true);
        let changedAt: number;
        if (change === "expired") {
          const [row] = await sql`SELECT valid_until FROM tailnet_snapshots WHERE source = 'backup'`;
          changedAt = new Date(row!.valid_until).getTime();
        } else {
          view = state(change === "replaced" ? [impostor] : []);
          await observe();
          changedAt = Date.now();
        }
        const results = await running;
        const stoppedAt = Date.now();
        const mine = results.find((item) => item.targetId === target!.id)!;
        expect(mine.error).toMatch(/stopped by the transfer watchdog|Transfer stopped/);
        expect(stoppedAt - changedAt).toBeLessThan(TRANSFER_STOP_BOUND_MS);
        expect(() => process.kill(pid, 0)).toThrow(expect.objectContaining({ code: "ESRCH" }));
      } finally {
        await rm(block, { force: true });
        await settled;
        await rm(pidPath, { force: true });
        view = state([home]);
        await observe();
      }
    }, 15_000);
  }
});

describe("watchdog deadlines independent of control reads", () => {
  test("hard expiry aborts while the next read remains unresolved; late reads cannot renew it", async () => {
    let readCount = 0;
    let finish!: (value: {
      identity: import("./modules/backup-observe.ts").TailnetIdentity;
      validUntil: Date;
    }) => void;
    const identity = { ok: true as const, stableId: home.id, ip: home.ips[0]!, ipChanged: false };
    const guard = observer.guardTransfer("deadline-fixture", {
      intervalMs: 20,
      readState: async () => {
        if (++readCount === 1) return { identity, validUntil: new Date(Date.now() + 100) };
        return new Promise((resolve) => {
          finish = resolve;
        });
      },
    });
    try {
      await new Promise<void>((resolve) =>
        guard.signal.addEventListener("abort", () => resolve(), { once: true }),
      );
      expect(readCount).toBe(2);
      expect(guard.reason()).toMatch(/expired/);
      finish({ identity, validUntil: new Date(Date.now() + 60_000) });
      await Bun.sleep(30);
      expect(guard.reason()).toMatch(/expired/);
      expect(readCount).toBe(2);
    } finally {
      guard.stop();
    }
  });

  test("a never-settling initial query still aborts within the read budget", async () => {
    const started = Date.now();
    const guard = observer.guardTransfer("unreachable-db", { readState: () => new Promise(() => {}) });
    try {
      await new Promise<void>((resolve) =>
        guard.signal.addEventListener("abort", () => resolve(), { once: true }),
      );
      expect(guard.reason()).toMatch(/timed out/);
      expect(Date.now() - started).toBeLessThan(TRANSFER_STOP_BOUND_MS - 2_000);
    } finally {
      guard.stop();
    }
  });

  test("a real stalled database read cannot keep an upload subprocess alive", async () => {
    view = state([home]);
    await observe(3_000);
    const target = await saveHome(`db-stall-${suffix}`);
    await writeFile(join(work, "block"), "");
    await rm(join(work, "pid"), { force: true });
    const keys = await offsite.targetSecrets(target);
    const upload = offsite.withTransfer(target, (signal) =>
      offsite.runRestic(target, keys, ["backup", work], 30_000, undefined, { signal }),
    );
    let release!: () => void;
    let locked!: () => void;
    const acquired = new Promise<void>((resolve) => {
      locked = resolve;
    });
    let transaction: Promise<unknown> | undefined;
    try {
      const deadline = Date.now() + 3_000;
      while (!(await Bun.file(join(work, "pid")).exists())) {
        if (Date.now() > deadline) throw new Error("upload did not start");
        await Bun.sleep(10);
      }
      const pid = Number(await Bun.file(join(work, "pid")).text());
      await Bun.sleep(100); // the initial guard read establishes its local lease
      const hold = new Promise<void>((resolve) => {
        release = resolve;
      });
      transaction = sql.begin(async (tx) => {
        await tx`LOCK TABLE tailnet_snapshots IN ACCESS EXCLUSIVE MODE`;
        locked();
        await hold;
      });
      await acquired;
      const started = Date.now();
      await expect(upload).rejects.toThrow(/watchdog|Transfer stopped/);
      expect(Date.now() - started).toBeLessThan(TRANSFER_STOP_BOUND_MS);
      expect(() => process.kill(pid, 0)).toThrow();
    } finally {
      release?.();
      await transaction;
      await rm(join(work, "block"), { force: true });
    }
  }, 10_000);

  test("identity replacement cancels an in-flight canary POST and closes its socket", async () => {
    view = state([home]);
    await observe();
    const target = await saveHome(`canary-cancel-${suffix}`);
    const previousDial = process.env.ARK_TEST_SOCKS5_DIAL;
    const sockets = new Set<Socket>();
    let posted = false;
    let closed = false;
    const proxy = createServer((socket) => {
      sockets.add(socket);
      socket.on("error", () => {});
      socket.once("close", () => {
        sockets.delete(socket);
        closed = true;
      });
      let stage = 0;
      socket.on("data", (data) => {
        if (stage++ === 0) socket.write(Buffer.from([5, 0]));
        else if (stage === 2) socket.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
        else if (data.toString().startsWith("POST ")) posted = true; // hold response open
      });
    });
    await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
    process.env.ARK_TEST_SOCKS5_DIAL = `127.0.0.1:${(proxy.address() as { port: number }).port}`;
    const pending = offsite.verifyTarget(target.id).catch((error: Error) => error);
    try {
      await waitUntil(() => posted, 3_000);
      expect(posted).toBe(true);
      view = state([impostor]);
      const changedAt = Date.now();
      await observe();
      expect(((await pending) as Error).message).toMatch(/Transfer stopped/);
      await waitUntil(() => closed, 500);
      expect(closed).toBe(true);
      expect(Date.now() - changedAt).toBeLessThan(TRANSFER_STOP_BOUND_MS);
    } finally {
      for (const socket of sockets) socket.destroy();
      proxy.close();
      if (previousDial === undefined) delete process.env.ARK_TEST_SOCKS5_DIAL;
      else process.env.ARK_TEST_SOCKS5_DIAL = previousDial;
      view = state([home]);
      await observe();
    }
  });
});

/** In-memory rest-server: append-only refuses deletes (except locks) and overwrites. */
function server(mode: { appendOnly: boolean; auth: boolean; privateRepos: boolean }): RestRequest {
  const files = new Map<string, Uint8Array>();
  return async ({ method, path, body, auth }) => {
    if (mode.auth && auth === false) return { status: 401, body: new Uint8Array() };
    if (path.startsWith("/")) return { status: mode.privateRepos ? 401 : 404, body: new Uint8Array() };
    const type = path.split("/")[0]!;
    if (method === "POST") {
      if (files.has(path) && mode.appendOnly && type !== "locks")
        return { status: 403, body: new Uint8Array() };
      files.set(path, body ?? new Uint8Array());
      return { status: 200, body: new Uint8Array() };
    }
    if (method === "DELETE") {
      if (mode.appendOnly && type !== "locks") return { status: 403, body: new Uint8Array() };
      return { status: files.delete(path) ? 200 : 404, body: new Uint8Array() };
    }
    if (path.endsWith("/")) return { status: 200, body: new TextEncoder().encode("[]") };
    const file = files.get(path);
    return file ? { status: 200, body: file } : { status: 404, body: new Uint8Array() };
  };
}
describe("append-only canary for rest-server", () => {
  const pinned = { stableId: "nHOME", ip: "100.66.2.9" };

  test("rest-server --append-only --private-repos with htpasswd passes", async () => {
    const evidence = await runRestCanary({
      request: server({ appendOnly: true, auth: true, privateRepos: true }),
      restUrl: homeUrl,
      pinned,
    });
    expect(evidence.findings).toEqual([]);
    expect(evidence.status).toBe("append_only");
    expect(evidence.attempts.deleteCanary).toBe(403);
    expect(evidence.attempts.deleteLock).toBe(200);
  });

  test("a server without --append-only is deletable; missing auth or private repos is unknown", async () => {
    expect(
      (
        await runRestCanary({
          request: server({ appendOnly: false, auth: true, privateRepos: true }),
          restUrl: homeUrl,
          pinned,
        })
      ).status,
    ).toBe("deletable");
    expect(
      (
        await runRestCanary({
          request: server({ appendOnly: true, auth: false, privateRepos: true }),
          restUrl: homeUrl,
          pinned,
        })
      ).status,
    ).toBe("unknown");
    expect(
      (
        await runRestCanary({
          request: server({ appendOnly: true, auth: true, privateRepos: false }),
          restUrl: homeUrl,
          pinned,
        })
      ).status,
    ).toBe("unknown");
  });
});
