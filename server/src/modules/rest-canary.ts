// Append-only canary for the home `rest-server` target (docs/design/front-door.md §3.18.2-3, FD-30).
//
// It runs with the deployed htpasswd credentials, through backup-ts's SOCKS5 proxy to the pinned
// address, exactly as restic does, and only ever probes objects it created itself or names that
// cannot exist:
//   1. writes a random canary pack under data/ (named by its SHA-256, as rest-server verifies);
//   2. tries to overwrite it and to delete it: both must be refused (403);
//   3. reads it back: the original hash must still be there;
//   4. deletes never-existing names under snapshots/, keys/ and index/: append-only refuses every
//      delete with 403, while a deletable server answers 404 (nothing is touched either way);
//   5. creates and removes a lock: restic must be able to remove its own locks (V-18);
//   6. checks that htpasswd authentication and `--private-repos` are enforced.
// It never writes or deletes `config`, keys, snapshots or index files: on a server that is not
// append-only that could destroy the repository.
import { createHash, randomBytes } from "node:crypto";

import type { AppendOnlyStatus } from "@ark-stack/shared";

export type RestRequest = (input: {
  method: string;
  /** Relative to the repository URL; a leading "/" is absolute on the server. */
  path: string;
  body?: Uint8Array;
  auth?: boolean;
}) => Promise<{ status: number; body: Uint8Array }>;

export type RestCanaryFinding = { kind: "deletable" | "unknown"; message: string };

export type RestCanaryEvidence = {
  version: 1;
  kind: "tailnet_rest";
  checkedAt: string;
  restUrl: string;
  pinned: { stableId: string; ip: string };
  canary: { name: string; sha256: string };
  attempts: Record<string, number | string>;
  retentionUntil: null;
  findings: RestCanaryFinding[];
  status: AppendOnlyStatus;
};

function sha256(bytes: Uint8Array) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function attempt(request: RestRequest, input: Parameters<RestRequest>[0]) {
  try {
    return await request(input);
  } catch (error) {
    return { status: -1, body: new Uint8Array(), error: (error as Error).message };
  }
}

export async function runRestCanary(input: {
  request: RestRequest;
  restUrl: string;
  pinned: { stableId: string; ip: string };
  now?: () => Date;
}): Promise<RestCanaryEvidence> {
  const now = input.now ?? (() => new Date());
  const findings: RestCanaryFinding[] = [];
  const attempts: Record<string, number | string> = {};
  const record = (name: string, result: { status: number; error?: string }) => {
    attempts[name] = result.status === -1 ? `error: ${result.error ?? "request failed"}` : result.status;
    return result.status;
  };
  const unknown = (message: string) => findings.push({ kind: "unknown", message });
  const deletable = (message: string) => findings.push({ kind: "deletable", message });

  const content = new Uint8Array(randomBytes(256));
  const name = sha256(content);
  const created = record(
    "createCanary",
    await attempt(input.request, { method: "POST", path: `data/${name}`, body: content }),
  );
  if (created < 200 || created > 299) {
    unknown(
      `The canary pack could not be written (${attempts.createCanary}); is the repository initialised?`,
    );
  } else {
    const overwrite = record(
      "overwriteCanary",
      await attempt(input.request, { method: "POST", path: `data/${name}`, body: content }),
    );
    if (overwrite >= 200 && overwrite <= 299) deletable("An existing pack can be overwritten.");
    else if (overwrite !== 403)
      unknown(`Overwriting an existing pack answered ${attempts.overwriteCanary}, not 403.`);
    const removed = record(
      "deleteCanary",
      await attempt(input.request, { method: "DELETE", path: `data/${name}` }),
    );
    if (removed >= 200 && removed <= 299)
      deletable("A pack can be deleted: rest-server is not running with --append-only.");
    else if (removed !== 403) unknown(`Deleting a pack answered ${attempts.deleteCanary}, not 403.`);
    const read = await attempt(input.request, { method: "GET", path: `data/${name}` });
    record("readCanary", read);
    if (read.status !== 200 || sha256(read.body) !== name) {
      if (!(removed >= 200 && removed <= 299))
        unknown(`The canary pack did not read back unchanged (${attempts.readCanary}).`);
    }
  }
  for (const type of ["snapshots", "keys", "index"] as const) {
    const missing = randomBytes(32).toString("hex");
    const status = record(
      `delete-${type}`,
      await attempt(input.request, { method: "DELETE", path: `${type}/${missing}` }),
    );
    if (status === 404 || (status >= 200 && status <= 299)) {
      deletable(`Deleting under ${type}/ is not refused (${status}): the server is not append-only.`);
    } else if (status !== 403) {
      unknown(`Deleting under ${type}/ answered ${attempts[`delete-${type}`]}, not 403.`);
    }
  }
  const lockBody = new Uint8Array(randomBytes(64));
  const lock = sha256(lockBody);
  const lockCreated = record(
    "createLock",
    await attempt(input.request, { method: "POST", path: `locks/${lock}`, body: lockBody }),
  );
  const lockRemoved = record(
    "deleteLock",
    await attempt(input.request, { method: "DELETE", path: `locks/${lock}` }),
  );
  if (!(lockCreated >= 200 && lockCreated <= 299 && lockRemoved >= 200 && lockRemoved <= 299)) {
    unknown(
      `restic cannot create and remove its lock files (${attempts.createLock}/${attempts.deleteLock}).`,
    );
  }
  const anonymous = record(
    "unauthenticated",
    await attempt(input.request, { method: "GET", path: "keys/", auth: false }),
  );
  if (anonymous !== 401)
    unknown(`An unauthenticated request answered ${attempts.unauthenticated}; configure htpasswd.`);
  const foreign = record(
    "otherRepository",
    await attempt(input.request, {
      method: "GET",
      path: `/${randomBytes(6).toString("hex")}-ark-canary/keys/`,
    }),
  );
  if (foreign !== 401 && foreign !== 403) {
    unknown(
      `Another user's repository path answered ${attempts.otherRepository}; run rest-server with --private-repos.`,
    );
  }

  const status: AppendOnlyStatus = findings.some((item) => item.kind === "deletable")
    ? "deletable"
    : findings.length
      ? "unknown"
      : "append_only";
  return {
    version: 1,
    kind: "tailnet_rest",
    checkedAt: now().toISOString(),
    restUrl: input.restUrl,
    pinned: input.pinned,
    canary: { name, sha256: name },
    attempts,
    retentionUntil: null,
    findings,
    status,
  };
}
