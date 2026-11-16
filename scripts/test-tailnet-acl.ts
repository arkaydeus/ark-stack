// Opt-in check of the generated Tailscale policy snippet against a real (scratch) tailnet
// (docs/design/front-door.md §3.7, FD-07). See docs/operating.md, "Tailnet policy snippet".
//
// It calls only `POST /api/v2/tailnet/{tailnet}/acl/validate`, which never changes the policy and
// needs only the `policy_file:read` scope. Without ARK_TEST_TS_POLICY_API_KEY it skips cleanly.
//
//   ARK_TEST_TS_POLICY_API_KEY=tskey-api-... mise run test:tailnet-acl
//
// Checks:
//   1. The §3.7 sample snippet validates on its own (syntax, tag owners, hosts, grants and tests).
//   2. The snippet plus the optional SSH example for tag:ark-vps also validates.
//   3. Adding a broad {"src":["*"],"dst":["*"],"ip":["*"]} grant makes the snippet's tests fail.
//   4. Adding a legacy allow-all ACL makes them fail too.

import {
  BROAD_GRANT,
  generateTailnetAcl,
  parseHujson,
  type AclSnippetInput,
  type TailnetPolicy,
} from "../shared/src/tailnet-acl.ts";

const key = process.env.ARK_TEST_TS_POLICY_API_KEY?.trim();
if (!key) {
  console.log(
    "test:tailnet-acl skipped: set ARK_TEST_TS_POLICY_API_KEY to a scratch tailnet API access token " +
      "(policy_file:read is enough) to validate the generated snippet against Tailscale.",
  );
  process.exit(0);
}

const tailnet = process.env.ARK_TEST_TS_TAILNET?.trim() || "-";
const apiBase = (process.env.ARK_TEST_TS_API_URL?.trim() || "https://api.tailscale.com").replace(/\/$/, "");

// The §3.7 example: one route of every kind and the tailnet backup target.
const sample: AclSnippetInput = {
  tailnet: null,
  routes: [
    {
      id: "rt_k3x9",
      kind: "http",
      hostname: "www.example.com",
      listenPort: 443,
      targetIp: "100.101.102.103",
      targetPort: 3000,
      targetNodeStableId: "nXYZ123CNTRL",
      targetName: "home.tail1234.ts.net",
    },
    {
      id: "rt_pg01",
      kind: "postgres",
      hostname: "pg-home.example.com",
      listenPort: 5432,
      tlsMode: "passthrough",
      targetIp: "100.90.4.7",
      targetPort: 5432,
      targetNodeStableId: "nPGH789CNTRL",
      targetName: "pg-home.tail1234.ts.net",
    },
    {
      id: "rt_p7q2",
      kind: "tls",
      hostname: "mqtt.example.com",
      listenPort: 8883,
      tlsMode: "terminate_mtls",
      targetIp: "100.88.1.20",
      targetPort: 1883,
      targetNodeStableId: "nABC456CNTRL",
      targetName: "nas.tail1234.ts.net",
    },
    {
      id: "rt_t001",
      kind: "tcp",
      hostname: "ssh-box.example.com",
      listenPort: 20001,
      tlsMode: "plain",
      targetIp: "100.77.9.3",
      targetPort: 22,
      targetNodeStableId: "nDEF012CNTRL",
      targetName: "box.tail1234.ts.net",
    },
  ],
  backupTargets: [
    {
      id: "bkt_home",
      name: "home",
      ip: "100.66.2.9",
      port: 8000,
      stableId: "nBAK345CNTRL",
      targetName: "backup-home.tail1234.ts.net",
    },
  ],
};

type Outcome = { ok: true } | { ok: false; status: number; message: string; details: string };

async function validate(
  body: string,
  contentType: "application/hujson" | "application/json",
): Promise<Outcome> {
  const response = await fetch(`${apiBase}/api/v2/tailnet/${encodeURIComponent(tailnet)}/acl/validate`, {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": contentType, accept: "application/json" },
    body,
    signal: AbortSignal.timeout(30_000),
  });
  const text = (await response.text()).trim();
  let parsed: { message?: string; data?: unknown } = {};
  try {
    parsed = text ? (JSON.parse(text) as typeof parsed) : {};
  } catch {
    parsed = { message: text };
  }
  // "An empty response body implies passing validation or tests."
  if (response.ok && !parsed.message && !parsed.data) return { ok: true };
  return {
    ok: false,
    status: response.status,
    message: parsed.message ?? `HTTP ${response.status}`,
    details: parsed.data ? JSON.stringify(parsed.data) : "",
  };
}

function merged(policy: TailnetPolicy, extra: TailnetPolicy): TailnetPolicy {
  return {
    ...policy,
    grants: [...(policy.grants ?? []), ...(extra.grants ?? [])],
    ...(extra.acls ? { acls: extra.acls } : {}),
    ...(extra.ssh ? { ssh: extra.ssh } : {}),
  };
}

function isAuthFailure(outcome: Outcome) {
  return !outcome.ok && (outcome.status === 401 || outcome.status === 403 || outcome.status === 404);
}

const snippet = generateTailnetAcl(sample);
const ssh = parseHujson(snippet.sshExample) as TailnetPolicy;
const checks: Array<{ name: string; run: () => Promise<Outcome>; expect: "accept" | "reject" }> = [
  {
    name: "generated snippet validates",
    run: () => validate(snippet.hujson, "application/hujson"),
    expect: "accept",
  },
  {
    name: "snippet plus the tag:ark-vps SSH example validates",
    run: () => validate(JSON.stringify(merged(snippet.policy, ssh)), "application/json"),
    expect: "accept",
  },
  {
    name: 'snippet plus {"src":["*"],"dst":["*"],"ip":["*"]} is rejected by its tests',
    run: () =>
      validate(JSON.stringify(merged(snippet.policy, { grants: [BROAD_GRANT] })), "application/json"),
    expect: "reject",
  },
  {
    name: "snippet plus a legacy allow-all ACL is rejected by its tests",
    run: () =>
      validate(
        JSON.stringify(merged(snippet.policy, { acls: [{ action: "accept", src: ["*"], dst: ["*:*"] }] })),
        "application/json",
      ),
    expect: "reject",
  },
];

let failed = 0;
for (const check of checks) {
  const outcome = await check.run();
  if (isAuthFailure(outcome) && !outcome.ok) {
    console.error(`FAIL ${check.name}: the API refused the token (${outcome.status} ${outcome.message}).`);
    process.exit(1);
  }
  // A rejection must come from the snippet's tests, not from a syntax error in the policy.
  const testFailure = !outcome.ok && /test/i.test(`${outcome.message} ${outcome.details}`);
  const passed = check.expect === "accept" ? outcome.ok : testFailure;
  if (passed) {
    console.log(`ok   ${check.name}${outcome.ok ? "" : ` (${outcome.message}: ${outcome.details})`}`);
  } else {
    failed++;
    console.error(
      `FAIL ${check.name}: ${outcome.ok ? "the policy was accepted" : `${outcome.status} ${outcome.message} ${outcome.details}`}`,
    );
  }
}

if (failed) {
  console.error(`test:tailnet-acl: ${failed} of ${checks.length} checks failed.`);
  process.exit(1);
}
console.log(`test:tailnet-acl: all ${checks.length} checks passed against tailnet ${tailnet}.`);
