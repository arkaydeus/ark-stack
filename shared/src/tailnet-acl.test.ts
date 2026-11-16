import { describe, expect, test } from "bun:test";

import {
  auditTailnetPolicy,
  ARK_BACKUP_TAG,
  ARK_EDGE_TAG,
  ARK_TAGS,
  BROAD_GRANT,
  diffLines,
  evaluatePolicyTests,
  generateTailnetAcl,
  parseHujson,
  policyAllows,
  tailnetBackupTarget,
  type AclBackupTarget,
  type AclRoute,
  type AclSnippetInput,
  type TailnetPolicy,
} from "./tailnet-acl.ts";

// The §3.7 example: one route of every kind plus the tailnet backup target.
const routes: AclRoute[] = [
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
];
const backup: AclBackupTarget = {
  id: "bkt_home",
  name: "home",
  ip: "100.66.2.9",
  port: 8000,
  stableId: "nBAK345CNTRL",
  targetName: "backup-home.tail1234.ts.net",
};
const sample: AclSnippetInput = { routes, backupTargets: [backup], tailnet: "tail1234.ts.net" };

function edgeAndBackupPairs(policy: TailnetPolicy) {
  const pairs = (tag: string) =>
    (policy.grants ?? [])
      .filter((grant) => grant.src.includes(tag))
      .flatMap((grant) => grant.dst.flatMap((dst) => grant.ip.map((ip) => `${policy.hosts?.[dst]}|${ip}`)));
  return { edge: pairs(ARK_EDGE_TAG), backup: pairs(ARK_BACKUP_TAG) };
}

describe("generateTailnetAcl snapshot", () => {
  test("every route kind and the backup target, in the §3.7 structure", () => {
    const snippet = generateTailnetAcl(sample);
    expect(snippet.omitted).toEqual([]);
    expect(snippet.hujson).toMatchInlineSnapshot(`
      "// Ark Stack front door — Tailscale policy snippet for all front-door routes and tailnet backup targets on tailnet tail1234.ts.net.
      // Merge each section into your tailnet policy file. Ark does not hold any Tailscale credential.
      // Tests sample TCP/UDP ports on known nodes and Ark tags; they do not prove tailnet-wide isolation.
      {
        "tagOwners": {
          "tag:ark-edge": ["autogroup:admin"],
          "tag:ark-backup": ["autogroup:admin"],
          "tag:ark-stack-admin": ["autogroup:admin"],
          "tag:ark-vps": ["autogroup:admin"],
        },
        "hosts": {
          // ssh-box.example.com (tcp, 20001) — pinned to StableID nDEF012CNTRL (box.tail1234.ts.net)
          "ark-rt-box": "100.77.9.3",
          // www.example.com (http, 443) — pinned to StableID nXYZ123CNTRL (home.tail1234.ts.net)
          "ark-rt-home": "100.101.102.103",
          // mqtt.example.com (tls, 8883, terminate_mtls) — pinned to StableID nABC456CNTRL (nas.tail1234.ts.net)
          "ark-rt-nas": "100.88.1.20",
          // pg-home.example.com (postgres, 5432, passthrough) — pinned to StableID nPGH789CNTRL (pg-home.tail1234.ts.net)
          "ark-rt-pg-home": "100.90.4.7",
          // backup target home (tailnet rest-server, 8000) — pinned to StableID nBAK345CNTRL (backup-home.tail1234.ts.net)
          "ark-backup-home": "100.66.2.9",
        },
        "grants": [
          // ssh-box.example.com (tcp, 20001)
          { "src": ["tag:ark-edge"], "dst": ["ark-rt-box"], "ip": ["tcp:22"] },
          // www.example.com (http, 443)
          { "src": ["tag:ark-edge"], "dst": ["ark-rt-home"], "ip": ["tcp:3000"] },
          // mqtt.example.com (tls, 8883, terminate_mtls)
          { "src": ["tag:ark-edge"], "dst": ["ark-rt-nas"], "ip": ["tcp:1883"] },
          // pg-home.example.com (postgres, 5432, passthrough)
          { "src": ["tag:ark-edge"], "dst": ["ark-rt-pg-home"], "ip": ["tcp:5432"] },
          // backup target home (tailnet rest-server)
          { "src": ["tag:ark-backup"], "dst": ["ark-backup-home"], "ip": ["tcp:8000"] },
        ],
        "tests": [
          {
            "src": "tag:ark-edge",
            "proto": "tcp",
            "accept": ["ark-rt-box:22", "ark-rt-home:3000", "ark-rt-nas:1883", "ark-rt-pg-home:5432"],
            "deny": [
              "ark-rt-box:80",
              "ark-rt-box:443",
              "ark-rt-box:3389",
              "ark-rt-box:5900",
              "ark-rt-box:445",
              "ark-rt-box:23",
              "ark-rt-box:2375",
              "ark-rt-box:8080",
              "ark-rt-box:8443",
              "ark-rt-box:65535",
              "ark-rt-box:3000",
              "ark-rt-box:1883",
              "ark-rt-box:5432",
              "ark-rt-box:8000",
              "ark-rt-home:22",
              "ark-rt-home:80",
              "ark-rt-home:443",
              "ark-rt-home:3389",
              "ark-rt-home:5900",
              "ark-rt-home:445",
              "ark-rt-home:23",
              "ark-rt-home:2375",
              "ark-rt-home:8080",
              "ark-rt-home:8443",
              "ark-rt-home:65535",
              "ark-rt-home:1883",
              "ark-rt-home:5432",
              "ark-rt-home:8000",
              "ark-rt-nas:22",
              "ark-rt-nas:80",
              "ark-rt-nas:443",
              "ark-rt-nas:3389",
              "ark-rt-nas:5900",
              "ark-rt-nas:445",
              "ark-rt-nas:23",
              "ark-rt-nas:2375",
              "ark-rt-nas:8080",
              "ark-rt-nas:8443",
              "ark-rt-nas:65535",
              "ark-rt-nas:3000",
              "ark-rt-nas:5432",
              "ark-rt-nas:8000",
              "ark-rt-pg-home:22",
              "ark-rt-pg-home:80",
              "ark-rt-pg-home:443",
              "ark-rt-pg-home:3389",
              "ark-rt-pg-home:5900",
              "ark-rt-pg-home:445",
              "ark-rt-pg-home:23",
              "ark-rt-pg-home:2375",
              "ark-rt-pg-home:8080",
              "ark-rt-pg-home:8443",
              "ark-rt-pg-home:65535",
              "ark-rt-pg-home:3000",
              "ark-rt-pg-home:1883",
              "ark-rt-pg-home:8000",
              "ark-backup-home:22",
              "ark-backup-home:80",
              "ark-backup-home:443",
              "ark-backup-home:3389",
              "ark-backup-home:5900",
              "ark-backup-home:445",
              "ark-backup-home:23",
              "ark-backup-home:2375",
              "ark-backup-home:8080",
              "ark-backup-home:8443",
              "ark-backup-home:65535",
              "ark-backup-home:3000",
              "ark-backup-home:1883",
              "ark-backup-home:5432",
              "ark-backup-home:8000",
              "tag:ark-backup:22",
              "tag:ark-backup:80",
              "tag:ark-backup:443",
              "tag:ark-backup:3389",
              "tag:ark-backup:5900",
              "tag:ark-backup:445",
              "tag:ark-backup:23",
              "tag:ark-backup:2375",
              "tag:ark-backup:8080",
              "tag:ark-backup:8443",
              "tag:ark-backup:65535",
              "tag:ark-stack-admin:443",
              "tag:ark-stack-admin:22",
              "tag:ark-stack-admin:80",
              "tag:ark-stack-admin:3389",
              "tag:ark-stack-admin:5900",
              "tag:ark-stack-admin:445",
              "tag:ark-stack-admin:23",
              "tag:ark-stack-admin:2375",
              "tag:ark-stack-admin:8080",
              "tag:ark-stack-admin:8443",
              "tag:ark-stack-admin:65535",
              "tag:ark-vps:22",
              "tag:ark-vps:80",
              "tag:ark-vps:443",
              "tag:ark-vps:3389",
              "tag:ark-vps:5900",
              "tag:ark-vps:445",
              "tag:ark-vps:23",
              "tag:ark-vps:2375",
              "tag:ark-vps:8080",
              "tag:ark-vps:8443",
              "tag:ark-vps:65535",
            ],
          },
          {
            "src": "tag:ark-edge",
            "proto": "udp",
            "deny": [
              "ark-rt-box:22",
              "ark-rt-box:80",
              "ark-rt-box:443",
              "ark-rt-box:3389",
              "ark-rt-box:5900",
              "ark-rt-box:445",
              "ark-rt-box:23",
              "ark-rt-box:2375",
              "ark-rt-box:8080",
              "ark-rt-box:8443",
              "ark-rt-box:65535",
              "ark-rt-box:3000",
              "ark-rt-box:1883",
              "ark-rt-box:5432",
              "ark-rt-box:8000",
              "ark-rt-home:22",
              "ark-rt-home:80",
              "ark-rt-home:443",
              "ark-rt-home:3389",
              "ark-rt-home:5900",
              "ark-rt-home:445",
              "ark-rt-home:23",
              "ark-rt-home:2375",
              "ark-rt-home:8080",
              "ark-rt-home:8443",
              "ark-rt-home:65535",
              "ark-rt-home:3000",
              "ark-rt-home:1883",
              "ark-rt-home:5432",
              "ark-rt-home:8000",
              "ark-rt-nas:22",
              "ark-rt-nas:80",
              "ark-rt-nas:443",
              "ark-rt-nas:3389",
              "ark-rt-nas:5900",
              "ark-rt-nas:445",
              "ark-rt-nas:23",
              "ark-rt-nas:2375",
              "ark-rt-nas:8080",
              "ark-rt-nas:8443",
              "ark-rt-nas:65535",
              "ark-rt-nas:3000",
              "ark-rt-nas:1883",
              "ark-rt-nas:5432",
              "ark-rt-nas:8000",
              "ark-rt-pg-home:22",
              "ark-rt-pg-home:80",
              "ark-rt-pg-home:443",
              "ark-rt-pg-home:3389",
              "ark-rt-pg-home:5900",
              "ark-rt-pg-home:445",
              "ark-rt-pg-home:23",
              "ark-rt-pg-home:2375",
              "ark-rt-pg-home:8080",
              "ark-rt-pg-home:8443",
              "ark-rt-pg-home:65535",
              "ark-rt-pg-home:3000",
              "ark-rt-pg-home:1883",
              "ark-rt-pg-home:5432",
              "ark-rt-pg-home:8000",
              "ark-backup-home:22",
              "ark-backup-home:80",
              "ark-backup-home:443",
              "ark-backup-home:3389",
              "ark-backup-home:5900",
              "ark-backup-home:445",
              "ark-backup-home:23",
              "ark-backup-home:2375",
              "ark-backup-home:8080",
              "ark-backup-home:8443",
              "ark-backup-home:65535",
              "ark-backup-home:3000",
              "ark-backup-home:1883",
              "ark-backup-home:5432",
              "ark-backup-home:8000",
              "tag:ark-backup:22",
              "tag:ark-backup:80",
              "tag:ark-backup:443",
              "tag:ark-backup:3389",
              "tag:ark-backup:5900",
              "tag:ark-backup:445",
              "tag:ark-backup:23",
              "tag:ark-backup:2375",
              "tag:ark-backup:8080",
              "tag:ark-backup:8443",
              "tag:ark-backup:65535",
              "tag:ark-stack-admin:443",
              "tag:ark-stack-admin:22",
              "tag:ark-stack-admin:80",
              "tag:ark-stack-admin:3389",
              "tag:ark-stack-admin:5900",
              "tag:ark-stack-admin:445",
              "tag:ark-stack-admin:23",
              "tag:ark-stack-admin:2375",
              "tag:ark-stack-admin:8080",
              "tag:ark-stack-admin:8443",
              "tag:ark-stack-admin:65535",
              "tag:ark-vps:22",
              "tag:ark-vps:80",
              "tag:ark-vps:443",
              "tag:ark-vps:3389",
              "tag:ark-vps:5900",
              "tag:ark-vps:445",
              "tag:ark-vps:23",
              "tag:ark-vps:2375",
              "tag:ark-vps:8080",
              "tag:ark-vps:8443",
              "tag:ark-vps:65535",
            ],
          },
          {
            "src": "tag:ark-backup",
            "proto": "tcp",
            "accept": ["ark-backup-home:8000"],
            "deny": [
              "ark-rt-box:22",
              "ark-rt-box:80",
              "ark-rt-box:443",
              "ark-rt-box:3389",
              "ark-rt-box:5900",
              "ark-rt-box:445",
              "ark-rt-box:23",
              "ark-rt-box:2375",
              "ark-rt-box:8080",
              "ark-rt-box:8443",
              "ark-rt-box:65535",
              "ark-rt-box:3000",
              "ark-rt-box:1883",
              "ark-rt-box:5432",
              "ark-rt-box:8000",
              "ark-rt-home:22",
              "ark-rt-home:80",
              "ark-rt-home:443",
              "ark-rt-home:3389",
              "ark-rt-home:5900",
              "ark-rt-home:445",
              "ark-rt-home:23",
              "ark-rt-home:2375",
              "ark-rt-home:8080",
              "ark-rt-home:8443",
              "ark-rt-home:65535",
              "ark-rt-home:3000",
              "ark-rt-home:1883",
              "ark-rt-home:5432",
              "ark-rt-home:8000",
              "ark-rt-nas:22",
              "ark-rt-nas:80",
              "ark-rt-nas:443",
              "ark-rt-nas:3389",
              "ark-rt-nas:5900",
              "ark-rt-nas:445",
              "ark-rt-nas:23",
              "ark-rt-nas:2375",
              "ark-rt-nas:8080",
              "ark-rt-nas:8443",
              "ark-rt-nas:65535",
              "ark-rt-nas:3000",
              "ark-rt-nas:1883",
              "ark-rt-nas:5432",
              "ark-rt-nas:8000",
              "ark-rt-pg-home:22",
              "ark-rt-pg-home:80",
              "ark-rt-pg-home:443",
              "ark-rt-pg-home:3389",
              "ark-rt-pg-home:5900",
              "ark-rt-pg-home:445",
              "ark-rt-pg-home:23",
              "ark-rt-pg-home:2375",
              "ark-rt-pg-home:8080",
              "ark-rt-pg-home:8443",
              "ark-rt-pg-home:65535",
              "ark-rt-pg-home:3000",
              "ark-rt-pg-home:1883",
              "ark-rt-pg-home:5432",
              "ark-rt-pg-home:8000",
              "ark-backup-home:22",
              "ark-backup-home:80",
              "ark-backup-home:443",
              "ark-backup-home:3389",
              "ark-backup-home:5900",
              "ark-backup-home:445",
              "ark-backup-home:23",
              "ark-backup-home:2375",
              "ark-backup-home:8080",
              "ark-backup-home:8443",
              "ark-backup-home:65535",
              "ark-backup-home:3000",
              "ark-backup-home:1883",
              "ark-backup-home:5432",
              "tag:ark-edge:443",
              "tag:ark-edge:22",
              "tag:ark-edge:80",
              "tag:ark-edge:3389",
              "tag:ark-edge:5900",
              "tag:ark-edge:445",
              "tag:ark-edge:23",
              "tag:ark-edge:2375",
              "tag:ark-edge:8080",
              "tag:ark-edge:8443",
              "tag:ark-edge:65535",
              "tag:ark-stack-admin:443",
              "tag:ark-stack-admin:22",
              "tag:ark-stack-admin:80",
              "tag:ark-stack-admin:3389",
              "tag:ark-stack-admin:5900",
              "tag:ark-stack-admin:445",
              "tag:ark-stack-admin:23",
              "tag:ark-stack-admin:2375",
              "tag:ark-stack-admin:8080",
              "tag:ark-stack-admin:8443",
              "tag:ark-stack-admin:65535",
              "tag:ark-vps:22",
              "tag:ark-vps:80",
              "tag:ark-vps:443",
              "tag:ark-vps:3389",
              "tag:ark-vps:5900",
              "tag:ark-vps:445",
              "tag:ark-vps:23",
              "tag:ark-vps:2375",
              "tag:ark-vps:8080",
              "tag:ark-vps:8443",
              "tag:ark-vps:65535",
            ],
          },
          {
            "src": "tag:ark-backup",
            "proto": "udp",
            "deny": [
              "ark-rt-box:22",
              "ark-rt-box:80",
              "ark-rt-box:443",
              "ark-rt-box:3389",
              "ark-rt-box:5900",
              "ark-rt-box:445",
              "ark-rt-box:23",
              "ark-rt-box:2375",
              "ark-rt-box:8080",
              "ark-rt-box:8443",
              "ark-rt-box:65535",
              "ark-rt-box:3000",
              "ark-rt-box:1883",
              "ark-rt-box:5432",
              "ark-rt-box:8000",
              "ark-rt-home:22",
              "ark-rt-home:80",
              "ark-rt-home:443",
              "ark-rt-home:3389",
              "ark-rt-home:5900",
              "ark-rt-home:445",
              "ark-rt-home:23",
              "ark-rt-home:2375",
              "ark-rt-home:8080",
              "ark-rt-home:8443",
              "ark-rt-home:65535",
              "ark-rt-home:3000",
              "ark-rt-home:1883",
              "ark-rt-home:5432",
              "ark-rt-home:8000",
              "ark-rt-nas:22",
              "ark-rt-nas:80",
              "ark-rt-nas:443",
              "ark-rt-nas:3389",
              "ark-rt-nas:5900",
              "ark-rt-nas:445",
              "ark-rt-nas:23",
              "ark-rt-nas:2375",
              "ark-rt-nas:8080",
              "ark-rt-nas:8443",
              "ark-rt-nas:65535",
              "ark-rt-nas:3000",
              "ark-rt-nas:1883",
              "ark-rt-nas:5432",
              "ark-rt-nas:8000",
              "ark-rt-pg-home:22",
              "ark-rt-pg-home:80",
              "ark-rt-pg-home:443",
              "ark-rt-pg-home:3389",
              "ark-rt-pg-home:5900",
              "ark-rt-pg-home:445",
              "ark-rt-pg-home:23",
              "ark-rt-pg-home:2375",
              "ark-rt-pg-home:8080",
              "ark-rt-pg-home:8443",
              "ark-rt-pg-home:65535",
              "ark-rt-pg-home:3000",
              "ark-rt-pg-home:1883",
              "ark-rt-pg-home:5432",
              "ark-rt-pg-home:8000",
              "ark-backup-home:22",
              "ark-backup-home:80",
              "ark-backup-home:443",
              "ark-backup-home:3389",
              "ark-backup-home:5900",
              "ark-backup-home:445",
              "ark-backup-home:23",
              "ark-backup-home:2375",
              "ark-backup-home:8080",
              "ark-backup-home:8443",
              "ark-backup-home:65535",
              "ark-backup-home:3000",
              "ark-backup-home:1883",
              "ark-backup-home:5432",
              "ark-backup-home:8000",
              "tag:ark-edge:443",
              "tag:ark-edge:22",
              "tag:ark-edge:80",
              "tag:ark-edge:3389",
              "tag:ark-edge:5900",
              "tag:ark-edge:445",
              "tag:ark-edge:23",
              "tag:ark-edge:2375",
              "tag:ark-edge:8080",
              "tag:ark-edge:8443",
              "tag:ark-edge:65535",
              "tag:ark-stack-admin:443",
              "tag:ark-stack-admin:22",
              "tag:ark-stack-admin:80",
              "tag:ark-stack-admin:3389",
              "tag:ark-stack-admin:5900",
              "tag:ark-stack-admin:445",
              "tag:ark-stack-admin:23",
              "tag:ark-stack-admin:2375",
              "tag:ark-stack-admin:8080",
              "tag:ark-stack-admin:8443",
              "tag:ark-stack-admin:65535",
              "tag:ark-vps:22",
              "tag:ark-vps:80",
              "tag:ark-vps:443",
              "tag:ark-vps:3389",
              "tag:ark-vps:5900",
              "tag:ark-vps:445",
              "tag:ark-vps:23",
              "tag:ark-vps:2375",
              "tag:ark-vps:8080",
              "tag:ark-vps:8443",
              "tag:ark-vps:65535",
            ],
          },
        ],
      }
      "
    `);
  });

  test("the HuJSON text parses to exactly the returned policy, in §3.7 section order", () => {
    const snippet = generateTailnetAcl(sample);
    const parsed = parseHujson(snippet.hujson) as TailnetPolicy;
    expect(parsed).toEqual(snippet.policy);
    expect(Object.keys(parsed)).toEqual(["tagOwners", "hosts", "grants", "tests"]);
    expect(parsed.tagOwners).toEqual({
      "tag:ark-edge": ["autogroup:admin"],
      "tag:ark-backup": ["autogroup:admin"],
      "tag:ark-stack-admin": ["autogroup:admin"],
      "tag:ark-vps": ["autogroup:admin"],
    });
    // One grant per (target host, port, protocol), always by the target's host:port.
    expect(parsed.grants).toEqual([
      { src: ["tag:ark-edge"], dst: ["ark-rt-box"], ip: ["tcp:22"] },
      { src: ["tag:ark-edge"], dst: ["ark-rt-home"], ip: ["tcp:3000"] },
      { src: ["tag:ark-edge"], dst: ["ark-rt-nas"], ip: ["tcp:1883"] },
      { src: ["tag:ark-edge"], dst: ["ark-rt-pg-home"], ip: ["tcp:5432"] },
      { src: ["tag:ark-backup"], dst: ["ark-backup-home"], ip: ["tcp:8000"] },
    ]);
    // Each comment names the public hostname and listener of every route kind.
    for (const text of [
      "www.example.com (http, 443)",
      "pg-home.example.com (postgres, 5432, passthrough)",
      "mqtt.example.com (tls, 8883, terminate_mtls)",
      "ssh-box.example.com (tcp, 20001)",
      "backup target home (tailnet rest-server, 8000)",
    ]) {
      expect(snippet.hujson).toContain(text);
    }
  });

  test("a per-route snippet names its scope and keeps the backup target off-limits", () => {
    const snippet = generateTailnetAcl({
      routes: [routes[0] as AclRoute],
      reservedTargets: [backup],
      scope: { routeId: "rt_k3x9", hostname: "www.example.com" },
    });
    expect(snippet.hujson.split("\n")[0]).toBe(
      "// Ark Stack front door — Tailscale policy snippet for route rt_k3x9 (www.example.com).",
    );
    expect(snippet.policy.grants).toEqual([
      { src: ["tag:ark-edge"], dst: ["ark-rt-home"], ip: ["tcp:3000"] },
    ]);
    expect(evaluatePolicyTests(snippet.policy)).toEqual([]);
  });

  test("the SSH example uses check mode for tag:ark-vps and is not part of the snippet", () => {
    const snippet = generateTailnetAcl(sample);
    const ssh = parseHujson(snippet.sshExample) as { ssh: Array<Record<string, unknown>> };
    expect(ssh.ssh).toEqual([
      {
        action: "check",
        src: ["autogroup:admin"],
        dst: ["tag:ark-vps"],
        users: ["autogroup:nonroot"],
        checkPeriod: "12h",
      },
    ]);
    expect(snippet.policy).not.toHaveProperty("ssh");
  });
});

describe("determinism and secrecy", () => {
  test("the same input gives byte-identical output, whatever the input order", () => {
    const first = generateTailnetAcl(sample).hujson;
    expect(generateTailnetAcl(sample).hujson).toBe(first);
    expect(generateTailnetAcl({ ...sample, routes: routes.toReversed() }).hujson).toBe(first);
    expect(
      generateTailnetAcl({ ...sample, routes: [routes[2], routes[0], routes[3], routes[1]] as AclRoute[] })
        .hujson,
    ).toBe(first);
  });

  test("the output carries no timestamp and does not depend on the clock", () => {
    const realNow = Date.now;
    const first = generateTailnetAcl(sample).hujson;
    try {
      Date.now = () => realNow() + 365 * 24 * 60 * 60 * 1000;
      expect(generateTailnetAcl(sample).hujson).toBe(first);
    } finally {
      Date.now = realNow;
    }
    expect(first).not.toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/);
    expect(first).not.toMatch(/generated \d/i);
  });

  test("secret-bearing fields on the input never reach the output", () => {
    const secretValues = ["sec_credential_123", "tskey-auth-kSECRET", "hunter2-password", "s3cr3t"];
    const withSecrets = routes.map((route) => ({
      ...route,
      clientCaId: "pca_private",
      keySecretId: secretValues[0],
      authKey: secretValues[1],
    }));
    const row = {
      id: "bkt_home",
      name: "home",
      restUrl: `http://ark:${secretValues[3]}@backup-home.tail1234.ts.net:8000/ark?token=${secretValues[2]}`,
      targetNodeStableId: "nBAK345CNTRL",
      credentialSecretId: secretValues[0],
    };
    const resolved = tailnetBackupTarget(row, [
      { stableId: "nBAK345CNTRL", dnsName: "backup-home.tail1234.ts.net.", ipv4: "100.66.2.9", ipv6: null },
    ]);
    expect(resolved).toEqual({ ...backup, addresses: [backup.ip] });
    const snippet = generateTailnetAcl({
      ...sample,
      routes: withSecrets,
      backupTargets: [resolved as AclBackupTarget],
    });
    const everything = JSON.stringify(snippet);
    for (const value of [...secretValues, "pca_private", "ark:", "/ark", "token="]) {
      expect(everything).not.toContain(value);
    }
    expect(snippet.hujson).toBe(generateTailnetAcl(sample).hujson);
  });
});

describe("grant safety", () => {
  const hostile: AclRoute[] = [
    ...routes,
    // A route whose "target" claims to be an Ark tag, a public IP, or a backup target.
    { ...(routes[0] as AclRoute), id: "rt_tag", targetIp: "tag:ark-vps" },
    { ...(routes[0] as AclRoute), id: "rt_public", targetIp: "8.8.8.8" },
    { ...(routes[0] as AclRoute), id: "rt_docker", targetIp: "172.17.0.1" },
    { ...(routes[0] as AclRoute), id: "rt_quad100", targetIp: "100.100.100.100" },
    { ...(routes[0] as AclRoute), id: "rt_backup", targetIp: "100.66.2.9", targetPort: 8000 },
    { ...(routes[0] as AclRoute), id: "rt_disabled", status: "disabled", targetIp: "100.70.1.1" },
    { ...(routes[0] as AclRoute), id: "tag:ark-edge", targetIp: "100.70.1.2" },
    {
      ...(routes[0] as AclRoute),
      id: "rt_inject",
      hostname: 'x.example.com\n"grants": [',
      targetIp: "100.70.1.3",
    },
    { ...(routes[0] as AclRoute), id: "rt_named", targetName: "tag:ark-vps", targetIp: "100.70.1.4" },
  ];

  test("no grant ever has an Ark tag (or anything but a declared host alias) as dst", () => {
    const snippet = generateTailnetAcl({ ...sample, routes: hostile });
    for (const grant of snippet.policy.grants ?? []) {
      for (const dst of grant.dst) {
        expect(ARK_TAGS as readonly string[]).not.toContain(dst);
        expect(dst.startsWith("tag:")).toBe(false);
        expect(snippet.policy.hosts).toHaveProperty(dst);
      }
    }
    expect(snippet.omitted.map((item) => [item.id, item.reason])).toEqual([
      ["rt_backup", "target is a backup target; the edge must never reach it"],
      ["rt_disabled", "route is disabled"],
      ["rt_docker", "target is not a routable Tailscale address"],
      ["rt_inject", "invalid public hostname"],
      ["rt_public", "target is not a routable Tailscale address"],
      ["rt_quad100", "target is not a routable Tailscale address"],
      ["rt_tag", "target is not a routable Tailscale address"],
      ["tag:ark-edge", "invalid route ID"],
    ]);
    // The injected hostname cannot open a new line or section.
    expect(snippet.hujson.split("\n").filter((line) => line.includes('"grants"'))).toHaveLength(1);
    expect(parseHujson(snippet.hujson)).toEqual(snippet.policy);
    // A route named after an Ark tag only gets a sanitised alias.
    expect(snippet.policy.hosts).toHaveProperty("ark-rt-100-70-1-4", "100.70.1.4");
  });

  test("edge grants and backup grants never overlap, including through a shared machine", () => {
    const sharedMachine: AclRoute = {
      ...(routes[0] as AclRoute),
      id: "rt_nasweb",
      targetIp: "100.66.2.9",
      targetPort: 80,
    };
    const snippet = generateTailnetAcl({ ...sample, routes: [...hostile, sharedMachine] });
    const { edge, backup: backupPairs } = edgeAndBackupPairs(snippet.policy);
    expect(backupPairs).toEqual(["100.66.2.9|tcp:8000"]);
    expect(edge).toContain("100.66.2.9|tcp:80");
    expect(edge.filter((pair) => backupPairs.includes(pair))).toEqual([]);
    // Each identity is asserted to be denied the other's targets.
    expect(policyAllows(snippet.policy, ARK_EDGE_TAG, "ark-backup-home", 8000)).toBe(false);
    expect(policyAllows(snippet.policy, ARK_BACKUP_TAG, "ark-rt-home", 3000)).toBe(false);
    expect(evaluatePolicyTests(snippet.policy)).toEqual([]);
    const edgeTest = snippet.policy.tests?.find((item) => item.src === ARK_EDGE_TAG);
    const backupTest = snippet.policy.tests?.find((item) => item.src === ARK_BACKUP_TAG);
    expect(edgeTest?.deny).toContain("ark-backup-home:8000");
    expect(backupTest?.deny).toEqual(expect.arrayContaining(edgeTest?.accept ?? ["missing"]));
  });

  test("routes sharing a target share one host, with one grant per port", () => {
    const api: AclRoute = { ...(routes[0] as AclRoute), id: "rt_api", hostname: "api.example.com" };
    const admin: AclRoute = {
      ...(routes[0] as AclRoute),
      id: "rt_adm",
      hostname: "admin.example.com",
      targetPort: 8080,
    };
    const snippet = generateTailnetAcl({ routes: [routes[0] as AclRoute, api, admin] });
    expect(snippet.policy.hosts).toEqual({ "ark-rt-home": "100.101.102.103" });
    expect(snippet.policy.grants).toEqual([
      { src: ["tag:ark-edge"], dst: ["ark-rt-home"], ip: ["tcp:3000"] },
      { src: ["tag:ark-edge"], dst: ["ark-rt-home"], ip: ["tcp:8080"] },
    ]);
    expect(snippet.hujson).toContain(
      "    // api.example.com (http, 443)\n    // www.example.com (http, 443)\n",
    );
  });

  test("aliases stay unique when two machines share a short name, and IPv6 targets work", () => {
    const other: AclRoute = {
      ...(routes[0] as AclRoute),
      id: "rt_other",
      targetIp: "fd7a:115c:a1e0::1",
      targetNodeStableId: "nOTHER",
      targetName: "home.other-tailnet.ts.net",
    };
    const snippet = generateTailnetAcl({ routes: [routes[0] as AclRoute, other] });
    expect(snippet.policy.hosts).toEqual({
      "ark-rt-home": "100.101.102.103",
      "ark-rt-home-2": "fd7a:115c:a1e0::1",
    });
    expect(evaluatePolicyTests(snippet.policy)).toEqual([]);
  });

  test("deny probes avoid ports that are granted", () => {
    const snippet = generateTailnetAcl({ routes });
    const edgeTest = snippet.policy.tests?.find((item) => item.src === ARK_EDGE_TAG);
    expect(edgeTest?.deny).toContain("ark-rt-box:3389");
    expect(edgeTest?.deny).not.toContain("ark-rt-box:22");
  });

  test("tag owners and inbound test users are validated", () => {
    expect(() => generateTailnetAcl({ routes, tagOwners: ["tag:ark-edge"] })).toThrow(/cannot own/);
    expect(() => generateTailnetAcl({ routes, testUsers: ['x@y.com", "*'] })).toThrow(/not a tailnet user/);
    const snippet = generateTailnetAcl({
      routes,
      testUsers: ["owner@example.com"],
      tagOwners: ["group:ark-admins"],
    });
    expect(snippet.policy.tests?.at(-1)).toEqual({ src: "owner@example.com", deny: ["tag:ark-edge:443"] });
    expect(snippet.policy.tagOwners?.["tag:ark-edge"]).toEqual(["group:ark-admins"]);
  });

  test("an empty route set still asserts the Ark tags are isolated", () => {
    const snippet = generateTailnetAcl({ routes: [] });
    expect(snippet.policy.grants).toEqual([]);
    expect(snippet.policy.hosts).toEqual({});
    expect(snippet.policy.tests?.map((item) => [item.src, item.proto])).toEqual([
      [ARK_EDGE_TAG, "tcp"],
      [ARK_EDGE_TAG, "udp"],
      [ARK_BACKUP_TAG, "tcp"],
      [ARK_BACKUP_TAG, "udp"],
    ]);
    expect(parseHujson(snippet.hujson)).toEqual(snippet.policy);
  });
});

describe("the tests block rejects broad rules (local evaluator)", () => {
  const snippet = generateTailnetAcl(sample);

  test("the generated policy passes its own tests", () => {
    expect(evaluatePolicyTests(snippet.policy)).toEqual([]);
  });

  test('a broad {"src":["*"],"dst":["*"],"ip":["*"]} grant fails the deny assertions', () => {
    const failures = evaluatePolicyTests({
      ...snippet.policy,
      grants: [...(snippet.policy.grants ?? []), BROAD_GRANT],
    });
    expect(failures.length).toBeGreaterThan(0);
    expect(failures.every((item) => item.expected === "deny")).toBe(true);
    // Both identities fail: the edge can reach SSH on its targets, and the backup node the routes.
    expect(failures).toEqual(
      expect.arrayContaining([
        { src: ARK_EDGE_TAG, destination: "ark-rt-home:22", expected: "deny" },
        { src: ARK_EDGE_TAG, destination: "ark-backup-home:8000", expected: "deny" },
        { src: ARK_EDGE_TAG, destination: "tag:ark-vps:22", expected: "deny" },
        { src: ARK_BACKUP_TAG, destination: "ark-rt-home:3000", expected: "deny" },
      ]),
    );
  });

  test("other broad shapes fail too: legacy ACLs, autogroup:tagged, a CIDR and a port range", () => {
    const broad: TailnetPolicy[] = [
      { acls: [{ action: "accept", src: ["*"], dst: ["*:*"] }] },
      { grants: [{ src: ["autogroup:tagged"], dst: ["*"], ip: ["*"] }] },
      { grants: [{ src: ["tag:ark-edge"], dst: ["100.64.0.0/10"], ip: ["tcp:1-65535"] }] },
      { grants: [{ src: ["tag:ark-backup"], dst: ["*"], ip: ["tcp:*"] }] },
      { acls: [{ action: "accept", src: ["tag:ark-edge"], dst: ["ark-rt-home:22,80"] }] },
    ];
    for (const extra of broad) {
      const merged: TailnetPolicy = {
        ...snippet.policy,
        grants: [...(snippet.policy.grants ?? []), ...(extra.grants ?? [])],
        acls: extra.acls,
      };
      expect(evaluatePolicyTests(merged).length).toBeGreaterThan(0);
    }
  });

  test("unrelated narrow rules for people do not fail the tests", () => {
    const merged: TailnetPolicy = {
      ...snippet.policy,
      grants: [
        ...(snippet.policy.grants ?? []),
        { src: ["autogroup:member"], dst: ["autogroup:self"], ip: ["*"] },
        { src: ["owner@example.com"], dst: ["tag:ark-vps"], ip: ["tcp:22"] },
      ],
    };
    expect(evaluatePolicyTests(merged)).toEqual([]);
  });

  test("the evaluator honours protocols and port ranges", () => {
    const policy: TailnetPolicy = {
      hosts: { box: "100.70.0.9" },
      grants: [
        { src: ["tag:a"], dst: ["box"], ip: ["udp:53"] },
        { src: ["tag:a"], dst: ["100.70.0.0/24"], ip: ["8000-8010"] },
      ],
    };
    expect(policyAllows(policy, "tag:a", "box", 53)).toBe(true);
    expect(policyAllows(policy, "tag:a", "box", 53, "tcp")).toBe(false);
    expect(policyAllows(policy, "tag:a", "box", 8005, "tcp")).toBe(true);
    expect(policyAllows(policy, "tag:a", "box", 8011)).toBe(false);
    expect(policyAllows(policy, "tag:b", "box", 8005)).toBe(false);
  });
});

describe("tailnetBackupTarget", () => {
  const nodes = [
    { stableId: "nBAK", dnsName: "backup-home.tail1234.ts.net.", ipv4: "100.66.2.9", ipv6: null },
  ];

  test("prefers the pinned StableID and derives the port from the URL", () => {
    expect(
      tailnetBackupTarget(
        {
          id: "b1",
          name: "home",
          restUrl: "https://backup-home.tail1234.ts.net/ark",
          targetNodeStableId: "nBAK",
        },
        nodes,
      ),
    ).toMatchObject({ ip: "100.66.2.9", port: 443, stableId: "nBAK" });
  });

  test("resolves by MagicDNS name or Tailscale IP literal when nothing is pinned", () => {
    expect(
      tailnetBackupTarget(
        {
          id: "b1",
          name: "home",
          restUrl: "http://backup-home.tail1234.ts.net/ark",
          targetNodeStableId: null,
        },
        nodes,
      ),
    ).toMatchObject({ ip: "100.66.2.9", port: 80 });
    expect(
      tailnetBackupTarget(
        { id: "b1", name: "home", restUrl: "http://100.66.2.10:8000/", targetNodeStableId: null },
        [],
      ),
    ).toMatchObject({ ip: "100.66.2.10", port: 8000, targetName: null });
  });

  test("an unobserved pinned node, a public address or a bad URL is omitted, not guessed", () => {
    for (const row of [
      { restUrl: "http://100.66.2.10:8000/", targetNodeStableId: "nMISSING" },
      { restUrl: "http://203.0.113.5:8000/", targetNodeStableId: null },
      { restUrl: "ftp://backup-home.tail1234.ts.net/", targetNodeStableId: null },
      { restUrl: null, targetNodeStableId: null },
    ]) {
      expect(tailnetBackupTarget({ id: "b1", name: "home", ...row }, nodes)).toMatchObject({
        kind: "backup",
      });
    }
  });
});

describe("diffLines", () => {
  test("marks added and removed lines against the previous snippet", () => {
    expect(diffLines("a\nb\nc", "a\nc\nd")).toEqual([
      { op: "same", line: "a" },
      { op: "remove", line: "b" },
      { op: "same", line: "c" },
      { op: "add", line: "d" },
    ]);
    expect(diffLines("same", "same")).toEqual([{ op: "same", line: "same" }]);
  });

  test("adding a route shows only the new host, grant and test lines", () => {
    const before = generateTailnetAcl({ ...sample, routes: routes.slice(0, 3) }).hujson;
    const after = generateTailnetAcl(sample).hujson;
    const changed = diffLines(before, after).filter((line) => line.op !== "same");
    expect(
      changed.some((line) => line.op === "add" && line.line.includes('"ark-rt-box": "100.77.9.3"')),
    ).toBe(true);
    expect(
      changed.filter((line) => line.op === "remove").every((line) => !line.line.includes('"hosts"')),
    ).toBe(true);
  });
});

describe("caller omissions", () => {
  test("unresolved entries from the caller are listed as not granted, sanitised", () => {
    const snippet = generateTailnetAcl({
      routes: [],
      omitted: [{ kind: "backup", id: "bkt_x", reason: "backup target has not been observed\n{" }],
    });
    expect(snippet.omitted).toEqual([
      { kind: "backup", id: "bkt_x", reason: "backup target has not been observed?{" },
    ]);
    expect(snippet.hujson).toContain(
      "// Not granted: backup bkt_x: backup target has not been observed?{.\n{",
    );
    expect(parseHujson(snippet.hujson)).toEqual(snippet.policy);
  });
});

describe("backup identity and dual-stack regressions", () => {
  const node = {
    stableId: "nBAK",
    dnsName: "backup.tail1234.ts.net.",
    ipv4: "100.66.2.9",
    ipv6: "fd7a:115c:a1e0::9",
  };
  const row = {
    id: "b1",
    name: "backup",
    restUrl: "http://backup.tail1234.ts.net:8000/ark",
    targetNodeStableId: "nBAK",
  };
  test("a missing pinned identity never falls back to a same-name replacement", () => {
    const result = tailnetBackupTarget({ ...row, targetNodeStableId: "nMISSING" }, [node]);
    expect(result).toMatchObject({ kind: "backup", reason: "pinned backup node has not been observed" });
    expect(
      generateTailnetAcl({ routes: [], omitted: [result as import("./tailnet-acl.ts").AclOmission] }).policy
        .grants,
    ).toEqual([]);
  });
  test("duplicate observations resolve once; distinct matching identities are ambiguous", () => {
    expect(tailnetBackupTarget({ ...row, targetNodeStableId: null }, [node, { ...node }])).toMatchObject({
      stableId: "nBAK",
      ip: node.ipv4,
    });
    expect(
      tailnetBackupTarget({ ...row, targetNodeStableId: null }, [node, { ...node, stableId: "nOTHER" }]),
    ).toMatchObject({ kind: "backup", reason: expect.stringContaining("ambiguous") });
  });
  test("literal URLs preserve their family and reject an address outside the pin", () => {
    for (const ip of [node.ipv4, node.ipv6]) {
      const host = ip.includes(":") ? `[${ip}]` : ip;
      expect(tailnetBackupTarget({ ...row, restUrl: `http://${host}:8000/ark` }, [node])).toMatchObject({
        ip,
        stableId: node.stableId,
      });
    }
    for (const host of ["100.66.2.10", "[fd7a:115c:a1e0::10]", "other.tail1234.ts.net"]) {
      expect(tailnetBackupTarget({ ...row, restUrl: `http://${host}:8000/` }, [node])).toMatchObject({
        kind: "backup",
      });
    }
  });
  test("the first observation wins when sources differ", () => {
    expect(tailnetBackupTarget(row, [node, { ...node, ipv4: "100.66.2.10" }])).toMatchObject({
      ip: node.ipv4,
      addresses: expect.arrayContaining([node.ipv4, node.ipv6, "100.66.2.10"]),
    });
  });
  test("global and per-route reservations cover both families, pinned or discovered", () => {
    for (const pinned of [true, false]) {
      for (const ip of [node.ipv4, node.ipv6]) {
        const resolved = tailnetBackupTarget(
          {
            ...row,
            targetNodeStableId: pinned ? node.stableId : null,
            restUrl: `http://${ip.includes(":") ? `[${ip}]` : ip}:8000/`,
          },
          [node],
        );
        expect(resolved).not.toHaveProperty("reason");
        const target = resolved as AclBackupTarget;
        const route = {
          ...routes[0]!,
          targetNodeStableId: node.stableId,
          targetIp: ip === node.ipv4 ? node.ipv6 : node.ipv4,
          targetPort: 8000,
        };
        for (const scope of [
          { backupTargets: [target] },
          { reservedTargets: [target], assertionRoutes: [route] },
        ]) {
          const generated = generateTailnetAcl({ routes: [route], ...scope });
          expect(generated.omitted).toContainEqual(expect.objectContaining({ kind: "route", id: route.id }));
          expect((generated.policy.grants ?? []).filter((grant) => grant.src.includes(ARK_EDGE_TAG))).toEqual(
            [],
          );
          expect(evaluatePolicyTests(generated.policy)).toEqual([]);
        }
      }
    }
  });
});

describe("policy isolation and composable assertions", () => {
  const route = routes[0]!;
  test("narrow TCP leaks, UDP on allowed ports and known non-target access fail native tests", () => {
    const generated = generateTailnetAcl({
      routes: [route],
      knownAddresses: ["100.70.0.9", "fd7a:115c:a1e0::99"],
    });
    for (const [dst, ip] of [
      ["ark-rt-home", "tcp:80"],
      ["tag:ark-vps", "tcp:80"],
      ["ark-rt-home", "udp:3000"],
      ["100.70.0.9", "tcp:80"],
      ["fd7a:115c:a1e0::99", "udp:22"],
    ]) {
      expect(
        evaluatePolicyTests({
          ...generated.policy,
          grants: [...generated.policy.grants!, { src: [ARK_EDGE_TAG], dst: [dst!], ip: [ip!] }],
        }).length,
      ).toBeGreaterThan(0);
    }
    expect(parseHujson(generated.hujson)).toEqual(generated.policy);
  });
  test("the local audit covers every TCP/UDP range boundary, even unprobed ports", () => {
    const expected = generateTailnetAcl({ routes: [route], knownAddresses: ["100.70.0.9"] }).policy;
    expect(auditTailnetPolicy(expected, expected)).toEqual([]);
    for (const extra of [
      { grants: [{ src: [ARK_EDGE_TAG], dst: ["ark-rt-home"], ip: ["tcp:12345"] }] },
      { grants: [{ src: [ARK_EDGE_TAG], dst: ["100.70.0.9"], ip: ["udp:49200-49300"] }] },
      { acls: [{ action: "accept", src: [ARK_BACKUP_TAG], dst: ["100.70.0.9:49201-49301"], proto: "tcp" }] },
    ]) {
      expect(
        auditTailnetPolicy(expected, {
          ...expected,
          grants: [...expected.grants!, ...(extra.grants ?? [])],
          acls: extra.acls,
        }).length,
      ).toBeGreaterThan(0);
    }
  });
  test("per-route assertions compose with the global policy and retain unauthorized denies", () => {
    const other = { ...route, id: "rt_ssh", targetPort: 22 };
    const all = [route, other];
    const global = generateTailnetAcl({ routes: all }).policy;
    for (const selected of all) {
      const scoped = generateTailnetAcl({ routes: [selected], assertionRoutes: all }).policy;
      expect(evaluatePolicyTests(scoped)).toEqual([]);
      const merged = { ...global, tests: [...global.tests!, ...scoped.tests!] };
      expect(evaluatePolicyTests(merged)).toEqual([]);
      expect(
        evaluatePolicyTests({
          ...merged,
          grants: [...merged.grants!, { src: [ARK_EDGE_TAG], dst: ["ark-rt-home"], ip: ["tcp:80"] }],
        }).length,
      ).toBeGreaterThan(0);
    }
  });
  test("per-route aliases remain stable when machines share a short name", () => {
    const other = { ...route, id: "rt_other", targetIp: "100.70.0.9", targetNodeStableId: "nOTHER" };
    const global = generateTailnetAcl({ routes: [route, other] }).policy;
    const scoped = generateTailnetAcl({ routes: [other], assertionRoutes: [route, other] }).policy;
    expect(scoped.hosts).toEqual(global.hosts);
    expect(evaluatePolicyTests({ ...global, tests: [...global.tests!, ...scoped.tests!] })).toEqual([]);
    expect(scoped.grants).toEqual(
      global.grants?.filter((grant) => global.hosts?.[grant.dst[0]!] === other.targetIp),
    );
  });
});
