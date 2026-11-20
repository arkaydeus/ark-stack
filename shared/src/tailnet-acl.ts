// Tailscale policy (HuJSON) snippet generator, docs/design/front-door.md §3.7 (FD-07).
//
// The running platform never holds a key that can write the tailnet policy (only the guided installer,
// scripts/host-setup/tailscale-api.ts, can add the tag owners and the owner SSH rule, with a credential
// the owner supplies for the install). Instead it generates the exact snippet the owner pastes: one
// grant per (target host, port, protocol) for the edge node, one per backup target for the backup node,
// and a `tests` block whose deny assertions make Tailscale reject the whole policy when a sampled
// destination is reachable. These tests are not an exhaustive audit.
//
// The generator is pure and deterministic: the same routes give byte-identical output whatever
// their order, there are no timestamps, and only public routing facts (hostnames, ports, Tailscale
// IPs, StableIDs) are ever rendered. Invalid or conflicting entries are omitted, never widened.

import { prefixMatch } from "./cidr.ts";
import { ValidationError } from "./errors.ts";
import { checkTailnetAddress, FORBIDDEN_TARGET_TAGS, parseIpLiteral } from "./tailnet.ts";

export const ARK_EDGE_TAG = "tag:ark-edge";
export const ARK_BACKUP_TAG = "tag:ark-backup";
export const ARK_ADMIN_TAG = "tag:ark-stack-admin";
export const ARK_VPS_TAG = "tag:ark-vps";
/** Every Ark tag, in the order the snippet declares them. None is ever a generated grant `dst`. */
export const ARK_TAGS = [ARK_EDGE_TAG, ARK_BACKUP_TAG, ARK_ADMIN_TAG, ARK_VPS_TAG] as const;

/** The broad rule a pre-existing default policy often carries; the generated tests reject it. */
export const BROAD_GRANT: TailnetGrant = { src: ["*"], dst: ["*"], ip: ["*"] };

/** Common ports sampled by native assertions, in addition to all configured service ports. */
const PROBE_PORTS = [22, 80, 443, 3389, 5900, 445, 23, 2375, 8080, 8443, 65535];
/** Ark-tag destinations the edge and backup identities must never reach. */
const TAG_PROBES: Record<string, number> = {
  [ARK_EDGE_TAG]: 443,
  [ARK_BACKUP_TAG]: 22,
  [ARK_ADMIN_TAG]: 443,
  [ARK_VPS_TAG]: 22,
};

export type AclRouteKind = "http" | "tls" | "postgres" | "tcp";

/** The public routing facts of one `front_routes` row. Nothing secret belongs here. */
export type AclRoute = {
  id: string;
  kind: AclRouteKind;
  /** Public hostname, for the comment only. */
  hostname: string;
  listenPort: number;
  compatPort?: number | null;
  tlsMode?: string | null;
  /** The pinned Tailscale address; the only address ever granted. */
  targetIp: string;
  targetPort: number;
  targetNodeStableId: string;
  /** MagicDNS name of the pinned node, when known: names the host alias and the comment. */
  targetName?: string | null;
  /** Routes the owner explicitly disabled get no grant. */
  status?: string | null;
};

/** A tailnet backup target (`backup_targets.kind = 'tailnet_rest'`), already resolved to an IP. */
export type AclBackupTarget = {
  id: string;
  name: string;
  ip: string;
  port: number;
  stableId?: string | null;
  /** All observed addresses of this identity, reserved across address families. */
  addresses?: string[];
  targetName?: string | null;
};

export type AclSnippetInput = {
  routes: AclRoute[];
  /** Complete route inventory used to make per-route assertions composable. */
  assertionRoutes?: AclRoute[];
  /** Observed addresses, including nodes without a route. Never granted by this field. */
  knownAddresses?: string[];
  /** Backup targets granted to `tag:ark-backup` in this snippet. */
  backupTargets?: AclBackupTarget[];
  /**
   * Backup targets that are not granted here (a per-route snippet) but still stay off-limits to
   * the edge: a route to one of them is omitted.
   */
  reservedTargets?: AclBackupTarget[];
  /** Tailnet name such as `tail1234.ts.net`, for the header only. */
  tailnet?: string | null;
  /** Who may apply the Ark tags. Defaults to `autogroup:admin`. */
  tagOwners?: string[];
  /** Optional inbound assertions: these users must not reach the edge node (§3.7). */
  testUsers?: string[];
  /** Entries the caller already could not resolve (an unobserved backup target), listed as not granted. */
  omitted?: AclOmission[];
  /** What the snippet covers, for the header only. */
  scope?: { routeId: string; hostname: string } | null;
};

export type TailnetGrant = { src: string[]; dst: string[]; ip: string[] };
export type TailnetAcl = { action: string; src: string[]; dst: string[]; proto?: string };
export type TailnetTest = { src: string; proto?: string; accept?: string[]; deny?: string[] };
export type TailnetPolicy = {
  tagOwners?: Record<string, string[]>;
  hosts?: Record<string, string>;
  grants?: TailnetGrant[];
  acls?: TailnetAcl[];
  tests?: TailnetTest[];
  ssh?: unknown[];
};

export type AclOmission = { kind: "route" | "backup"; id: string; reason: string };

export type AclSnippet = {
  /** The HuJSON text to paste. */
  hujson: string;
  /** The same policy as plain JSON (comments dropped). */
  policy: TailnetPolicy;
  /** A separate, optional Tailscale SSH example for `tag:ark-vps` (check mode). */
  sshExample: string;
  /** Entries that got no grant, with the reason. */
  omitted: AclOmission[];
};

type HostEntry = {
  alias: string;
  ip: string;
  comments: string[];
  /** Ports granted to the snippet's source tag on this host, with the comment for each grant. */
  ports: Map<number, string[]>;
};

const ID = /^[A-Za-z0-9_-]{1,64}$/;
const HOSTNAME =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const STABLE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const TLS_MODES = new Set(["passthrough", "terminate", "terminate_mtls", "plain"]);
const KINDS = new Set<AclRouteKind>(["http", "tls", "postgres", "tcp"]);
const USER = /^[^\s@",:]+@[^\s@",:]+\.[^\s@",:]+$/;
const TAG_OWNER =
  /^(?:autogroup:admin|autogroup:owner|group:[a-z0-9_.@-]+|tag:[a-z0-9-]+|[^\s@",:]+@[^\s@",:]+)$/;

function isPort(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= 65535;
}

function tailnetIp(value: unknown) {
  if (typeof value !== "string") return null;
  const parsed = parseIpLiteral(value.trim());
  if (!parsed || checkTailnetAddress(parsed)) return null;
  return parsed.canonical;
}

function cleanName(value: unknown) {
  if (typeof value !== "string") return null;
  const name = value.trim().toLowerCase().replace(/\.$/, "");
  return HOSTNAME.test(name) ? name : null;
}

/** Comments are `//` lines, so only control characters could break out; drop anything unusual. */
function commentText(value: string) {
  return value.replace(/[^\x20-\x7e—]/g, "?");
}

function slug(value: string) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40)
    .replace(/-+$/g, "");
}

function compare(a: string, b: string) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function describeRoute(route: AclRoute) {
  const listener = route.compatPort ? `${route.listenPort}+${route.compatPort}` : `${route.listenPort}`;
  const mode = route.kind !== "tcp" && route.kind !== "http" && route.tlsMode ? `, ${route.tlsMode}` : "";
  return `${route.hostname} (${route.kind}, ${listener}${mode})`;
}

function pinned(stableId: string | null | undefined, name: string | null | undefined, ip: string) {
  const id = stableId && STABLE_ID.test(stableId) ? stableId : "unknown";
  return `pinned to StableID ${id} (${name ?? ip})`;
}

function routeProblem(route: AclRoute): string | null {
  if (!route || typeof route !== "object") return "invalid route";
  if (typeof route.id !== "string" || !ID.test(route.id)) return "invalid route ID";
  if (!KINDS.has(route.kind)) return "unknown route kind";
  if (cleanName(route.hostname) === null) return "invalid public hostname";
  if (!isPort(route.listenPort)) return "invalid listener port";
  if (route.compatPort !== null && route.compatPort !== undefined && !isPort(route.compatPort)) {
    return "invalid compat port";
  }
  if (route.tlsMode !== null && route.tlsMode !== undefined && !TLS_MODES.has(route.tlsMode)) {
    return "invalid TLS mode";
  }
  if (!isPort(route.targetPort)) return "invalid target port";
  if (!tailnetIp(route.targetIp)) return "target is not a routable Tailscale address";
  if (typeof route.targetNodeStableId !== "string" || !STABLE_ID.test(route.targetNodeStableId)) {
    return "target has no pinned StableID";
  }
  if (route.status === "disabled") return "route is disabled";
  return null;
}

function backupProblem(target: AclBackupTarget): string | null {
  if (!target || typeof target !== "object") return "invalid backup target";
  if (typeof target.id !== "string" || !ID.test(target.id)) return "invalid backup target ID";
  if (!isPort(target.port)) return "invalid backup target port";
  if (!tailnetIp(target.ip)) return "backup target is not a routable Tailscale address";
  return null;
}

/** Assigns unique aliases: the first claimant keeps the base name, later ones get `-2`, `-3`… */
function claim(taken: Set<string>, base: string) {
  let alias = base;
  for (let n = 2; taken.has(alias); n++) alias = `${base}-${n}`;
  taken.add(alias);
  return alias;
}

function ipSlug(ip: string) {
  return slug(ip.replaceAll(":", "-").replaceAll(".", "-")) || "host";
}

/**
 * Builds the policy snippet. Routes and backup targets are sorted internally, so input order never
 * changes the output.
 */
export function generateTailnetAcl(input: AclSnippetInput): AclSnippet {
  const omitted: AclOmission[] = (input.omitted ?? []).map((item) => ({
    kind: item.kind === "backup" ? "backup" : "route",
    id: ID.test(item.id) ? item.id : "?",
    reason: commentText(item.reason),
  }));
  const tagOwners = input.tagOwners?.length ? [...input.tagOwners] : ["autogroup:admin"];
  for (const owner of tagOwners) {
    if (!TAG_OWNER.test(owner) || (FORBIDDEN_TARGET_TAGS as string[]).includes(owner)) {
      throw new ValidationError(`${JSON.stringify(owner)} cannot own the Ark tags.`);
    }
  }
  const testUsers = [...new Set(input.testUsers ?? [])].toSorted(compare);
  for (const item of testUsers) {
    if (!USER.test(item)) throw new ValidationError(`${JSON.stringify(item)} is not a tailnet user login.`);
  }

  // Backup targets first: they are reserved, so an edge route can never share one.
  const backups = new Map<string, AclBackupTarget[]>(); // ip -> targets
  const reserved = new Set<string>();
  const reservedIdentities = new Set<string>();
  const reserve = (target: AclBackupTarget) => {
    if (!isPort(target.port)) return;
    for (const address of [target.ip, ...(target.addresses ?? [])]) {
      const ip = tailnetIp(address);
      if (ip) reserved.add(`${ip}|${target.port}`);
    }
    if (target.stableId && STABLE_ID.test(target.stableId)) {
      reservedIdentities.add(`${target.stableId}|${target.port}`);
    }
  };
  for (const target of [...(input.backupTargets ?? [])].toSorted((a, b) => compare(a.id, b.id))) {
    const problem = backupProblem(target);
    if (problem) {
      omitted.push({ kind: "backup", id: typeof target?.id === "string" ? target.id : "?", reason: problem });
      continue;
    }
    const ip = tailnetIp(target.ip) as string;
    reserve(target);
    backups.set(ip, [...(backups.get(ip) ?? []), target]);
  }
  for (const target of input.reservedTargets ?? []) {
    reserve(target);
  }

  const edge = new Map<string, AclRoute[]>(); // ip -> routes
  for (const route of [...input.routes].toSorted((a, b) => compare(String(a?.id), String(b?.id)))) {
    const problem = routeProblem(route);
    if (problem) {
      omitted.push({ kind: "route", id: typeof route?.id === "string" ? route.id : "?", reason: problem });
      continue;
    }
    const ip = tailnetIp(route.targetIp) as string;
    if (
      reserved.has(`${ip}|${route.targetPort}`) ||
      reservedIdentities.has(`${route.targetNodeStableId}|${route.targetPort}`)
    ) {
      omitted.push({
        kind: "route",
        id: route.id,
        reason: "target is a backup target; the edge must never reach it",
      });
      continue;
    }
    edge.set(ip, [...(edge.get(ip) ?? []), { ...route, hostname: cleanName(route.hostname) as string }]);
  }

  const taken = new Set<string>();
  const edgeHosts: HostEntry[] = [...edge.entries()]
    .map(([ip, routes]) => {
      const names = routes.map((route) => cleanName(route.targetName)).filter((name) => name !== null);
      const name = names.toSorted(compare)[0] ?? null;
      const label = (name && slug(name.split(".")[0] ?? "")) || ipSlug(ip);
      return { ip, routes, name, label };
    })
    .toSorted((a, b) => compare(a.label, b.label) || compare(a.ip, b.ip))
    .map(({ ip, routes, name, label }) => {
      const sorted = routes.toSorted(
        (a, b) => compare(a.hostname, b.hostname) || a.listenPort - b.listenPort || compare(a.id, b.id),
      );
      const ports = new Map<number, string[]>();
      for (const route of sorted)
        ports.set(route.targetPort, [...(ports.get(route.targetPort) ?? []), describeRoute(route)]);
      const stableIds = [...new Set(sorted.map((route) => route.targetNodeStableId))].toSorted(compare);
      return {
        alias: claim(taken, `ark-rt-${label}`),
        ip,
        comments:
          sorted.length === 1 && stableIds.length === 1
            ? [`${describeRoute(sorted[0] as AclRoute)} — ${pinned(stableIds[0], name, ip)}`]
            : [
                ...sorted.map((route) => describeRoute(route)),
                ...stableIds.map((id) => `— ${pinned(id, name, ip)}`),
              ],
        ports: new Map([...ports.entries()].toSorted(([a], [b]) => a - b)),
      };
    });

  const backupHosts: HostEntry[] = [...backups.entries()]
    .map(([ip, targets]) => {
      const sorted = targets.toSorted((a, b) => compare(a.id, b.id));
      const first = sorted[0] as AclBackupTarget;
      const label =
        slug(first.name ?? "") || slug(cleanName(first.targetName)?.split(".")[0] ?? "") || ipSlug(ip);
      return { ip, targets: sorted, label };
    })
    .toSorted((a, b) => compare(a.label, b.label) || compare(a.ip, b.ip))
    .map(({ ip, targets, label }) => {
      const ports = new Map<number, string[]>();
      for (const target of targets) {
        ports.set(target.port, [
          ...(ports.get(target.port) ?? []),
          `backup target ${commentText(target.name)} (tailnet rest-server)`,
        ]);
      }
      const comments = targets.map(
        (target) =>
          `backup target ${commentText(target.name)} (tailnet rest-server, ${target.port}) — ${pinned(target.stableId, cleanName(target.targetName), ip)}`,
      );
      return {
        alias: claim(taken, `ark-backup-${label}`),
        ip,
        comments: [...new Set(comments)],
        ports: new Map([...ports.entries()].toSorted(([a], [b]) => a - b)),
      };
    });

  // ---- Policy object ----
  const owners: Record<string, string[]> = {};
  for (const tag of ARK_TAGS) owners[tag] = [...tagOwners];
  const hosts: Record<string, string> = {};
  for (const host of [...edgeHosts, ...backupHosts]) hosts[host.alias] = host.ip;

  type GrantLine = { grant: TailnetGrant; comments: string[] };
  const grantLines: GrantLine[] = [];
  const grantsFor = (tag: string, entries: HostEntry[]) => {
    for (const host of entries) {
      for (const [port, comments] of host.ports) {
        grantLines.push({ grant: { src: [tag], dst: [host.alias], ip: [`tcp:${port}`] }, comments });
      }
    }
  };
  grantsFor(ARK_EDGE_TAG, edgeHosts);
  grantsFor(ARK_BACKUP_TAG, backupHosts);

  const edgeAccept = granted(edgeHosts);
  const backupAccept = granted(backupHosts);
  const knownAddresses = [
    ...new Set((input.knownAddresses ?? []).map(tailnetIp).filter((ip): ip is string => ip !== null)),
  ].toSorted(compare);
  const destinations = [
    ...new Set([...Object.keys(hosts), ...knownAddresses.filter((ip) => !Object.values(hosts).includes(ip))]),
  ];
  const probePorts = [
    ...new Set([
      ...PROBE_PORTS,
      ...edgeHosts.flatMap((entry) => [...entry.ports.keys()]),
      ...backupHosts.flatMap((entry) => [...entry.ports.keys()]),
    ]),
  ];
  const tests: TailnetTest[] = [];
  for (const [src, accept] of [
    [ARK_EDGE_TAG, edgeAccept],
    [ARK_BACKUP_TAG, backupAccept],
  ] as const) {
    const allowed = (host: string, port: number) =>
      grantLines.some(
        ({ grant }) =>
          grant.src.includes(src) &&
          grant.dst.some((alias) => (hosts[alias] ?? alias) === (hosts[host] ?? host)) &&
          grant.ip.includes(`tcp:${port}`),
      );
    const tcpDeny = destinations.flatMap((host) => {
      return probePorts.filter((port) => !allowed(host, port)).map((port) => testDestination(host, port));
    });
    tests.push({ ...withLists(src, [...accept], [...tcpDeny, ...tagProbes(src)]), proto: "tcp" });
    tests.push({
      src,
      proto: "udp",
      deny: [
        ...new Set([
          ...destinations.flatMap((host) => probePorts.map((port) => testDestination(host, port))),
          ...tagProbes(src),
        ]),
      ],
    });
  }
  tests.push(
    ...testUsers.map((user) => ({ src: user, deny: [`${ARK_EDGE_TAG}:${TAG_PROBES[ARK_EDGE_TAG]}`] })),
  );

  // Build assertions against all legitimate grants, while emitting only the selected grants.
  // Full-inventory aliases also prevent same-short-name collisions when snippets are merged.
  if (input.assertionRoutes) {
    const complete = generateTailnetAcl({
      ...input,
      routes: input.assertionRoutes,
      assertionRoutes: undefined,
      backupTargets: [...(input.backupTargets ?? []), ...(input.reservedTargets ?? [])],
      reservedTargets: undefined,
      scope: null,
    });
    const completeHosts = complete.policy.hosts ?? {};
    for (const line of grantLines) {
      line.grant.dst = line.grant.dst.map(
        (alias) =>
          Object.keys(completeHosts).find(
            (key) =>
              key.startsWith(alias.startsWith("ark-backup-") ? "ark-backup-" : "ark-rt-") &&
              completeHosts[key] === hosts[alias],
          ) ?? alias,
      );
    }
    for (const key of Object.keys(hosts)) delete hosts[key];
    Object.assign(hosts, completeHosts);
    tests.splice(
      0,
      tests.length,
      ...(complete.policy.tests ?? []).map((test) => ({
        ...test,
        accept: test.accept?.filter((entry) => {
          const split = entry.lastIndexOf(":");
          return policyAllows(
            { hosts, grants: grantLines.map((line) => line.grant) },
            test.src,
            entry.slice(0, split),
            Number(entry.slice(split + 1)),
            test.proto,
          );
        }),
      })),
    );
  }

  const policy: TailnetPolicy = {
    tagOwners: owners,
    hosts,
    grants: grantLines.map((line) => line.grant),
    tests,
  };

  // ---- HuJSON text ----
  const out: string[] = [];
  const scope = input.scope
    ? `route ${commentText(input.scope.routeId)} (${cleanName(input.scope.hostname) ?? "unknown host"})`
    : "all front-door routes and tailnet backup targets";
  const tailnet = cleanName(input.tailnet);
  out.push(
    `// Ark Stack front door — Tailscale policy snippet for ${scope}${tailnet ? ` on tailnet ${tailnet}` : ""}.`,
  );
  out.push(
    "// Merge each section into your tailnet policy file. Ark does not hold any Tailscale credential.",
  );
  out.push(
    "// Tests sample TCP/UDP ports on known nodes and Ark tags; they do not prove tailnet-wide isolation.",
  );
  for (const item of omitted.toSorted((a, b) => compare(a.kind, b.kind) || compare(a.id, b.id))) {
    out.push(`// Not granted: ${item.kind} ${commentText(item.id)}: ${item.reason}.`);
  }
  out.push("{");
  out.push('  "tagOwners": {');
  for (const [tag, owner] of Object.entries(owners)) out.push(`    ${json(tag)}: ${inline(owner)},`);
  out.push("  },");
  out.push(Object.keys(hosts).length ? '  "hosts": {' : '  "hosts": {},');
  for (const [alias, ip] of Object.entries(hosts)) {
    const host = (alias.startsWith("ark-backup-") ? backupHosts : edgeHosts).find((item) => item.ip === ip);
    for (const comment of host?.comments ?? []) out.push(`    // ${commentText(comment)}`);
    out.push(`    ${json(alias)}: ${json(ip)},`);
  }
  if (Object.keys(hosts).length) out.push("  },");
  out.push(grantLines.length ? '  "grants": [' : '  "grants": [],');
  for (const line of grantLines) {
    for (const comment of line.comments) out.push(`    // ${commentText(comment)}`);
    const { src, dst, ip } = line.grant;
    out.push(`    { "src": ${inline(src)}, "dst": ${inline(dst)}, "ip": ${inline(ip)} },`);
  }
  if (grantLines.length) out.push("  ],");
  out.push('  "tests": [');
  for (const test of tests) {
    out.push("    {");
    out.push(`      "src": ${json(test.src)},`);
    if (test.proto) out.push(`      "proto": ${json(test.proto)},`);
    if (test.accept) out.push(...arrayLines("accept", test.accept));
    if (test.deny) out.push(...arrayLines("deny", test.deny));
    out.push("    },");
  }
  out.push("  ],");
  out.push("}");

  return {
    hujson: `${out.join("\n")}\n`,
    policy,
    sshExample: sshPolicyExample({ admin: tagOwners[0] as string }),
    omitted: omitted.toSorted((a, b) => compare(a.kind, b.kind) || compare(a.id, b.id)),
  };
}

/** `alias:port` for every port granted on these hosts. */
function granted(entries: HostEntry[]) {
  return entries.flatMap((host) => [...host.ports.keys()].map((port) => `${host.alias}:${port}`));
}

function testDestination(host: string, port: number) {
  return `${host.includes(":") && !host.startsWith("tag:") ? `[${host}]` : host}:${port}`;
}

/** The other Ark tags, which `self` must never reach. */
function tagProbes(self: string) {
  return ARK_TAGS.filter((tag) => tag !== self).flatMap((tag) =>
    [...new Set([TAG_PROBES[tag], ...PROBE_PORTS])].map((port) => `${tag}:${port}`),
  );
}

function withLists(src: string, accept: string[], deny: string[]): TailnetTest {
  const test: TailnetTest = { src };
  if (accept.length) test.accept = [...new Set(accept)];
  if (deny.length) test.deny = [...new Set(deny)];
  return test;
}

function json(value: string) {
  return JSON.stringify(value);
}

function inline(values: string[]) {
  return `[${values.map(json).join(", ")}]`;
}

function arrayLines(key: string, values: string[]) {
  const single = `      ${json(key)}: ${inline(values)},`;
  if (single.length <= 100) return [single];
  return [`      ${json(key)}: [`, ...values.map((value) => `        ${json(value)},`), "      ],"];
}

/**
 * An optional Tailscale SSH policy for the Ark VPS (§3.7). It is kept separate from the generated
 * snippet because it grants a user identity access to `tag:ark-vps`, which the front-door snippet
 * never does. `check` mode makes the user re-authenticate before a session.
 */
export function sshPolicyExample(input: { admin?: string } = {}) {
  const admin =
    input.admin && TAG_OWNER.test(input.admin) && !input.admin.startsWith("tag:")
      ? input.admin
      : "autogroup:admin";
  return [
    "// Optional: Tailscale SSH to the Ark VPS. Not part of the generated front-door snippet.",
    '// "check" re-authenticates the user with the identity provider before each session.',
    "{",
    '  "grants": [',
    `    { "src": [${json(admin)}], "dst": [${json(ARK_VPS_TAG)}], "ip": ["tcp:22"] },`,
    "  ],",
    '  "ssh": [',
    "    {",
    '      "action": "check",',
    `      "src": [${json(admin)}],`,
    `      "dst": [${json(ARK_VPS_TAG)}],`,
    '      "users": ["autogroup:nonroot"],',
    '      "checkPeriod": "12h",',
    "    },",
    "  ],",
    "}",
    "",
  ].join("\n");
}

/** Resolves a `tailnet_rest` backup target row to the facts the snippet needs, never its URL. */
export function tailnetBackupTarget(
  row: { id: string; name: string; restUrl: string | null; targetNodeStableId: string | null },
  nodes: Array<{ stableId: string; dnsName: string; ipv4: string | null; ipv6: string | null }>,
): AclBackupTarget | AclOmission {
  let url: URL;
  try {
    url = new URL(row.restUrl ?? "");
  } catch {
    return { kind: "backup", id: row.id, reason: "backup target has no valid REST URL" };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { kind: "backup", id: row.id, reason: "backup target URL is not http or https" };
  }
  const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
  const host = url.hostname
    .replace(/^\[|\]$/g, "")
    .toLowerCase()
    .replace(/\.$/, "");
  // Observers are ordered by the caller (backup first). Deduplicate identities, not rows.
  const unique = [...new Map(nodes.toReversed().map((node) => [node.stableId, node])).values()];
  const literal = parseIpLiteral(host);
  if (literal && !tailnetIp(host))
    return { kind: "backup", id: row.id, reason: "backup URL is not a Tailscale address" };
  const matches = unique.filter((node) =>
    literal
      ? [node.ipv4, node.ipv6].some((ip) => tailnetIp(ip) === tailnetIp(host))
      : node.dnsName.toLowerCase().replace(/\.$/, "") === host,
  );
  const node = row.targetNodeStableId
    ? unique.find((item) => item.stableId === row.targetNodeStableId)
    : matches.length === 1
      ? matches[0]
      : undefined;
  const omit = (reason: string): AclOmission => ({ kind: "backup", id: row.id, reason });
  if (row.targetNodeStableId && !node) return omit("pinned backup node has not been observed");
  if (matches.length > 1) return omit("backup target name or address is ambiguous");
  if (node && !matches.some((item) => item.stableId === node.stableId))
    return omit("backup URL does not match the pinned identity");
  const ip = literal ? tailnetIp(host) : (tailnetIp(node?.ipv4) ?? tailnetIp(node?.ipv6));
  if (!ip) return omit("backup target has not been observed on the tailnet yet");

  return {
    id: row.id,
    name: row.name,
    ip,
    port,
    stableId: node?.stableId ?? row.targetNodeStableId,
    addresses: [
      ...new Set(
        nodes
          .flatMap((item) =>
            item.stableId === node?.stableId ? [tailnetIp(item.ipv4), tailnetIp(item.ipv6)] : [],
          )
          .filter((address): address is string => address !== null),
      ),
    ],
    targetName: cleanName(node?.dnsName) ?? (parseIpLiteral(host) ? null : cleanName(host)),
  };
}

// ---- HuJSON parsing and a local evaluator for the generated `tests` ----

/** Strips comments and trailing commas from HuJSON and parses the result. */
export function parseHujson(text: string): unknown {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const char = text[i] as string;
    if (char === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j;
    } else if (char === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (char === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end < 0 ? text.length : end + 1;
    } else {
      out += char;
    }
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
}

export type PolicyTestFailure = { src: string; destination: string; expected: "accept" | "deny" };

/**
 * Evaluates a policy's `tests` against its `grants` and `acls` the way Tailscale does for the
 * selectors the generator uses (tags, host aliases, IPs, CIDRs, users, `*` and the common
 * autogroups). It is a local check, not a substitute for Tailscale's own validation; the opt-in
 * `mise run test:tailnet-acl` runs that against a scratch tailnet.
 */
export function evaluatePolicyTests(policy: TailnetPolicy): PolicyTestFailure[] {
  const failures: PolicyTestFailure[] = [];
  for (const test of policy.tests ?? []) {
    for (const [expected, destinations] of [
      ["accept", test.accept ?? []],
      ["deny", test.deny ?? []],
    ] as const) {
      for (const destination of destinations) {
        const split = destination.lastIndexOf(":");
        const host = destination.slice(0, split).replace(/^\[|\]$/g, "");
        const port = Number(destination.slice(split + 1));
        const allowed = policyAllows(policy, test.src, host, port, test.proto);
        if (allowed !== (expected === "accept")) failures.push({ src: test.src, destination, expected });
      }
    }
  }
  return failures;
}

/** Whether any grant or ACL lets `src` reach `host:port` (TCP or UDP when `proto` is unset). */
export function policyAllows(policy: TailnetPolicy, src: string, host: string, port: number, proto?: string) {
  const grants = (policy.grants ?? []).some(
    (grant) =>
      grant.src.some((selector) => selectorMatches(policy, selector, src)) &&
      grant.dst.some((selector) => selectorMatches(policy, selector, host)) &&
      grant.ip.some((spec) => portSpecMatches(spec, port, proto)),
  );
  if (grants) return true;
  return (policy.acls ?? []).some((acl) => {
    if (acl.action !== "accept") return false;
    if (!acl.src.some((selector) => selectorMatches(policy, selector, src))) return false;
    return acl.dst.some((entry) => {
      const split = entry.lastIndexOf(":");
      const selector = entry.slice(0, split).replace(/^\[|\]$/g, "");
      const ports = entry.slice(split + 1).split(",");
      return (
        selectorMatches(policy, selector, host) &&
        ports.some((part) => portSpecMatches(acl.proto ? `${acl.proto}:${part}` : part, port, proto))
      );
    });
  });
}

function resolveAddress(policy: TailnetPolicy, value: string) {
  const aliased = policy.hosts?.[value];
  return parseIpLiteral(aliased ?? value);
}

function selectorMatches(policy: TailnetPolicy, selector: string, entity: string) {
  if (selector === "*" || selector === entity) return true;
  if (selector === "autogroup:tagged") return entity.startsWith("tag:");
  if (selector === "autogroup:member") return entity.includes("@");
  const address = resolveAddress(policy, entity);
  if (!address) return false;
  const aliased = policy.hosts?.[selector] ?? selector;
  const [network, bits] = aliased.split("/");
  const parsed = parseIpLiteral(network ?? "");
  if (!parsed || parsed.version !== address.version) return false;
  const width = bits === undefined ? (parsed.version === 4 ? 32 : 128) : Number(bits);
  return prefixMatch(address.bytes, parsed.bytes, width);
}

function portSpecMatches(spec: string, port: number, proto?: string) {
  if (spec === "*") return true;
  const split = spec.lastIndexOf(":");
  const protocol = split < 0 ? null : spec.slice(0, split).toLowerCase();
  const ports = split < 0 ? spec : spec.slice(split + 1);
  if (protocol !== null) {
    const name = protocol === "6" ? "tcp" : protocol === "17" ? "udp" : protocol;
    if (proto ? name !== proto : name !== "tcp" && name !== "udp") return false;
  }
  if (ports === "*") return true;
  const [low, high] = ports.split("-").map(Number);
  if (low === undefined || !Number.isInteger(low)) return false;
  return port >= low && port <= (high ?? low);
}

// ---- Line diff, for "what changed since the last generated snippet" ----

export type DiffLine = { op: "same" | "add" | "remove"; line: string };

/** A minimal LCS line diff. Large inputs fall back to remove-all/add-all rather than run slowly. */
export function diffLines(previous: string, next: string): DiffLine[] {
  const a = previous.split("\n");
  const b = next.split("\n");
  if (a.length * b.length > 4_000_000) {
    return [
      ...a.map((line) => ({ op: "remove" as const, line })),
      ...b.map((line) => ({ op: "add" as const, line })),
    ];
  }
  const table = Array.from({ length: a.length + 1 }, () => new Uint32Array(b.length + 1));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      const row = table[i] as Uint32Array;
      row[j] =
        a[i] === b[j]
          ? ((table[i + 1] as Uint32Array)[j + 1] as number) + 1
          : Math.max((table[i + 1] as Uint32Array)[j] as number, row[j + 1] as number);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      out.push({ op: "same", line: a[i] as string });
      i++;
      j++;
    } else if (((table[i + 1] as Uint32Array)[j] as number) >= ((table[i] as Uint32Array)[j + 1] as number)) {
      out.push({ op: "remove", line: a[i++] as string });
    } else {
      out.push({ op: "add", line: b[j++] as string });
    }
  }
  while (i < a.length) out.push({ op: "remove", line: a[i++] as string });
  while (j < b.length) out.push({ op: "add", line: b[j++] as string });
  return out;
}

/**
 * Compare the full TCP/UDP port space on known destinations against a trusted global snippet.
 * Grant/ACL access is constant between port-range boundaries, so checking every boundary covers
 * the complement without rendering 65,536 test destinations per host. This local model supports
 * the same selectors as policyAllows; live Tailscale validation is still required for policies
 * with groups, posture, via or other capabilities this evaluator does not model.
 */
export function auditTailnetPolicy(expected: TailnetPolicy, candidate: TailnetPolicy): PolicyTestFailure[] {
  for (const policy of [expected, candidate]) {
    const supportedSelector = (value: string) =>
      value === "*" ||
      (ARK_TAGS as readonly string[]).includes(value) ||
      USER.test(value) ||
      ["autogroup:tagged", "autogroup:member", "autogroup:self"].includes(value) ||
      !!resolveAddress(policy, value.split("/")[0] ?? value);
    for (const rule of [...(policy.grants ?? []), ...(policy.acls ?? [])]) {
      const isGrant = "ip" in rule;
      const keys = isGrant ? ["src", "dst", "ip"] : ["action", "src", "dst", "proto"];
      if (
        Object.keys(rule).some((key) => !keys.includes(key)) ||
        rule.src.some((src) => !supportedSelector(src)) ||
        rule.dst.some(
          (entry) =>
            !supportedSelector(
              isGrant ? entry : entry.slice(0, entry.lastIndexOf(":")).replace(/^\[|\]$/g, ""),
            ),
        )
      ) {
        throw new ValidationError(
          "The local audit cannot model this rule's selectors or conditions; validate and review it with Tailscale.",
        );
      }
    }
  }
  const ports = new Set([0, 1, 65535]);
  for (const policy of [expected, candidate]) {
    const specs = [
      ...(policy.grants ?? []).flatMap((grant) => grant.ip),
      ...(policy.acls ?? []).flatMap((acl) =>
        acl.dst.flatMap((dst) => dst.slice(dst.lastIndexOf(":") + 1).split(",")),
      ),
    ];
    for (const spec of specs) {
      const range = spec.slice(spec.lastIndexOf(":") + 1);
      const [low, high = low] = range.split("-").map(Number);
      for (const port of [low, high === undefined ? undefined : high + 1]) {
        if (port !== undefined && Number.isInteger(port) && port >= 0 && port <= 65535) ports.add(port);
      }
    }
  }
  const known = new Set<string>(Object.values(expected.hosts ?? {}));
  for (const test of expected.tests ?? []) {
    for (const entry of [...(test.accept ?? []), ...(test.deny ?? [])]) {
      const host = entry.slice(0, entry.lastIndexOf(":")).replace(/^\[|\]$/g, "");
      known.add(expected.hosts?.[host] ?? host);
    }
  }
  const failures: PolicyTestFailure[] = [];
  for (const src of [ARK_EDGE_TAG, ARK_BACKUP_TAG]) {
    for (const host of known) {
      for (const proto of ["tcp", "udp"]) {
        for (const port of [...ports].toSorted((a, b) => a - b)) {
          const wanted = policyAllows(expected, src, host, port, proto);
          if (policyAllows(candidate, src, host, port, proto) !== wanted) {
            failures.push({
              src,
              destination: `${proto}/${testDestination(host, port)}`,
              expected: wanted ? "accept" : "deny",
            });
            break;
          }
        }
      }
    }
  }
  return failures;
}
