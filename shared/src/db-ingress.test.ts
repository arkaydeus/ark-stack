// Rendered-ruleset tests for `inet ark_db_ingress` (docs/design/front-door.md §3.11, FD-18).
// The kernel-level behaviour (nft -c, connection caps, rates, /64 grouping on both hooks) is
// tested in a privileged container by `mise run test:db-ingress` (scripts/test-db-ingress.ts).
import { describe, expect, test } from "bun:test";

import {
  DB_INGRESS_LIMIT_DEFAULTS,
  dbIngressLimits,
  dbIngressLimitsInput,
  dbIngressLimitsSummary,
  renderDbIngress,
  platformDbIngressLimits,
} from "./db-ingress.ts";
import { ingressCounterMetrics, parseNftCounters } from "./ingress-counters.ts";

const design = await Bun.file(new URL("../../docs/design/front-door.md", import.meta.url)).text();

/** The `table inet ark_db_ingress { ... }` block of §3.11, as literal lines. */
function designRules() {
  const start = design.indexOf("table inet ark_db_ingress {");
  const end = design.indexOf("\n}\n", start);
  expect(start).toBeGreaterThan(-1);
  return design
    .slice(start, end)
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

function chain(rules: string, name: string) {
  const start = rules.indexOf(`  chain ${name} {`);
  expect(start).toBeGreaterThan(-1);
  return rules.slice(start, rules.indexOf("\n  }\n", start));
}

describe("rendered ark_db_ingress ruleset", () => {
  test("matches TCP 5432 on both the input and forward hooks, ahead of Docker at priority -1", () => {
    const rules = renderDbIngress();
    const input = chain(rules, "input");
    expect(input).toContain("type filter hook input priority -1; policy accept;");
    expect(input).toContain("tcp dport 5432 jump ark_db_limits");
    const forward = chain(rules, "forward");
    expect(forward).toContain("type filter hook forward priority -1; policy accept;");
    expect(forward).toContain("ct direction original ct status dnat tcp dport 5432 jump ark_db_limits");
  });

  test("at the defaults, the §3.11 example is rendered with generation-qualified set names", () => {
    const rendered = renderDbIngress();
    for (const line of designRules()) {
      if (line.startsWith("table ") || line === "}") continue;
      // Ark names counters for metrics and qualifies dynamic sets by the configured limits.
      const named = line
        .replace(/ counter drop$/, "")
        .replace(/\bconn([46])\b/g, "conn$1_128")
        .replace(/\brate([46])\b/g, "rate$1_30_60");
      expect(rendered).toContain(named);
    }
    expect(DB_INGRESS_LIMIT_DEFAULTS).toEqual({
      maxConnectionsPerSource: 128,
      newConnectionsPerSecond: 30,
      newConnectionBurst: 60,
    });
  });

  test("groups IPv6 sources by /64 for both limits and IPv4 per address", () => {
    const limits = chain(renderDbIngress(), "ark_db_limits");
    expect(limits).toContain("add @conn4_128 { ip saddr ct count over 128 }");
    expect(limits).toContain("add @conn6_128 { ip6 saddr and ffff:ffff:ffff:ffff:: ct count over 128 }");
    expect(limits).toContain("update @rate4_30_60 { ip saddr limit rate over 30/second burst 60 packets }");
    expect(limits).toContain(
      "update @rate6_30_60 { ip6 saddr and ffff:ffff:ffff:ffff:: limit rate over 30/second burst 60 packets }",
    );
    // ct count sets must not carry a timeout (nftables meters page); rate sets expire.
    expect(renderDbIngress()).toContain("set conn6_128 { type ipv6_addr; size 65535; flags dynamic; }");
    expect(renderDbIngress()).toContain(
      "set rate6_30_60 { type ipv6_addr; size 65535; flags dynamic; timeout 2m; }",
    );
  });

  test("reapplies retain state and cap changes guard previous source generations until drained", () => {
    const original = renderDbIngress({
      maxConnectionsPerSource: 5,
      newConnectionsPerSecond: 2,
      newConnectionBurst: 5,
    });
    expect(
      renderDbIngress(
        { maxConnectionsPerSource: 5, newConnectionsPerSecond: 2, newConnectionBurst: 5 },
        original,
      ),
    ).toBe(original);
    const lower = renderDbIngress(
      { maxConnectionsPerSource: 4, newConnectionsPerSecond: 3, newConnectionBurst: 6 },
      original,
    );
    expect(lower).not.toContain("delete table");
    expect(lower).not.toContain("flush set");
    expect(lower).toContain("flush chain inet ark_db_ingress ark_db_limits");
    expect(lower).toContain('ct state new ip saddr @active4_5 counter name "drop_conn4" drop');
    expect(lower).toContain(
      'ct state new ip6 saddr and ffff:ffff:ffff:ffff:: @active6_5 counter name "drop_conn6" drop',
    );
    expect(lower).toContain("add @conn4_4 { ip saddr ct count over 4 }");
    expect(lower).toContain("update @rate4_3_6 { ip saddr limit rate over 3/second burst 6 packets }");
    const legacy = original.replaceAll("conn4_5", "conn4").replaceAll("conn6_5", "conn6");
    const upgraded = renderDbIngress(DB_INGRESS_LIMIT_DEFAULTS, legacy);
    expect(upgraded).toContain('ip saddr @active4 counter name "drop_conn4" drop');
    expect(upgraded).toContain("set conn6 { type ipv6_addr; size 65535; flags dynamic; }");
  });

  test("renders the configured limits and every drop with a named counter", () => {
    const rules = renderDbIngress({
      maxConnectionsPerSource: 7,
      newConnectionsPerSecond: 3,
      newConnectionBurst: 9,
    });
    expect(rules).toContain('ct count over 7 } counter name "drop_conn4" drop');
    expect(rules).toContain('ct count over 7 } counter name "drop_conn6" drop');
    expect(rules).toContain('limit rate over 3/second burst 9 packets } counter name "drop_rate4" drop');
    expect(rules).toContain('limit rate over 3/second burst 9 packets } counter name "drop_rate6" drop');
    for (const name of ["drop_conn4", "drop_conn6", "drop_rate4", "drop_rate6"]) {
      expect(rules).toContain(`  counter ${name} {}`);
    }
    expect(rules).not.toContain('counter name "drop_allowlist"');
    // No anonymous drop counters: every drop is attributable in the metrics.
    expect(rules).not.toMatch(/ counter drop$/m);
  });

  test("refuses limits nft would reject or that would disable the cap", () => {
    expect(() =>
      renderDbIngress({
        maxConnectionsPerSource: 0,
        newConnectionsPerSecond: 30,
        newConnectionBurst: 60,
      }),
    ).toThrow("Invalid database ingress limits");
    expect(() =>
      renderDbIngress({
        maxConnectionsPerSource: 1.5,
        newConnectionsPerSecond: 30,
        newConnectionBurst: 60,
      }),
    ).toThrow("Invalid database ingress limits");
  });
});

describe("platform limits", () => {
  test("validates bounds, whole numbers, unknown keys and burst >= rate", () => {
    const valid = { maxConnectionsPerSource: 64, newConnectionsPerSecond: 10, newConnectionBurst: 20 };
    expect(dbIngressLimitsInput.parse(valid)).toEqual(valid);
    expect(dbIngressLimitsInput.safeParse({ ...valid, maxConnectionsPerSource: 65_536 }).success).toBe(false);
    expect(dbIngressLimitsInput.safeParse({ ...valid, newConnectionsPerSecond: 0 }).success).toBe(false);
    expect(dbIngressLimitsInput.safeParse({ ...valid, newConnectionBurst: 100_001 }).success).toBe(false);
    expect(dbIngressLimitsInput.safeParse({ ...valid, newConnectionBurst: 9 }).success).toBe(false);
    expect(dbIngressLimitsInput.safeParse({ ...valid, newConnectionBurst: "20" }).success).toBe(false);
    expect(dbIngressLimitsInput.safeParse({ ...valid, extra: 1 }).success).toBe(false);
  });

  test("a missing or out-of-range stored value falls back to the safe default", () => {
    expect(platformDbIngressLimits(null)).toEqual(DB_INGRESS_LIMIT_DEFAULTS);
    expect(
      platformDbIngressLimits({
        dbIngressMaxConnections: 16,
        dbIngressRatePerSecond: 5,
        dbIngressRateBurst: 10,
      }),
    ).toEqual({ maxConnectionsPerSource: 16, newConnectionsPerSecond: 5, newConnectionBurst: 10 });
    expect(
      dbIngressLimits({ maxConnectionsPerSource: -1, newConnectionsPerSecond: 200, newConnectionBurst: 0 }),
    ).toEqual({ maxConnectionsPerSource: 128, newConnectionsPerSecond: 200, newConnectionBurst: 200 });
    expect(dbIngressLimitsSummary(null)).toMatchObject({
      ...DB_INGRESS_LIMIT_DEFAULTS,
      defaults: DB_INGRESS_LIMIT_DEFAULTS,
      ipv6Grouping: "/64",
      port: 5432,
    });
  });
});

describe("nft counters as Prometheus metrics", () => {
  const kernel = JSON.stringify({
    nftables: [
      { metainfo: { version: "1.1.3", json_schema_version: 1 } },
      {
        counter: {
          family: "inet",
          name: "drop_conn4",
          table: "ark_db_ingress",
          handle: 1,
          packets: 6,
          bytes: 360,
        },
      },
      {
        counter: {
          family: "inet",
          name: "drop_rate6",
          table: "ark_db_ingress",
          handle: 4,
          packets: 5,
          bytes: 400,
        },
      },
      {
        counter: { family: "inet", name: "rogue", table: "ark_db_ingress", handle: 9, packets: 1, bytes: 1 },
      },
      {
        counter: { family: "inet", name: "drop_conn4", table: "ark_front", handle: 2, packets: 99, bytes: 1 },
      },
    ],
  });

  test("parseNftCounters keeps only this table's known named counters", () => {
    const snapshot = parseNftCounters(kernel, new Date("2026-11-16T00:00:00Z"));
    expect(snapshot).toEqual({
      table: "ark_db_ingress",
      observedAt: "2026-11-16T00:00:00.000Z",
      counters: [
        { name: "drop_conn4", packets: 6, bytes: 360 },
        { name: "drop_rate6", packets: 5, bytes: 400 },
      ],
    });
  });

  test("exports drops by table, chain, reason and family, plus snapshot presence and age", () => {
    const snapshot = parseNftCounters(kernel, new Date("2026-11-16T00:00:00Z"));
    const lines = ingressCounterMetrics(snapshot, new Date("2026-11-16T00:00:30Z"));
    expect(lines).toContain('ark_nft_counters_present{table="ark_db_ingress"} 1');
    expect(lines).toContain('ark_nft_counters_age_seconds{table="ark_db_ingress"} 30');
    expect(lines).toContain("# TYPE ark_nft_drop_packets_total counter");
    expect(lines).toContain(
      'ark_nft_drop_packets_total{table="ark_db_ingress",chain="ark_db_limits",reason="concurrent",family="ipv4"} 6',
    );
    expect(lines).toContain(
      'ark_nft_drop_packets_total{table="ark_db_ingress",chain="ark_db_limits",reason="rate",family="ipv6"} 5',
    );
    expect(lines.join("\n")).not.toContain("rogue");
  });

  test("exports both tables from the same snapshot with a single definition per metric", () => {
    const instant = new Date("2026-11-16T00:00:00Z");
    const db = parseNftCounters(kernel, instant);
    const front = parseNftCounters(kernel, instant, "ark_front");
    const lines = ingressCounterMetrics({ ...db, front }, instant);
    expect(lines).toContain('ark_nft_counters_present{table="ark_front"} 1');
    expect(lines).toContain('ark_nft_counters_present{table="ark_db_ingress"} 1');
    expect(lines).toContain(
      'ark_nft_drop_packets_total{table="ark_front",chain="shared_limits",reason="concurrent",family="ipv4"} 99',
    );
    expect(lines.filter((line) => line === "# TYPE ark_nft_drop_packets_total counter")).toHaveLength(1);
  });

  test("a missing or malformed snapshot reports absent and never invents counter values", () => {
    for (const value of [null, {}, { table: "ark_db_ingress", counters: [] }, "garbage"]) {
      const lines = ingressCounterMetrics(value);
      expect(lines).toContain('ark_nft_counters_present{table="ark_db_ingress"} 0');
      expect(lines.some((line) => line.startsWith("ark_nft_drop_packets_total"))).toBe(false);
    }
    const tampered = ingressCounterMetrics({
      table: "ark_db_ingress",
      observedAt: new Date().toISOString(),
      counters: [
        { name: 'drop_conn4"} 1\nevil{', packets: 1 },
        { name: "drop_conn6", packets: -1 },
        { name: "drop_rate4", packets: "7" },
        { name: "drop_rate6", packets: 2 },
        { name: "drop_rate6", packets: 3 },
      ],
    });
    const drops = tampered.filter((line) => line.startsWith("ark_nft_drop_packets_total"));
    expect(drops).toEqual([
      'ark_nft_drop_packets_total{table="ark_db_ingress",chain="ark_db_limits",reason="rate",family="ipv6"} 2',
    ]);
  });
});
