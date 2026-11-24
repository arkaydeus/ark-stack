import { expect, test } from "bun:test";

import {
  hostRoutesFromFront,
  assertHostFirewall,
  providerFirewallRules,
  publicHostPorts,
  readHostSshAccess,
  renderHostFirewall,
  renderEdgeL4Generation,
  renderFrontIngress,
  type HostPortConfig,
  type HostSshAccess,
  updateHostFirewallPorts,
} from "@ark-stack/shared";
import { unexpectedPorts } from "../../scripts/host-audit.ts";
import { assertAutomaticUpdates, vpsAuthKeyFile } from "../../scripts/install-host-hardening.ts";

test("the provider rules use the same ports as the host and exclude empty raw port reservations", () => {
  const routes = hostRoutesFromFront(
    renderFrontIngress(
      [
        { id: "rt_open", listenPort: 20007, sourceCidrs: [], allowInternet: true },
        { id: "rt_restricted", listenPort: 20009, sourceCidrs: ["198.51.100.9/32"] },
      ],
      [8883],
    ),
  );
  const config = { mailEnabled: true, sniPorts: [8883], routes };
  expect(publicHostPorts(config)).toEqual({
    tcp: [25, 80, 443, 465, 587, 993, 5432, 8883, 20007, 20009],
    udp: [41641, 41642],
  });
  expect(providerFirewallRules({ ...config, mailEnabled: false })).toEqual([
    { protocol: "tcp", ports: [80, 443, 5432, 8883, 20007, 20009], sourceCidrs: ["0.0.0.0/0", "::/0"] },
    { protocol: "udp", ports: [41641, 41642], sourceCidrs: ["0.0.0.0/0", "::/0"] },
  ]);
});

test("DHCPv6 replies are allowed only to the link-local client, outside the public inventory", () => {
  const config = { mailEnabled: false, sniPorts: [] };
  expect(renderHostFirewall(config)).toContain("ip6 daddr fe80::/10 udp sport 547 udp dport 546 accept");
  expect(publicHostPorts(config).udp).not.toContain(546);
});

test("edge reconciliation updates public sets independently of the guided SSH allowance", () => {
  const config = { mailEnabled: false, sniPorts: [8883] };
  const access = { ports: [22], source: "2001:db8:0:0:0:0:0:1" };
  const rules = renderHostFirewall(config, access)
    .split("\n")
    .slice(2)
    .join("\n")
    .replace(access.source, "2001:db8::1");
  expect(readHostSshAccess(rules)).toEqual({ ports: [22], source: "2001:db8::1" });
  expect(() => assertHostFirewall(rules, config, access)).not.toThrow();
  expect(() => assertHostFirewall(rules, config)).toThrow();
  expect(updateHostFirewallPorts(config)).not.toMatch(/ssh_access|delete table/);
});

const installedTable = (config: HostPortConfig, access?: HostSshAccess) =>
  renderHostFirewall(config, access).split("\n").slice(2).join("\n");

function firewallProblem(rules: string, config: HostPortConfig, access?: HostSshAccess) {
  try {
    assertHostFirewall(rules, config, access);
    return "";
  } catch (error) {
    return String(error);
  }
}

test("the host firewall check accepts protocol numbers and names, and only the baseline's protocols", () => {
  const config = { mailEnabled: true, sniPorts: [] };
  const named = installedTable(config, { ports: [] });
  // What nft lists without /etc/protocols, as in the database-ingress image.
  const numeric = named
    .replace("{ icmp, ipv6-icmp }", "{ 1, 58 }")
    .replace("l4proto tcp", "l4proto 6")
    .replace("l4proto udp", "l4proto 17");
  expect(numeric).not.toMatch(/l4proto (?:tcp|udp|\{ icmp)/);
  for (const rules of [
    numeric,
    named.replace("{ icmp, ipv6-icmp }", "{ ipv6-icmp, 1 }"),
    named.replace("l4proto udp", "l4proto 17"),
  ]) {
    expect(firewallProblem(rules, config, { ports: [] })).toBe("");
  }
  for (const [from, to] of [
    ["{ 1, 58 }", "{ 1, 132 }"],
    ["{ 1, 58 }", "{ 1, 58, 132 }"],
    ["{ 1, 58 }", "{ 1-58 }"],
    ["{ 1, 58 }", "1"],
    ["{ 1, 58 }", "!= { 1, 58 }"],
    ["l4proto 6 ", "l4proto 17 "],
    ["l4proto 6 ", "l4proto 132 "],
    ["l4proto 6 ", "l4proto != 6 "],
    ["l4proto 6 ", "l4proto 6-17 "],
    ["l4proto 17 ", "l4proto 6 "],
    ["l4proto 17 ", ""],
    ["sport 547", "sport 17"],
  ] as const) {
    expect(numeric).toContain(from);
    expect(firewallProblem(numeric.replace(from, to), config, { ports: [] })).toContain("rules differ");
  }
});

test("a host firewall mismatch names the difference without administrator addresses", () => {
  const config = { mailEnabled: true, sniPorts: [] };
  const access = { ports: [22], source: "198.51.100.23" };
  const rules = installedTable(config, access);
  expect(firewallProblem(rules.replace("policy drop", "policy accept"), config, access)).toContain(
    'chain input is missing "type filter hook input priority -5; policy drop;"; chain input has 1 unexpected entry',
  );
  expect(firewallProblem(rules.replace("{ 25, 80", "{ 80, 8080"), config, access)).toContain(
    'set public_tcp is missing "element 25"; set public_tcp has 1 unexpected entry',
  );
  expect(firewallProblem(rules.replace("    jump ssh_access\n", ""), config, access)).toContain(
    'chain input is missing "jump ssh_access"',
  );
  const loopback = 'iifname "lo" accept';
  for (const added of [
    "ip saddr 198.51.100.23 accept",
    "ip saddr { 198.51.100.23, 203.0.113.0/24 } accept",
    "ip6 saddr 2001:db8::17 accept",
    "ip6 saddr { 2001:db8::17, ::ffff:198.51.100.23 } accept",
    "@nh,96,32 0xc6336417 accept",
    "jump allow_198_51_100_23",
    "ip saddr @admin_198_51_100_23 accept",
    'tcp dport 3306 accept comment "from 198-51-100-23.isp.example"',
    'tcp dport 3306 log prefix "admin_0xc6336417" accept',
    'tcp dport 3306 accept comment "ip6 saddr dead 198-51-100-23"',
  ]) {
    const error = firewallProblem(rules.replace(loopback, `${loopback}\n    ${added}`), config, access);
    expect(error).toContain("chain input has 1 unexpected entry");
    expect(error).not.toMatch(/198[._-]51[._-]100[._-]23|203\.0|2001:db8|c6336417/i);
  }
  for (const extra of [
    "chain allow_198_51_100_23 {\n    accept\n  }",
    "set admin_198_51_100_23 {\n    type ipv4_addr\n  }",
    "map admin_0xc6336417 {\n    type ipv4_addr : verdict\n  }",
  ]) {
    const error = firewallProblem(
      rules.replace("chain published {", `${extra}\n  chain published {`),
      config,
      access,
    );
    expect(error).toContain("the listing has 1 unexpected section");
    expect(error).not.toMatch(/198_51_100_23|c6336417/i);
  }
  const ssh = firewallProblem(rules, config, { ports: [22, 2222], source: "203.0.113.9" });
  expect(ssh).toContain("chain ssh_access differs (installed rules: 1, expected: 2)");
  expect(ssh).not.toMatch(/198\.51|203\.0/);
});

test("retained SSH only exempts the matching host SSH socket from the local audit", () => {
  const config = { mailEnabled: false, sniPorts: [] };
  const sockets = [
    'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=911,fd=3))',
    'tcp LISTEN 0 128 [::]:22 [::]:* users:(("docker-proxy",pid=123,fd=5))',
    'tcp LISTEN 0 128 0.0.0.0:12345 0.0.0.0:* users:(("sshd",pid=911,fd=4))',
  ].join("\n");
  expect(unexpectedPorts(config, sockets, [], new Set(), [22])).toEqual([
    "Unexpected TCP [::]:22 listening on the host.",
    "Unexpected TCP 0.0.0.0:12345 listening on the host.",
  ]);
});

test("host ss audit allows DHCP client sockets and resolver stubs but rejects unrelated owners", () => {
  const sockets = [
    'udp UNCONN 0 0 10.0.0.5%ens3:68 0.0.0.0:* users:(("systemd-network",pid=345,fd=21))',
    'udp UNCONN 0 0 [fe80::a%ens3]:546 [::]:* users:(("systemd-networkd",pid=345,fd=23))',
    'udp UNCONN 0 0 [fe80::b]%ens3:546 [::]:* users:(("systemd-network",pid=345,fd=24))',
    'udp UNCONN 0 0 *:546 *:* users:(("dhclient",pid=567,fd=10))',
    'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=458,fd=17))',
    'tcp LISTEN 0 4096 127.0.0.54:53 0.0.0.0:* users:(("systemd-resolve",pid=458,fd=18))',
    'udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:* users:(("other",pid=8,fd=9),("dhclient",pid=9,fd=10))',
    'udp UNCONN 0 0 *:12345 *:* users:(("other",pid=12,fd=3))',
  ].join("\n");
  expect(unexpectedPorts({ mailEnabled: false, sniPorts: [] }, sockets, [])).toEqual([
    "Unexpected UDP 0.0.0.0:68 listening on the host.",
    "Unexpected UDP *:12345 listening on the host.",
  ]);
});

test("effective apt validation reports all overridden settings together", () => {
  const config = `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "0";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "05:00";
`;
  expect(() => assertAutomaticUpdates(config, "04:00", "noble")).toThrow(
    /APT::Periodic::Unattended-Upgrade.*Automatic-Reboot must be enabled.*Automatic-Reboot-Time.*Allowed-Origins/,
  );
});

test("missing enrollment key has the same operator error as an unset key", async () => {
  await expect(vpsAuthKeyFile(`/nonexistent/${crypto.randomUUID()}`)).rejects.toThrow(
    "Set TS_VPS_AUTHKEY_FILE to a private absolute key file",
  );
});

test("a configured SNI frontend is present with or without leased routes and rejects unknown SNI", () => {
  const generation = renderEdgeL4Generation({ httpHostnames: [], sniPorts: [8883] });
  for (const file of ["haproxy.cfg", "haproxy.closed.cfg"]) {
    expect(generation.files[file]).toMatch(
      /frontend fe_tls8883\n    bind :::8883 v4v6\n[\s\S]+default_backend be_reject/,
    );
    expect(generation.files[file]).not.toContain("frontend fe_tls5671");
  }
});

test("audit distinguishes edge raw reservations from unrelated listeners and publications", () => {
  const config = { mailEnabled: false, sniPorts: [] };
  const sockets = [
    'tcp LISTEN 0 128 0.0.0.0:20001 0.0.0.0:* users:(("docker-proxy",pid=1,fd=1))',
    'tcp LISTEN 0 128 [::]:20001 [::]:* users:(("dockerd",pid=1,fd=1))',
    'tcp LISTEN 0 128 [::]:20001 [::]:* users:(("sshd",pid=1,fd=1))',
    'tcp LISTEN 0 128 127.0.0.1:3000 0.0.0.0:* users:(("bun",pid=1,fd=1))',
    'udp UNCONN 0 0 100.64.0.5:10101 0.0.0.0:* users:(("test",pid=1,fd=1))',
    'udp UNCONN 0 0 [::]:24444 [::]:* users:(("test",pid=1,fd=1))',
  ].join("\n");
  expect(
    unexpectedPorts(
      config,
      sockets,
      [
        {
          container: "/ark-platform-edge-ts-1",
          arkEdge: true,
          protocol: "tcp",
          address: "0.0.0.0",
          port: 20001,
          target: 20001,
        },
        {
          container: "/ark-platform-edge-ts-1",
          arkEdge: true,
          protocol: "tcp",
          address: "::",
          port: 20001,
          target: 20001,
        },
        { container: "/unexpected", protocol: "tcp", address: "::", port: 20003, target: 8080 },
        {
          container: "/unexpected",
          arkEdge: true,
          protocol: "tcp",
          address: "::",
          port: 20004,
          target: 8080,
        },
      ],
      new Set(["100.64.0.5"]),
    ),
  ).toEqual([
    "Unexpected TCP [::]:20003 published by /unexpected.",
    "Unexpected TCP [::]:20004 published by /unexpected.",
    "Unexpected TCP [::]:20001 listening on the host.",
    "Unexpected UDP [::]:24444 listening on the host.",
  ]);
});
