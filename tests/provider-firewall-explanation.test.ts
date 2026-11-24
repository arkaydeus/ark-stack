import { expect, test } from "bun:test";
import { join } from "node:path";

import {
  describeProviderRules,
  manualProviderFirewall,
  type FirewallContext,
  type ProviderRule,
} from "../scripts/host-setup/provider-firewall.ts";
import { hetznerProviderFirewall } from "../scripts/host-setup/provider-firewalls/hetzner.ts";
import type { Ui } from "../scripts/host-setup/system.ts";

const RULES: ProviderRule[] = [
  { protocol: "tcp", ports: [80, 443], sourceCidrs: ["0.0.0.0/0", "::/0"] },
  { protocol: "udp", ports: [41641, 41642], sourceCidrs: ["0.0.0.0/0", "::/0"] },
];
const FINISH =
  "Apply the rules above in your provider's firewall, then re-run host:setup with --provider-firewall-applied.";

function firewallContext(interactive: boolean, answer = "") {
  const printed: string[] = [];
  const questions: string[] = [];
  const ui: Ui = {
    interactive,
    print: (line = "") => void printed.push(line),
    ask: async (question) => {
      questions.push(question);
      return answer;
    },
    askSecret: async () => "",
    askPassword: async () => "",
  };
  const context: FirewallContext = {
    ui,
    interactive,
    env: {},
    publicAddresses: { ipv4: ["203.0.113.10"], ipv6: [] },
    confirmed: false,
  };
  return { context, printed, questions };
}

const flat = (text: string) => text.replace(/[*`]/g, "").replace(/\s+/g, " ");

/** The meaning the step and the docs share. */
function expectExplanation(text: string) {
  const words = flat(text);
  expect(words).toContain("Your host may run a separate firewall outside");
  expect(words).toContain("it cannot see or change the host's one");
  expect(words).toContain("you set that in the host's control panel");
  expect(words).toMatch(
    /Normally on: AWS \(security groups\), Google Cloud \(VPC firewall rules\), Azure \(network security groups\) and Oracle Cloud \(security lists or network security groups\)/,
  );
  expect(words).toContain(
    "Not normally on, unless you added one: Hetzner, DigitalOcean, HOSTKEY, Vultr and Linode",
  );
  expect(words).toMatch(/Not sure\? Look for Firewall, Security group or Network ACL in the control panel/);
  expect(words).toContain("A VM behind a router usually needs these ports forwarded to it instead");
}

test.each([true, false])(
  "the manual step explains the provider firewall before unchanged rules (interactive: %p)",
  async (interactive) => {
    for (const retainSsh of [false, true]) {
      const { context } = firewallContext(interactive);
      const plan = await manualProviderFirewall.plan(RULES, { ...context, retainSsh });
      const rules = describeProviderRules(RULES, retainSsh);
      expect(plan.inSync).toBe(false);
      expect(plan.changes.slice(-rules.length)).toEqual(rules);
      const explanation = plan.changes.slice(0, -rules.length);
      expectExplanation(explanation.join("\n"));
      // Setup indents each line by six columns; keep them within a 110-column terminal.
      for (const line of explanation) expect(line.length).toBeLessThanOrEqual(104);
    }
  },
);

test.each([
  ["yes", "applied"],
  ["y", "applied"],
  ["skip", "pending"],
  ["", "pending"],
  ["none", "pending"],
])("the question covers a host with no firewall and what skip leaves; %p is %s", async (answer, status) => {
  const { context, questions } = firewallContext(true, answer);
  const plan = await manualProviderFirewall.plan(RULES, context);
  const result = await manualProviderFirewall.apply(plan, context);
  expect(questions).toHaveLength(1);
  expect(questions[0]).toStartWith(
    "Type yes once they are applied, or if your host has no separate firewall.",
  );
  expect(questions[0]).toContain(
    "Type skip to finish later: the install carries on, but this step and the final local audit stay unfinished",
  );
  expect(result.status).toBe(status as typeof result.status);
  if (result.status === "pending") {
    expect(result).toEqual({
      status: "pending",
      note: "The provider firewall rules were not confirmed.",
      finish: FINISH,
    });
  }
});

test("an unconfirmed scripted run asks nothing and keeps its finish command", async () => {
  const { context, questions } = firewallContext(false);
  const plan = await manualProviderFirewall.plan(RULES, context);
  expect(await manualProviderFirewall.apply(plan, context)).toEqual({
    status: "pending",
    note: "The provider firewall rules were printed but not confirmed.",
    finish: FINISH,
  });
  expect(questions).toEqual([]);
});

test("the Hetzner adapter prints its plan without the manual explanation", async () => {
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const { pathname } = new URL(request.url);
      if (pathname.endsWith("/instance-id")) return new Response("4242");
      if (pathname === "/v1/servers/4242") {
        return Response.json({
          server: {
            id: 4242,
            name: "ark-vps",
            public_net: { ipv4: { ip: "203.0.113.10" }, ipv6: null, firewalls: [] },
          },
        });
      }
      if (pathname === "/v1/firewalls") {
        return Response.json({ firewalls: [], meta: { pagination: { next_page: null } } });
      }
      return new Response("not found", { status: 404 });
    },
  });
  try {
    const url = `http://127.0.0.1:${server.port}`;
    const adapter = hetznerProviderFirewall({ apiBase: `${url}/v1`, metadataBase: url });
    const { context, printed } = firewallContext(false);
    context.env = { HCLOUD_TOKEN: "hcloud-test-token" };
    expect(await adapter.detect(context)).toBe(true);
    const plan = await adapter.plan(RULES, context);
    const text = [...(plan.notices ?? []), ...plan.changes, ...printed].join("\n");
    expect(text).toContain("ark-stack-4242");
    expect(text).not.toContain("separate firewall");
    expect(text).not.toContain("Not sure?");
  } finally {
    await server.stop(true);
  }
});

test("the production install guide has the same explanation and the outside check", async () => {
  const guide = await Bun.file(join(import.meta.dir, "../docs/getting-started/production-install.md")).text();
  const section = guide.split("\n### Provider firewall\n")[1]?.split("\n### ")[0] ?? "";
  expectExplanation(section.replace(/^- /gm, ""));
  expect(section).toContain("sudo tcpdump -ni any 'tcp dst port 22222'");
  expect(section).toContain("nc -vz -w 5 <public-ip> 22222");
  expect(guide).not.toContain("and a provider firewall you control");
});
