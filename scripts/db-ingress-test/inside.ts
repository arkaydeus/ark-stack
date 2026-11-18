// Runs inside the privileged Linux container started by scripts/test-db-ingress.ts. It builds a
// small topology of network namespaces and checks the public-port policies (§3.11) against real
// TCP connections:
//
//   netns cl  (clients)                container netns ("host")             netns be  (backend)
//   10.10.0.2, 10.10.0.3        <->    10.10.0.1                    <->    10.20.0.2
//   2001:db8:10:1::2, ::3 (one /64)    2001:db8:10:1::1, 2001:db8:10:2::1  fd00:20::2
//   2001:db8:10:2::2 (another /64)     server on :5432 (input hook)        server on :5432
//                                      DNAT :5432 -> be (forward hook)
//
// Only node builtins are imported, so the container needs nothing but bun, nft and ip.
// Modes: `main` (default) runs every case; `server <banner>` and `client` are helpers it starts
// inside the namespaces.
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync } from "node:fs";
import { mkdir, rename } from "node:fs/promises";
import { connect, createServer, type Socket } from "node:net";
import { createInterface } from "node:readline";

const mode = process.argv[2] ?? "main";
const rulesDir = process.env.ARK_DB_INGRESS_RULES ?? "/rules";
const self = process.argv[1];

// ---------------------------------------------------------------- helpers in the namespaces

const serverPorts = [80, 443, 5432, 8883, 20001, 20002, 20003, 20049, 20050];

async function runServer(banner: string) {
  await Promise.all(
    serverPorts.map(
      (port) =>
        new Promise<void>((resolve) => {
          const server = createServer((socket) => {
            socket.on("error", () => undefined);
            socket.on("end", () => socket.end());
            socket.write(`${banner}\n`);
          });
          server.listen({ host: "::", port, ipv6Only: false }, resolve);
        }),
    ),
  );
  console.log("ready");
}

type Endpoint = { src: string; dst: string; port: number; timeoutMs: number };
type OpenCommand = Endpoint & { op: "open"; count: number; hold: boolean };
type ProbeCommand = Endpoint & { op: "probe" };
type Command = OpenCommand | ProbeCommand | { op: "closeAll" } | { op: "closeOne"; src: string };

function open(command: Endpoint) {
  return new Promise<Socket | null>((resolve) => {
    const socket = connect({ host: command.dst, port: command.port, localAddress: command.src });
    const timer = setTimeout(() => {
      socket.destroy();
      resolve(null);
    }, command.timeoutMs);
    socket.once("connect", () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once("error", () => {
      clearTimeout(timer);
      socket.destroy();
      resolve(null);
    });
  });
}

function runClient() {
  const held: Socket[] = [];
  const lines = createInterface({ input: process.stdin });
  lines.on("line", async (line) => {
    const command = JSON.parse(line) as Command;
    if (command.op === "open") {
      const sockets = await Promise.all(Array.from({ length: command.count }, () => open(command)));
      const opened = sockets.filter((socket): socket is Socket => socket !== null);
      for (const socket of opened) {
        socket.on("error", () => undefined);
        if (command.hold) held.push(socket);
        else socket.end();
      }
      console.log(JSON.stringify({ ok: opened.length, failed: command.count - opened.length }));
    } else if (command.op === "probe") {
      const socket = await open(command);
      if (!socket) {
        console.log(JSON.stringify({ banner: null }));
        return;
      }
      const banner = await new Promise<string | null>((resolve) => {
        const timer = setTimeout(() => resolve(null), command.timeoutMs);
        socket.once("data", (chunk) => {
          clearTimeout(timer);
          resolve(String(chunk).trim());
        });
      });
      socket.end();
      console.log(JSON.stringify({ banner }));
    } else if (command.op === "closeOne") {
      const index = held.findIndex((socket) => socket.localAddress === command.src);
      if (index >= 0) held.splice(index, 1)[0]!.destroy();
      console.log(JSON.stringify({ closed: index >= 0 }));
    } else {
      for (const socket of held.splice(0)) socket.destroy();
      console.log(JSON.stringify({ closed: true }));
    }
  });
}

// ---------------------------------------------------------------------------- the harness

function sh(...args: string[]) {
  const result = spawnSync(args[0], args.slice(1), { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`${args.join(" ")} exited ${result.status}: ${(result.stderr || result.stdout).trim()}`);
  }
  return result.stdout;
}

function inNs(ns: string, ...args: string[]) {
  return sh("ip", "netns", "exec", ns, ...args);
}

function enableIpv6(ns?: string) {
  const script =
    "echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6; echo 0 > /proc/sys/net/ipv6/conf/default/disable_ipv6";
  if (ns) inNs(ns, "sh", "-c", script);
  else sh("sh", "-c", script);
}

function topology() {
  enableIpv6();
  sh("sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward; echo 1 > /proc/sys/net/ipv6/conf/all/forwarding");
  for (const ns of ["cl", "be"]) {
    sh("ip", "netns", "add", ns);
    enableIpv6(ns);
    inNs(ns, "ip", "link", "set", "lo", "up");
    sh("ip", "link", "add", `h-${ns}`, "type", "veth", "peer", "name", `c-${ns}`);
    sh("ip", "link", "set", `c-${ns}`, "netns", ns);
  }
  const host = (...args: string[]) => sh("ip", ...args);
  host("addr", "add", "10.10.0.1/24", "dev", "h-cl");
  host("addr", "add", "198.51.100.1/24", "dev", "h-cl");
  host("-6", "addr", "add", "2001:db8:10:1::1/64", "dev", "h-cl", "nodad");
  host("-6", "addr", "add", "2001:db8:10:2::1/64", "dev", "h-cl", "nodad");
  host("-6", "addr", "add", "2001:db8:100::1/64", "dev", "h-cl", "nodad");
  host("link", "set", "h-cl", "up");
  host("addr", "add", "10.20.0.1/24", "dev", "h-be");
  host("-6", "addr", "add", "fd00:20::1/64", "dev", "h-be", "nodad");
  host("link", "set", "h-be", "up");
  const cl = (...args: string[]) => inNs("cl", "ip", ...args);
  for (const address of ["10.10.0.2/24", "10.10.0.3/24", "10.10.0.4/24", "198.51.100.2/24"])
    cl("addr", "add", address, "dev", "c-cl");
  for (const address of [
    "2001:db8:10:1::2/64",
    "2001:db8:10:1::3/64",
    "2001:db8:10:2::2/64",
    "2001:db8:100::2/64",
  ]) {
    cl("-6", "addr", "add", address, "dev", "c-cl", "nodad");
  }
  cl("link", "set", "c-cl", "up");
  const be = (...args: string[]) => inNs("be", "ip", ...args);
  be("addr", "add", "10.20.0.2/24", "dev", "c-be");
  be("-6", "addr", "add", "fd00:20::2/64", "dev", "c-be", "nodad");
  be("link", "set", "c-be", "up");
  be("route", "add", "default", "via", "10.20.0.1");
  be("-6", "route", "add", "default", "via", "fd00:20::1");
}

const children: ChildProcess[] = [];

async function startServer(ns: string | null, banner: string) {
  const args = ns
    ? ["ip", "netns", "exec", ns, "bun", self, "server", banner]
    : ["bun", self, "server", banner];
  const child = spawn(args[0], args.slice(1), { stdio: ["ignore", "pipe", "inherit"] });
  children.push(child);
  await new Promise<void>((resolve, reject) => {
    child.stdout?.once("data", () => resolve());
    child.once("exit", (code) => reject(new Error(`${banner} server exited ${code}`)));
  });
}

class Client {
  private child = spawn("ip", ["netns", "exec", "cl", "bun", self, "client"], {
    stdio: ["pipe", "pipe", "inherit"],
  });
  private replies = createInterface({ input: this.child.stdout! })[Symbol.asyncIterator]();

  constructor() {
    children.push(this.child);
  }

  async send<T>(command: Command): Promise<T> {
    this.child.stdin!.write(`${JSON.stringify(command)}\n`);
    const next = await this.replies.next();
    if (next.done) throw new Error("client helper exited");
    return JSON.parse(next.value) as T;
  }

  open(
    src: string,
    dst: string,
    count: number,
    options: { hold?: boolean; timeoutMs?: number; port?: number } = {},
  ) {
    return this.send<{ ok: number; failed: number }>({
      op: "open",
      src,
      dst,
      port: options.port ?? 5432,
      count,
      hold: options.hold ?? true,
      timeoutMs: options.timeoutMs ?? 1500,
    });
  }

  probe(src: string, dst: string, port = 5432) {
    return this.send<{ banner: string | null }>({ op: "probe", src, dst, port, timeoutMs: 700 });
  }

  closeOne(src: string) {
    return this.send<{ closed: boolean }>({ op: "closeOne", src });
  }

  closeAll() {
    return this.send<{ closed: boolean }>({ op: "closeAll" });
  }
}

let failures = 0;

function check(condition: boolean, claim: string, observed: string) {
  if (!condition) failures++;
  console.log(`  ${condition ? "ok  " : "FAIL"}  ${claim} [${observed}]`);
}

function counters(table = "ark_db_ingress") {
  const json = sh("nft", "-j", "list", "counters", "table", "inet", table);
  const values: Record<string, number> = {};
  for (const item of (
    JSON.parse(json) as { nftables: Array<{ counter?: { name: string; packets: number } }> }
  ).nftables) {
    if (item.counter) values[item.counter.name] = item.counter.packets;
  }
  return { json, values };
}

function apply(file: string) {
  sh("nft", "-f", `${rulesDir}/${file}`);
}

const NAT = `table inet ark_test_nat
delete table inet ark_test_nat
table inet ark_test_nat {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    ip daddr 10.10.0.1 tcp dport { ${serverPorts.join(", ")} } dnat ip to 10.20.0.2
    ip6 daddr 2001:db8:10:1::1 tcp dport { ${serverPorts.join(", ")} } dnat ip6 to fd00:20::2
  }
}
`;

const V4_DST = "10.10.0.1";
const V6_DST = "2001:db8:10:1::1";
const A4 = "10.10.0.2";
const B4 = "10.10.0.3";
const A6 = "2001:db8:10:1::2";
const A6_SAME_64 = "2001:db8:10:1::3";
const C6_OTHER_64 = "2001:db8:10:2::2";

async function reset(client: Client, file: string) {
  await client.closeAll();
  await Bun.sleep(300);
  // Isolate independent scenarios explicitly. Production reapplies never delete the table.
  sh("nft", "delete", "table", "inet", "ark_db_ingress");
  apply(file);
}

async function concurrentCase(client: Client, hook: "input" | "forward", limit: number) {
  console.log(`\n[${hook} hook] concurrent connections per source (limit ${limit})`);
  const expectBanner = hook;
  const probe = await client.probe(B4, V4_DST);
  check(
    probe.banner === expectBanner,
    `a tcp/5432 connection takes the ${hook} path`,
    `banner=${probe.banner}`,
  );
  await reset(client, "conn.nft");

  const a = await client.open(A4, V4_DST, limit + 3);
  check(
    a.ok === limit && a.failed === 3,
    `IPv4 ${A4}: ${limit} of ${limit + 3} concurrent connections establish, the excess is dropped`,
    `ok=${a.ok} failed=${a.failed}`,
  );
  const b = await client.open(B4, V4_DST, 2);
  check(b.ok === 2, `IPv4 ${B4}: a second source still connects`, `ok=${b.ok} failed=${b.failed}`);

  const a6 = await client.open(A6, V6_DST, limit);
  check(
    a6.ok === limit,
    `IPv6 ${A6}: ${limit} concurrent connections establish`,
    `ok=${a6.ok} failed=${a6.failed}`,
  );
  const same = await client.open(A6_SAME_64, V6_DST, 2);
  check(
    same.ok === 0 && same.failed === 2,
    `IPv6 ${A6_SAME_64} (same /64): dropped, the /64 is already at its limit`,
    `ok=${same.ok} failed=${same.failed}`,
  );
  const other = await client.open(C6_OTHER_64, V6_DST, 2);
  check(
    other.ok === 2,
    `IPv6 ${C6_OTHER_64} (another /64): still connects`,
    `ok=${other.ok} failed=${other.failed}`,
  );

  // Hold the sockets across ordinary reloads and limit changes. In particular, lowering
  // below the old cap must still reject new sessions while another source has capacity.
  for (const file of ["conn.nft", "conn-lower.nft"]) {
    if (file === "conn-lower.nft") {
      await client.closeOne(A4);
      await client.closeOne(A6);
      await Bun.sleep(500);
    }
    apply(file);
    for (const [source, destination] of [
      [A4, V4_DST],
      [A6_SAME_64, V6_DST],
    ]) {
      const extra = await client.open(source!, destination!, limit, { timeoutMs: 700 });
      check(extra.ok === 0, `${hook}: ${source} stays capped after ${file}`, `ok=${extra.ok}`);
    }
    const independent = await client.open(file === "conn-lower.nft" ? "10.10.0.4" : B4, V4_DST, 1);
    check(
      independent.ok === 1,
      `${hook}: another source still connects after ${file}`,
      `ok=${independent.ok}`,
    );
  }

  const { json, values } = counters();
  check(
    (values.drop_conn4 ?? 0) >= 3,
    "counter drop_conn4 counts the IPv4 drops",
    `drop_conn4=${values.drop_conn4}`,
  );
  check(
    (values.drop_conn6 ?? 0) >= 2,
    "counter drop_conn6 counts the IPv6 drops",
    `drop_conn6=${values.drop_conn6}`,
  );
  check(
    (values.drop_rate4 ?? 0) === 0 && (values.drop_rate6 ?? 0) === 0,
    "the rate counters stay at zero",
    `drop_rate4=${values.drop_rate4} drop_rate6=${values.drop_rate6}`,
  );
  console.log(`@@counters ${hook}-concurrent ${json.trim()}`);
  await client.closeAll();
  // Retired conncount elements are garbage-collected when the old sessions drain.
  await Bun.sleep(3000);
  const resumed = await client.open(A4, V4_DST, limit - 1);
  check(resumed.ok === limit - 1, `${hook}: a drained source uses the lower cap`, `ok=${resumed.ok}`);
  const capped = await client.open(A4, V4_DST, 1, { timeoutMs: 700 });
  check(capped.ok === 0, `${hook}: lower cap is enforced after draining`, `ok=${capped.ok}`);
  await client.closeAll();
}

async function rateCase(client: Client, hook: "input" | "forward", burst: number) {
  console.log(`\n[${hook} hook] new-connection rate per source (burst ${burst})`);
  await reset(client, "rate.nft");
  // A dropped SYN is retransmitted after one second, so attempts give up before that.
  const timeoutMs = 700;
  const attempts = burst * 3;
  const a = await client.open(A4, V4_DST, attempts, { hold: false, timeoutMs });
  check(
    a.ok >= 1 && a.ok <= burst + 1 && a.failed >= attempts - burst - 1,
    `IPv4 ${A4}: a burst of ${attempts} new connections is limited to about ${burst}`,
    `ok=${a.ok} failed=${a.failed}`,
  );
  const b = await client.open(B4, V4_DST, 3, { hold: false, timeoutMs });
  check(b.ok === 3, `IPv4 ${B4}: another source is not limited`, `ok=${b.ok} failed=${b.failed}`);

  const a6 = await client.open(A6, V6_DST, burst - 1, { hold: false, timeoutMs });
  check(
    a6.ok === burst - 1,
    `IPv6 ${A6}: ${burst - 1} new connections fit in the burst`,
    `ok=${a6.ok} failed=${a6.failed}`,
  );
  const same = await client.open(A6_SAME_64, V6_DST, burst + 1, { hold: false, timeoutMs });
  check(
    same.ok <= 2 && same.failed >= burst - 1,
    `IPv6 ${A6_SAME_64} (same /64): shares the exhausted bucket and is limited`,
    `ok=${same.ok} failed=${same.failed}`,
  );
  const other = await client.open(C6_OTHER_64, V6_DST, 3, { hold: false, timeoutMs });
  check(
    other.ok === 3,
    `IPv6 ${C6_OTHER_64} (another /64): not limited`,
    `ok=${other.ok} failed=${other.failed}`,
  );

  const { json, values } = counters();
  check(
    (values.drop_rate4 ?? 0) > 0,
    "counter drop_rate4 counts the IPv4 drops",
    `drop_rate4=${values.drop_rate4}`,
  );
  check(
    (values.drop_rate6 ?? 0) > 0,
    "counter drop_rate6 counts the IPv6 drops",
    `drop_rate6=${values.drop_rate6}`,
  );
  check(
    (values.drop_conn4 ?? 0) === 0 && (values.drop_conn6 ?? 0) === 0,
    "the concurrent-connection counters stay at zero",
    `drop_conn4=${values.drop_conn4} drop_conn6=${values.drop_conn6}`,
  );
  console.log(`@@counters ${hook}-rate ${json.trim()}`);
}

async function frontProbes(client: Client, hook: "input" | "forward", generated: boolean) {
  const name = generated ? "generated ark_front" : "literal \u00A73.11 ark_front";
  const cases: Array<[number, string, string, boolean]> = [
    [80, A4, V4_DST, true],
    [443, A6, V6_DST, true],
    [20001, "198.51.100.2", V4_DST, true],
    [20001, "2001:db8:100::2", V6_DST, true],
    [20001, A4, V4_DST, false],
    [20001, A6, V6_DST, false],
    [20049, A4, V4_DST, false],
    [20049, A6, V6_DST, false],
    [20050, A4, V4_DST, true],
  ];
  if (generated) cases.push([8883, A4, V4_DST, true], [20002, A4, V4_DST, false], [20003, A6, V6_DST, true]);
  for (const [port, source, destination, allowed] of cases) {
    const { banner } = await client.probe(source, destination, port);
    check(
      banner === (allowed ? hook : null),
      `${hook}: ${name} tcp/${port} from ${source} is ${allowed ? "admitted" : "dropped"}`,
      `banner=${banner}`,
    );
  }
  if (generated) {
    const { values } = counters("ark_front");
    check(
      values.drop_allowlist >= 3 && values.drop_closed >= 2,
      "kernel counters confirm CIDR and closed-port drops",
      JSON.stringify(values),
    );
  }
}

async function sharedLimitsCase(client: Client, hook: "input" | "forward") {
  apply("front-limits.nft");
  const a = await client.open(A4, V4_DST, 2, { port: 80 });
  const extra = await client.open(A4, V4_DST, 1, { port: 443, timeoutMs: 700 });
  const other = await client.open(B4, V4_DST, 1, { port: 8883 });
  check(
    a.ok === 2 && extra.ok === 0 && other.ok === 1,
    `${hook}: shared IPv4 cap spans HTTP, HTTPS and SNI`,
    `initial=${a.ok} extra=${extra.ok} other source=${other.ok}`,
  );
  const v6 = await client.open(A6, V6_DST, 2, { port: 443 });
  const same = await client.open(A6_SAME_64, V6_DST, 1, { port: 8883, timeoutMs: 700 });
  const different = await client.open(C6_OTHER_64, V6_DST, 1, { port: 8883 });
  check(
    v6.ok === 2 && same.ok === 0 && different.ok === 1,
    `${hook}: shared IPv6 cap groups sources by /64`,
    `initial=${v6.ok} same /64=${same.ok} another /64=${different.ok}`,
  );
  await client.closeAll();

  const { values } = counters("ark_front");
  check(
    values.drop_conn4 > 0 && values.drop_conn6 > 0,
    "shared connection drops increment both family counters",
    JSON.stringify(values),
  );
  apply("front-rate.nft");
  for (const [source, destination] of [
    [A4, V4_DST],
    [A6, V6_DST],
  ] as const) {
    const result = await client.open(source, destination, 15, { port: 8883, hold: false, timeoutMs: 700 });
    check(
      result.ok >= 1 && result.ok <= 6,
      `${hook}: ${source} is rate-limited on the shared SNI port`,
      JSON.stringify(result),
    );
  }
  const rate = counters("ark_front").values;
  check(
    rate.drop_rate4 > 0 && rate.drop_rate6 > 0,
    "shared new-connection drops increment both family counters",
    JSON.stringify(rate),
  );
}

async function reconcilerCase(client: Client) {
  const dir = "/tmp/front-reconciler";
  await mkdir(`${dir}/front`, { recursive: true });
  const child = spawn("bun", ["/bundle/database-ingress.js"], {
    stdio: "inherit",
    env: {
      ...process.env,
      ARK_FRONT_INGRESS_DIR: `${dir}/front`,
      ARK_EDGE_SNI_PORTS: "8883",
      ARK_PGBOUNCER_DIR: `${dir}/pgbouncer`,
      ARK_DB_INGRESS_METRICS_DIR: `${dir}/metrics`,
    },
  });
  children.push(child);
  async function request(rules: string) {
    const id = crypto.randomUUID();
    const hash = createHash("sha256").update(rules).digest("hex");
    await Bun.write(`${dir}/front/policy.nft.tmp`, rules);
    await rename(`${dir}/front/policy.nft.tmp`, `${dir}/front/policy.nft`);
    await Bun.write(`${dir}/front/policy.request.tmp`, JSON.stringify({ id, hash }));
    await rename(`${dir}/front/policy.request.tmp`, `${dir}/front/policy.request`);
    for (let i = 0; i < 60; i++) {
      const status = await Bun.file(`${dir}/front/policy.status`)
        .text()
        .catch(() => "");
      if (
        status.includes(`request_id=${id}
`) &&
        status.includes(`policy_hash=${hash}
`)
      ) {
        return status.replaceAll("\n", " ").trim();
      }
      await Bun.sleep(100);
    }
    throw new Error("Reconciler did not acknowledge the requested nft policy.");
  }

  // Simulate a kernel with an FD-26 table still active. Its drop must disappear with the upgrade.
  await Bun.write(
    "/tmp/legacy-front.nft",
    `table inet ark_front_raw {
  chain forward {
    type filter hook forward priority -1; policy accept;
    ct status dnat tcp dport 20001 drop
  }
}
`,
  );
  sh("nft", "-f", "/tmp/legacy-front.nft");
  const good = await Bun.file(`${rulesDir}/combined.nft`).text();
  let status = await request(good);
  check(
    status.startsWith("applied=true "),
    "reconciler installs and acknowledges the complete policy",
    status,
  );
  const before = await client.probe("198.51.100.2", V4_DST, 20001);
  check(
    before.banner === "forward",
    "reconciler retires the legacy raw table in the install",
    JSON.stringify(before),
  );
  let snapshots: { table?: string; front?: { table?: string } } = {};
  for (let i = 0; i < 40 && !snapshots.front; i++) {
    snapshots = await Bun.file(`${dir}/metrics/counters.json`)
      .json()
      .catch(() => ({}));
    if (!snapshots.front) await Bun.sleep(50);
  }
  check(
    snapshots.table === "ark_db_ingress" && snapshots.front?.table === "ark_front",
    "reconciler exports both tables to the read-only API snapshot",
    JSON.stringify({ database: snapshots.table, front: snapshots.front?.table }),
  );

  // Force an nft transaction error while the old listeners and policies are still in place.
  status = await request(good + "add chain inet ark_front invalid chain syntax\n");
  check(
    status.startsWith("applied=false ") && /error=.*nft .*exited/.test(status),
    "failed apply reports an error for the exact request",
    status,
  );
  for (const port of [80, 443, 5432, 8883, 20001]) {
    const input = await client.probe("198.51.100.2", "198.51.100.1", port);
    const forward = await client.probe("2001:db8:100::2", V6_DST, port);
    check(
      input.banner === null && forward.banner === null,
      `failed apply closes tcp/${port} on input and DNAT paths`,
      `input=${input.banner} forward=${forward.banner}`,
    );
  }
  const unrelated = await client.probe(A4, V4_DST, 20050);
  check(
    unrelated.banner === "forward",
    "failure guard leaves unrelated ports reachable",
    JSON.stringify(unrelated),
  );

  status = await request(good);
  check(status.startsWith("applied=true "), "reconciler acknowledges recovery", status);
  const recovered = await client.probe("2001:db8:100::2", V6_DST, 20001);
  check(
    recovered.banner === "forward",
    "successful readback releases the drop guard",
    JSON.stringify(recovered),
  );
}
async function main() {
  console.log("nft -c (check only) on every rendered ruleset");
  const files = readdirSync(rulesDir)
    .filter((name) => name.endsWith(".nft"))
    .toSorted();
  for (const file of files) {
    const result = spawnSync("nft", ["-c", "-f", `${rulesDir}/${file}`], { encoding: "utf8" });
    check(result.status === 0, `nft -c -f ${file}`, result.status === 0 ? "valid" : result.stderr.trim());
  }
  console.log(`  nft version: ${sh("nft", "--version").trim()}`);

  topology();
  await startServer(null, "input");
  await startServer("be", "forward");
  const client = new Client();
  apply("legacy.nft");
  check(
    !sh("nft", "list", "table", "inet", "ark_db_ingress").includes("ark_db_limits"),
    "legacy fixture has no per-source limits",
    "pre-FD-18 policy",
  );
  apply("defaults.nft");
  const listed = sh("nft", "list", "table", "inet", "ark_db_ingress");
  check(
    listed.includes("ark_db_limits") &&
      listed.includes("drop_conn4") &&
      listed.includes("drop_rate6") &&
      !listed.includes("ark_db_allow") &&
      !listed.includes("drop_allowlist"),
    "legacy table upgrades to named limit counters and retires its CIDR chain",
    "FD-18 policy loaded",
  );
  console.log("\nLoaded ruleset (defaults), as the kernel reports it:");
  console.log(listed.trimEnd());

  const conn = Number(process.env.ARK_DB_INGRESS_TEST_CONN ?? "5");
  const burst = Number(process.env.ARK_DB_INGRESS_TEST_BURST ?? "5");

  await concurrentCase(client, "input", conn);
  await rateCase(client, "input", burst);
  apply("front-example.nft");
  await frontProbes(client, "input", false);
  apply("front-defaults.nft");
  await frontProbes(client, "input", true);
  await sharedLimitsCase(client, "input");

  await Bun.write("/tmp/nat.nft", NAT);
  sh("nft", "-f", "/tmp/nat.nft");
  apply("conn.nft");
  await concurrentCase(client, "forward", conn);
  await rateCase(client, "forward", burst);
  sh("nft", "delete", "table", "inet", "ark_front");
  apply("front-example.nft");
  await frontProbes(client, "forward", false);
  apply("front-defaults.nft");
  await frontProbes(client, "forward", true);
  await sharedLimitsCase(client, "forward");
  await reconcilerCase(client);

  for (const child of children) child.kill();
  console.log(failures ? `\n${failures} check(s) failed.` : "\nAll in-container checks passed.");
  process.exit(failures ? 1 : 0);
}

// Dispatch last, so every module-level binding above is initialised before main() runs.
if (mode === "server") await runServer(process.argv[3] ?? "server");
else if (mode === "client") runClient();
else await main();
