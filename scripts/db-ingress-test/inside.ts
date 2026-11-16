// Runs inside the privileged Linux container started by scripts/test-db-ingress.ts. It builds a
// small topology of network namespaces and checks the rendered `inet ark_db_ingress` ruleset
// (docs/design/front-door.md §3.11, FD-18) against real TCP connections:
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
import { readdirSync } from "node:fs";
import { connect, createServer, type Socket } from "node:net";
import { createInterface } from "node:readline";

const mode = process.argv[2] ?? "main";
const rulesDir = process.env.ARK_DB_INGRESS_RULES ?? "/rules";
const self = process.argv[1];

// ---------------------------------------------------------------- helpers in the namespaces

function runServer(banner: string) {
  const server = createServer((socket) => {
    socket.on("error", () => undefined);
    socket.on("end", () => socket.end());
    socket.write(`${banner}\n`);
  });
  server.listen({ host: "::", port: 5432, ipv6Only: false }, () => console.log("ready"));
}

type OpenCommand = { op: "open"; src: string; dst: string; count: number; timeoutMs: number; hold: boolean };
type ProbeCommand = { op: "probe"; src: string; dst: string; timeoutMs: number };
type Command = OpenCommand | ProbeCommand | { op: "closeAll" };

function open(command: { src: string; dst: string; timeoutMs: number }) {
  return new Promise<Socket | null>((resolve) => {
    const socket = connect({ host: command.dst, port: 5432, localAddress: command.src });
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
  host("-6", "addr", "add", "2001:db8:10:1::1/64", "dev", "h-cl", "nodad");
  host("-6", "addr", "add", "2001:db8:10:2::1/64", "dev", "h-cl", "nodad");
  host("link", "set", "h-cl", "up");
  host("addr", "add", "10.20.0.1/24", "dev", "h-be");
  host("-6", "addr", "add", "fd00:20::1/64", "dev", "h-be", "nodad");
  host("link", "set", "h-be", "up");
  const cl = (...args: string[]) => inNs("cl", "ip", ...args);
  for (const address of ["10.10.0.2/24", "10.10.0.3/24"]) cl("addr", "add", address, "dev", "c-cl");
  for (const address of ["2001:db8:10:1::2/64", "2001:db8:10:1::3/64", "2001:db8:10:2::2/64"]) {
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

  open(src: string, dst: string, count: number, options: { hold?: boolean; timeoutMs?: number } = {}) {
    return this.send<{ ok: number; failed: number }>({
      op: "open",
      src,
      dst,
      count,
      hold: options.hold ?? true,
      timeoutMs: options.timeoutMs ?? 1500,
    });
  }

  probe(src: string, dst: string) {
    return this.send<{ banner: string | null }>({ op: "probe", src, dst, timeoutMs: 2000 });
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

function counters() {
  const json = sh("nft", "-j", "list", "counters", "table", "inet", "ark_db_ingress");
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
    ip daddr 10.10.0.1 tcp dport 5432 dnat ip to 10.20.0.2
    ip6 daddr 2001:db8:10:1::1 tcp dport 5432 dnat ip6 to fd00:20::2
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
  // `nft -f` deletes and recreates the table, so every per-source set and counter starts empty.
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

async function allowlistCase(client: Client) {
  console.log("\n[input hook] CIDR allowlist ahead of the limits");
  await reset(client, "allowlist.nft");
  const denied = await client.open(A4, V4_DST, 1, { hold: false, timeoutMs: 700 });
  check(
    denied.ok === 0,
    `IPv4 ${A4}: outside the allowlist, dropped`,
    `ok=${denied.ok} failed=${denied.failed}`,
  );
  const allowed = await client.open(B4, V4_DST, 1, { hold: false });
  check(
    allowed.ok === 1,
    `IPv4 ${B4}: inside the allowlist, connects`,
    `ok=${allowed.ok} failed=${allowed.failed}`,
  );
  const v6 = await client.open(C6_OTHER_64, V6_DST, 1, { hold: false });
  check(
    v6.ok === 1,
    `IPv6 ${C6_OTHER_64}: inside the allowlist, connects`,
    `ok=${v6.ok} failed=${v6.failed}`,
  );
  const { json, values } = counters();
  check(
    (values.drop_allowlist ?? 0) > 0,
    "counter drop_allowlist counts the drop",
    `drop_allowlist=${values.drop_allowlist}`,
  );
  console.log(`@@counters input-allowlist ${json.trim()}`);
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
  apply("defaults.nft");
  const listed = sh("nft", "list", "table", "inet", "ark_db_ingress");
  console.log("\nLoaded ruleset (defaults), as the kernel reports it:");
  console.log(listed.trimEnd());

  const conn = Number(process.env.ARK_DB_INGRESS_TEST_CONN ?? "5");
  const burst = Number(process.env.ARK_DB_INGRESS_TEST_BURST ?? "5");

  await concurrentCase(client, "input", conn);
  await rateCase(client, "input", burst);
  await allowlistCase(client);

  await Bun.write("/tmp/nat.nft", NAT);
  sh("nft", "-f", "/tmp/nat.nft");
  apply("conn.nft");
  await concurrentCase(client, "forward", conn);
  await rateCase(client, "forward", burst);

  for (const child of children) child.kill();
  console.log(failures ? `\n${failures} check(s) failed.` : "\nAll in-container checks passed.");
  process.exit(failures ? 1 : 0);
}

// Dispatch last, so every module-level binding above is initialised before main() runs.
if (mode === "server") runServer(process.argv[3] ?? "server");
else if (mode === "client") runClient();
else await main();
