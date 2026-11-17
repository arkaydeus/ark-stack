import { afterEach, expect, test } from "bun:test";
import { createServer, type Socket } from "node:net";
import { socks5Connect, socks5HttpRequest } from "./modules/socks5-http.ts";

const savedDial = process.env.ARK_TEST_SOCKS5_DIAL;
const cleanups: (() => void)[] = [];
afterEach(() => {
  for (const cleanup of cleanups.splice(0)) cleanup();
  if (savedDial === undefined) delete process.env.ARK_TEST_SOCKS5_DIAL;
  else process.env.ARK_TEST_SOCKS5_DIAL = savedDial;
});

async function proxy(options: {
  split?: boolean;
  reply?: number[];
  greeting?: boolean;
  hold?: boolean;
  response?: Buffer;
}) {
  const sockets = new Set<Socket>();
  let destination = Buffer.alloc(0);
  let requests = 0;
  let closed = 0;
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("error", () => {});
    socket.once("close", () => {
      sockets.delete(socket);
      closed++;
    });
    let stage = 0;
    socket.on("data", (data) => {
      if (stage === 0) {
        stage++;
        if (options.greeting === false) return;
        if (options.split) {
          socket.write(Buffer.from([5]));
          setTimeout(() => socket.write(Buffer.from([0])), 5);
        } else socket.write(Buffer.from([5, 0]));
      } else if (stage === 1) {
        stage++;
        destination = Buffer.from(data);
        const reply = Buffer.from(options.reply ?? [5, 0, 0, 3, 3, 97, 98, 99, 0, 80]);
        if (options.split) {
          socket.write(reply.subarray(0, 4));
          setTimeout(() => socket.write(reply.subarray(4)), 5);
        } else socket.write(reply);
      } else {
        requests++;
        if (!options.hold)
          socket.end(options.response ?? Buffer.from("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as { port: number };
  process.env.ARK_TEST_SOCKS5_DIAL = `127.0.0.1:${address.port}`;
  cleanups.push(() => {
    for (const socket of sockets) socket.destroy();
    server.close();
  });
  return {
    get destination() {
      return destination;
    },
    get requests() {
      return requests;
    },
    get closed() {
      return closed;
    },
  };
}
const request = (extra: Partial<Parameters<typeof socks5HttpRequest>[0]> = {}) =>
  socks5HttpRequest({
    proxy: "socks5://backup-ts:1055",
    url: "http://home.tail123.ts.net:8000/ark",
    connectHost: "100.66.2.9",
    method: "POST",
    timeoutMs: 500,
    ...extra,
  });
async function until(predicate: () => boolean) {
  const deadline = Date.now() + 1_000;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error("fixture did not progress");
    await Bun.sleep(5);
  }
}

test("split greeting and domain reply; HTTP dials the pinned address", async () => {
  const fixture = await proxy({ split: true });
  const result = await request();
  expect(result.status).toBe(200);
  expect(Buffer.from(result.body).toString()).toBe("ok");
  expect([...fixture.destination]).toEqual([5, 1, 0, 1, 100, 66, 2, 9, 31, 64]);
});
test("SOCKS failure codes and malformed replies reject", async () => {
  for (const reply of [
    [5, 5, 0, 1, 0],
    [5, 0, 0, 9, 0],
    [4, 0, 0, 1, 0],
  ]) {
    await proxy({ reply });
    await expect(request()).rejects.toThrow(/refused|Malformed/);
  }
});
test("chunked HTTP bodies decode across socket fragments", async () => {
  await proxy({
    split: true,
    response: Buffer.from(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;foo=bar\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
    ),
  });
  expect(Buffer.from((await request()).body).toString()).toBe("abcde");
});
test("response cap rejects and closes the connection", async () => {
  const fixture = await proxy({
    response: Buffer.concat([Buffer.from("HTTP/1.1 200 OK\r\n\r\n"), Buffer.alloc(4 * 1024 * 1024)]),
  });
  await expect(request({ timeoutMs: 2_000 })).rejects.toThrow(/too large/);
  await until(() => fixture.closed === 1);
});
for (const phase of ["SOCKS", "TLS", "HTTP"] as const) {
  test(`abort closes a stalled ${phase} connection`, async () => {
    const fixture = await proxy({ greeting: phase !== "SOCKS", hold: true });
    const controller = new AbortController();
    const pending = request({
      signal: controller.signal,
      url: `${phase === "TLS" ? "https" : "http"}://home.tail123.ts.net:8000/ark`,
    }).catch((error: Error) => error);
    if (phase !== "SOCKS") await until(() => fixture.requests > 0);
    else await Bun.sleep(20);
    controller.abort(new Error("identity changed"));
    expect(((await pending) as Error).message).toMatch(/identity changed/);
    await until(() => fixture.closed === 1);
  });
}
test("overall deadline closes a TLS peer that never responds", async () => {
  const fixture = await proxy({ hold: true });
  const started = Date.now();
  await expect(request({ url: "https://home.tail123.ts.net:8000/ark", timeoutMs: 100 })).rejects.toThrow(
    /within 100 ms/,
  );
  expect(Date.now() - started).toBeLessThan(1_000);
  await until(() => fixture.closed === 1);
});
test("SOCKS connect rejects an already aborted signal before connecting", async () => {
  const fixture = await proxy({});
  expect(() =>
    socks5Connect(
      "socks5://backup-ts:1055",
      "100.66.2.9",
      8000,
      500,
      AbortSignal.abort(new Error("cancelled")),
    ),
  ).toThrow(/cancelled/);
  expect(fixture.requests).toBe(0);
});
