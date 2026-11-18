import { expect, test } from "bun:test";
import { once } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect, createServer, type TLSSocket } from "node:tls";

import { queryPostgresOverTls } from "../scripts/ipv6-preflight-probe.ts";

test("the IPv6 preflight database query uses an already connected TLS socket", async () => {
  const database = new URL(process.env.DATABASE_URL ?? "");
  expect(["localhost", "127.0.0.1", "[::1]"]).toContain(database.hostname);
  const hostname = "postgres.invalid";
  const dir = await mkdtemp(join(tmpdir(), "ark-probe-tls-"));
  try {
    const keyPath = join(dir, "key.pem");
    const certPath = join(dir, "cert.pem");
    const certCommand = Bun.spawnSync(
      [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-days",
        "1",
        "-subj",
        `/CN=${hostname}`,
        "-keyout",
        keyPath,
        "-out",
        certPath,
      ],
      { stderr: "pipe" },
    );
    if (certCommand.exitCode !== 0) throw new Error(certCommand.stderr.toString());
    const [key, cert] = await Promise.all([readFile(keyPath), readFile(certPath)]);
    const connections = new Set<TLSSocket>();
    // Terminate TLS on loopback and forward the PostgreSQL protocol to the test database.
    const listener = createServer({ key, cert }, (client) => {
      connections.add(client);
      const upstream = createConnection({
        host: database.hostname.replace(/^\[|\]$/g, ""),
        port: Number(database.port || 5432),
      });
      client.on("error", () => upstream.destroy());
      client.once("close", () => {
        connections.delete(client);
        upstream.destroy();
      });
      upstream.on("error", () => client.destroy());
      client.pipe(upstream).pipe(client);
    });
    listener.listen(0, "::1");
    try {
      await once(listener, "listening");
      const address = listener.address();
      if (!address || typeof address === "string") throw new Error("Missing TLS fixture address.");
      const tls = connect({ host: "::1", port: address.port, servername: hostname, ca: cert });
      try {
        await once(tls, "secureConnect");
        expect(tls.authorized).toBe(true);
        await queryPostgresOverTls(tls, hostname, {
          username: decodeURIComponent(database.username),
          password: decodeURIComponent(database.password),
          database: decodeURIComponent(database.pathname.slice(1)),
        });
      } finally {
        tls.destroy();
      }
    } finally {
      for (const client of connections) client.destroy();
      await new Promise<void>((resolve) => listener.close(() => resolve()));
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
