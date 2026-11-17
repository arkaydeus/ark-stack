// Test double for the edge node's LocalAPI (front door FD-06). It speaks raw HTTP/1.1 on a unix
// socket, as tailscaled does, so tests exercise the production client unchanged: `GET
// /localapi/v0/status` returns the configured view, `POST /localapi/v0/dial` answers `101` only for
// reachable `ip:port` pairs (a tailnet grant), and every other endpoint is refused with 403 like a
// read-only caller. Used by server tests and `mise run test:edge`; never by production code.
import { rm } from "node:fs/promises";

import { backendKey } from "@ark-stack/shared";

export type MockPeer = {
  id: string;
  name: string;
  ips: string[];
  tags?: string[];
  online?: boolean;
};

export type MockLocalApiState = {
  backendState: string;
  suffix: string;
  self: MockPeer;
  peers: MockPeer[];
  /** `ip:port` pairs (canonical, IPv6 bracketed) a dial may reach. */
  reachable: Set<string>;
  /** Overrides the status answer: an HTTP status code, a raw body, or a closed connection. */
  statusFault?: { code?: number; body?: string; close?: boolean };
};

function statusNode(peer: MockPeer, suffix: string) {
  return {
    ID: peer.id,
    HostName: peer.name,
    DNSName: `${peer.name}${suffix}.`,
    TailscaleIPs: peer.ips,
    Tags: peer.tags,
    Online: peer.online ?? true,
  };
}

export function mockStatusDocument(state: MockLocalApiState) {
  return {
    Version: "1.86.2-mock",
    BackendState: state.backendState,
    Self: statusNode(state.self, state.suffix),
    Peer: Object.fromEntries(
      state.peers.map((peer, index) => [`nodekey:${index}`, statusNode(peer, state.suffix)]),
    ),
    CurrentTailnet: {
      Name: "example",
      MagicDNSSuffix: state.suffix.replace(/^\./, ""),
      MagicDNSEnabled: true,
    },
  };
}

type Socket = { write(data: string): number; end(): void };

const HANDLED = "\0handled";

function respond(socket: Socket, code: number, reason: string, body: string, type = "text/plain") {
  socket.write(
    `HTTP/1.1 ${code} ${reason}\r\nContent-Type: ${type}\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
  );
  socket.end();
}

export class MockLocalApi {
  readonly calls: string[] = [];
  private listener?: { stop(force?: boolean): void };

  constructor(public state: MockLocalApiState) {}

  async listen(path: string) {
    await rm(path, { force: true });
    const buffers = new WeakMap<object, string>();
    this.listener = Bun.listen({
      unix: path,
      socket: {
        data: (socket, chunk) => {
          const previous = buffers.get(socket) ?? "";
          if (previous === HANDLED) return;
          const buffer = previous + chunk.toString("latin1");
          if (!buffer.includes("\r\n\r\n")) {
            buffers.set(socket, buffer);
            return;
          }
          buffers.set(socket, HANDLED);
          this.handle(socket, buffer);
        },
      },
    });
    return path;
  }

  private handle(socket: Socket, request: string) {
    const [head = ""] = request.split("\r\n\r\n");
    const [line = "", ...headerLines] = head.split("\r\n");
    const [method = "", target = ""] = line.split(" ");
    const headers = Object.fromEntries(
      headerLines.map((header) => {
        const index = header.indexOf(":");
        return [header.slice(0, index).trim().toLowerCase(), header.slice(index + 1).trim()];
      }),
    );
    const path = target.split("?")[0];
    this.calls.push(`${method} ${path}`);
    if (method === "GET" && path === "/localapi/v0/status") {
      const fault = this.state.statusFault;
      if (fault?.close) return socket.end();
      if (fault?.code) return respond(socket, fault.code, "Error", fault.body ?? "failure");
      if (fault?.body !== undefined) return respond(socket, 200, "OK", fault.body, "application/json");
      return respond(socket, 200, "OK", JSON.stringify(mockStatusDocument(this.state)), "application/json");
    }
    if (method === "POST" && path === "/localapi/v0/dial") {
      const key = backendKey(headers["dial-host"] ?? "", Number(headers["dial-port"]));
      this.calls.push(`dial ${key}`);
      if (this.state.reachable.has(key)) {
        socket.write("HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: ts-dial\r\n\r\n");
        return;
      }
      return respond(socket, 502, "Bad Gateway", `dial failure: dial tcp ${key}: i/o timeout`);
    }
    return respond(socket, 403, "Forbidden", "access denied");
  }

  stop() {
    this.listener?.stop(true);
  }
}
