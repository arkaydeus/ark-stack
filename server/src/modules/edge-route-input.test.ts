import { expect, test } from "bun:test";
import { httpRoutesFor, type RouteRow, type NodeRow } from "./edge-route-input.ts";

const allowed = {
  id: "rt_home",
  kind: "http",
  hostname: "www.example.com",
  stableId: "nHOME",
  ip: "100.101.102.103",
  port: 3000,
};
const row: RouteRow = {
  id: allowed.id,
  kind: "http",
  accessMode: "public",
  bypassPaths: [],
  httpOptions: {},
  targetInput: "home.tail1234.ts.net",
  targetNodeStableId: allowed.stableId,
};
const node: NodeRow = {
  stableId: allowed.stableId,
  dnsName: "home.tail1234.ts.net",
  hostName: "home",
  ipv4: allowed.ip,
  ipv6: "fd7a:115c:a1e0::103",
};

test("skips absent rows, changed kinds and stable-ID mismatches", () => {
  expect(httpRoutesFor([allowed], [], [node])).toEqual([]);
  expect(httpRoutesFor([{ ...allowed, kind: "tcp" }], [row], [node])).toEqual([]);
  expect(httpRoutesFor([allowed], [{ ...row, kind: "tcp" }], [node])).toEqual([]);
  expect(httpRoutesFor([allowed], [{ ...row, targetNodeStableId: "replacement" }], [node])).toEqual([]);
});

test("ignores non-string redirectTo and extracts a string redirect without passing it as an option", () => {
  expect(httpRoutesFor([allowed], [{ ...row, httpOptions: { redirectTo: 42 } }], [node])[0]).toMatchObject({
    redirectTo: null,
    options: {},
  });
  expect(
    httpRoutesFor(
      [allowed],
      [{ ...row, httpOptions: { redirectTo: "example.com", upstreamHost: "public" } }],
      [node],
    )[0],
  ).toMatchObject({ redirectTo: "example.com", options: { upstreamHost: "public" } });
});

test("a missing observation uses only the stored target name, without invented addresses", () => {
  expect(httpRoutesFor([allowed], [row], [])[0]).toMatchObject({
    internalNames: [row.targetInput],
    internalIps: [],
  });
});

test("internalIps excludes empty and pinned addresses, retaining the other observed family", () => {
  expect(httpRoutesFor([allowed], [row], [node])[0]?.internalIps).toEqual([node.ipv6!]);
  expect(httpRoutesFor([allowed], [row], [{ ...node, ipv4: null, ipv6: "" }])[0]?.internalIps).toEqual([]);
  expect(httpRoutesFor([{ ...allowed, ip: node.ipv6! }], [row], [node])[0]?.internalIps).toEqual([
    node.ipv4!,
  ]);
});
