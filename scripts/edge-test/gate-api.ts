// Test-only stand-in for the Ark API behind the edge (`api:3000`) in `scripts/test-edge-gate.ts`
// (FD-11, docs/design/front-door.md §3.9). It records every request it receives (`GET /__seen`,
// which the harness reads from inside the container) and answers the gate's edge handlers with the
// production policy from shared/src/gate.ts: the Origin/CSRF decision, the redirect-or-401 rule, the
// raw-URI bypass guard. Sessions are fixed tokens from `GATE_SESSIONS`; the real session store is
// covered by server/src/gate-handshake.suite.ts against PostgreSQL.
//
// Every handler requires the genuine `X-Ark-Edge-Token`, so a request that arrives without it (or
// with a client-forged one) shows up as a 401.

import {
  GATE_COOKIE,
  bypassMatches,
  checkRawRequestUri,
  gateOriginDecision,
  gateWantsRedirect,
  parseCookies,
} from "../../shared/src/gate.ts";

type Route = { host: string; bypassPaths: string[]; allowedOrigins: string[] };
type Session = { user: string; email: string; routes: string[] };

const token = process.env.ARK_EDGE_GATE_TOKEN ?? "";
const routes = JSON.parse(process.env.GATE_ROUTES ?? "{}") as Record<string, Route>;
const sessions = JSON.parse(process.env.GATE_SESSIONS ?? "{}") as Record<string, Session>;
const loginHost = process.env.GATE_LOGIN_HOST ?? "login.example.com";

type Seen = { method: string; uri: string; host: string; token: boolean; headers: Record<string, string> };
const seen: Seen[] = [];

Bun.serve({
  hostname: "0.0.0.0",
  port: 3000,
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/__seen") return Response.json(seen);
    const host = request.headers.get("host") ?? "";
    const genuine = Boolean(token) && request.headers.get("x-ark-edge-token") === token;
    seen.push({
      method: request.method,
      uri: `${url.pathname}${url.search}`,
      host,
      token: genuine,
      headers: Object.fromEntries(request.headers),
    });
    if (!genuine) return new Response("edge token missing or wrong", { status: 401 });
    const route = routes[url.searchParams.get("route") ?? request.headers.get("x-ark-route") ?? ""];
    switch (url.pathname) {
      case "/api/gate/check": {
        if (!route || route.host !== host) return new Response(null, { status: 403 });
        const routeId = url.searchParams.get("route")!;
        const tokens = parseCookies(request.headers.get("cookie")).get(GATE_COOKIE) ?? [];
        const session = tokens.length === 1 ? sessions[tokens[0]!] : undefined;
        const method = request.headers.get("x-forwarded-method") ?? "GET";
        const upgrade = request.headers.get("x-ark-upgrade") || request.headers.get("upgrade");
        if (session?.routes.includes(routeId)) {
          const decision = gateOriginDecision({
            method,
            origin: request.headers.get("origin"),
            upgrade,
            routeHost: route.host,
            allowedOrigins: route.allowedOrigins,
          });
          if (!decision.ok) return new Response(decision.reason, { status: 403 });
          return new Response(null, {
            status: 204,
            headers: {
              "X-Ark-User": session.user,
              "X-Ark-Email": session.email,
              "Cache-Control": "no-store",
            },
          });
        }
        if (gateWantsRedirect({ method, accept: request.headers.get("accept"), upgrade })) {
          const location = new URL(`https://${loginHost}/gate/authorize`);
          location.searchParams.set("route", routeId);
          location.searchParams.set("state", "S".repeat(22));
          location.searchParams.set("rd", request.headers.get("x-forwarded-uri") ?? "/");
          return new Response(null, {
            status: 302,
            headers: {
              Location: location.toString(),
              "Set-Cookie": `__Host-ark_gate_state=${"S".repeat(22)}; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax`,
            },
          });
        }
        return new Response(null, { status: 401, headers: { "WWW-Authenticate": "Ark-Gate" } });
      }
      case "/api/gate/bypass-check": {
        if (!route || route.host !== host) return new Response(null, { status: 400 });
        const checked = checkRawRequestUri(request.headers.get("x-ark-original-uri"));
        return new Response(null, {
          status: checked.ok && bypassMatches(checked.path, route.bypassPaths) ? 204 : 400,
        });
      }
      case "/api/gate/callback":
      case "/api/gate/logout-route":
        return Response.json({
          handler: url.pathname,
          uri: `${url.pathname}${url.search}`,
          method: request.method,
          route: request.headers.get("x-ark-route"),
        });
      default:
        return Response.json({ unexpected: url.pathname }, { status: 404 });
    }
  },
});

console.log("gate api stand-in listening on :3000");
