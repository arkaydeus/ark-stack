// Test-only upstream for `mise run test:edge`. It runs inside the pinned Bun container on the
// disposable edge-test network (alias `upstream`) and stands in for a tailnet service.
// It deliberately emits headers that the edge must strip or rewrite (§3.5 of docs/design/front-door.md).

const leakyHeaders = {
  Server: "ark-test-upstream",
  "X-Powered-By": "ark-test-upstream",
};

Bun.serve({
  hostname: "0.0.0.0",
  port: 3000,
  fetch(request, server) {
    const url = new URL(request.url);
    switch (url.pathname) {
      case "/ws":
        if (server.upgrade(request)) return undefined;
        return new Response("WebSocket upgrade required", { status: 426 });
      case "/headers":
        // Echo exactly what reached the upstream so the edge test can inspect it.
        return Response.json(Object.fromEntries(request.headers), { headers: leakyHeaders });
      case "/auth":
        // forward_auth endpoint: approves every request and supplies the gate identity.
        return new Response(null, {
          status: 200,
          headers: { "X-Ark-User": "usr_gate_alice", "X-Ark-Email": "alice@example.com" },
        });
      case "/redirect": {
        const headers = new Headers(leakyHeaders);
        headers.set("Location", "http://home.tail1234.ts.net:3000/next?x=1#frag");
        headers.append("Set-Cookie", "sid=1; Path=/; Domain=home.tail1234.ts.net; HttpOnly");
        headers.append("Set-Cookie", "pref=dark; domain=.tail1234.ts.net; Secure; SameSite=Lax");
        return new Response(null, { status: 302, headers });
      }
      case "/redirect-ip":
        return new Response(null, {
          status: 302,
          headers: { ...leakyHeaders, Location: "//100.101.102.103:3000/ip-path" },
        });
      case "/redirect-external":
        return new Response(null, {
          status: 302,
          headers: { ...leakyHeaders, Location: "https://other.example.net/keep" },
        });
      case "/status/404":
        return new Response("upstream not found", { status: 404, headers: leakyHeaders });
      case "/status/500":
        return new Response("upstream failure", { status: 500, headers: leakyHeaders });
      default:
        return new Response("ok", { headers: leakyHeaders });
    }
  },
  websocket: {
    // No server pings and the maximum idle timeout, so "idle" really means no frames at all.
    sendPings: false,
    idleTimeout: 960,
    message(socket, message) {
      socket.send(message);
    },
  },
});

console.log("edge-test upstream listening on :3000");
