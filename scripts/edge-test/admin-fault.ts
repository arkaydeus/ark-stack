// Test-only fault injector for `mise run test:edge` (FD-06). It sits between the edge watchdog and
// Caddy's admin API on edge-control and forwards every request to edge-admin:2019, except that
// `POST /load` fails. That makes a route withdrawal impossible to apply, so the test can show the
// watchdog's fallback: stop Caddy and raise an alert. Production code has no fault switch.
const upstream = "http://edge-admin:2019";

Bun.serve({
  hostname: "0.0.0.0",
  port: 2019,
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/load") {
      console.log("refusing POST /load");
      return new Response("injected load failure", { status: 500 });
    }
    console.log(`forwarding ${request.method} ${url.pathname}`);
    const response = await fetch(`${upstream}${url.pathname}${url.search}`, {
      method: request.method,
      headers: { "content-type": request.headers.get("content-type") ?? "application/json" },
      body: request.method === "GET" ? undefined : await request.text(),
    });
    return new Response(await response.text(), { status: response.status });
  },
});

console.log("admin fault injector on :2019");
