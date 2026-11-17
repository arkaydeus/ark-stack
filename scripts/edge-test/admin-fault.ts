// Test-only fault injector for `mise run test:edge` (FD-06). It sits between the edge watchdog and
// Caddy's admin API on edge-control and forwards requests to edge-admin:2019. By default it
// refuses POST /load; read mode refuses GET /config/ after /fault/enable. This exercises failed
// inspection as well as failed reload, with public traffic still live. Production has no fault switch.
const upstream = "http://edge-admin:2019";
let enabled = process.env.ARK_TEST_ADMIN_FAULT !== "read";

Bun.serve({
  hostname: "0.0.0.0",
  port: 2019,
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/fault/enable") {
      enabled = true;
      return new Response("ok");
    }
    if (
      enabled &&
      ((process.env.ARK_TEST_ADMIN_FAULT === "read" && url.pathname === "/config/") ||
        (process.env.ARK_TEST_ADMIN_FAULT !== "read" &&
          request.method === "POST" &&
          url.pathname === "/load"))
    ) {
      console.log(`refusing ${request.method} ${url.pathname}`);
      return new Response("injected admin failure", { status: 500 });
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
