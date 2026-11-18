// Test-only entry point for `mise run test:edge`. The harness bundles it with Bun.build and runs it
// in the pinned Bun container on the edge-control network of the disposable edge-ts/edge Compose
// project, where edge-ts carries the `edge-admin` alias for the Caddy in its namespace, so the apply
// goes through the production `writeEdge` as the domain worker does:
// render -> write ARK_EDGE_DIR/Caddyfile -> POST /adapt -> POST /load with must-revalidate.
// Caddy's admin API only accepts Host `edge-admin:2019`, which is why this cannot run on the host.
//
//   bun write-edge.js write '<writeEdge input JSON>'
//   bun write-edge.js write-routed '<writeEdge input JSON>' (also apply the HTTP SNI generation)
//   bun write-edge.js load-without-revalidate   (control: /adapt + /load without Cache-Control)
import { servedHttpHostnames, servedHttpRoutes } from "@ark-stack/shared";
import { writeEdgeL4 } from "../../server/src/modules/edge-l4.ts";
import { writeEdge } from "../../server/src/modules/providers.ts";

const [mode, input] = process.argv.slice(2);

if (mode === "write" || mode === "write-routed") {
  const plan = JSON.parse(input ?? "{}");
  const written = await writeEdge(plan);
  if (mode === "write-routed") {
    await writeEdgeL4({
      httpHostnames: servedHttpHostnames(plan),
      httpRoutes: servedHttpRoutes(plan),
    });
  }
  console.log(JSON.stringify(written));
} else if (mode === "load-without-revalidate") {
  const base = process.env.ARK_EDGE_RELOAD_URL ?? "";
  const caddyfile = await Bun.file(`${process.env.ARK_EDGE_DIR}/Caddyfile`).text();
  const adapted = await fetch(`${base}/adapt`, {
    method: "POST",
    headers: { "content-type": "text/caddyfile" },
    body: caddyfile,
  });
  if (!adapted.ok) throw new Error(`/adapt returned ${adapted.status}: ${await adapted.text()}`);
  const { result } = (await adapted.json()) as { result: unknown };
  const loaded = await fetch(`${base}/load`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(result),
  });
  if (!loaded.ok) throw new Error(`/load returned ${loaded.status}: ${await loaded.text()}`);
  console.log(JSON.stringify({ status: loaded.status }));
} else {
  throw new Error(`Unknown mode ${mode}`);
}
