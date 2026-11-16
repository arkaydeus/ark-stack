import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { renderCaddyfile } from "@ark-stack/shared";

const image = "caddy:2.10.2@sha256:c3d7ee5d2b11f9dc54f947f68a734c84e9c9666c92c88a7f30b9cba5da182adb";
const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const directory = await mkdtemp(join(tmpdir(), `ark-edge-${suffix}-`));

async function validate(name: string, source: string) {
  const file = join(directory, `${name}.Caddyfile`);
  await Bun.write(file, source);
  const container = `ark-fix1-caddy-${name}-${suffix}`;
  const child = Bun.spawn(
    [
      "docker",
      "run",
      "--rm",
      "--name",
      container,
      "--volume",
      `${file}:/etc/caddy/Caddyfile:ro`,
      image,
      "caddy",
      "adapt",
      "--config",
      "/etc/caddy/Caddyfile",
      "--adapter",
      "caddyfile",
      "--validate",
    ],
    { stdout: "pipe", stderr: "pipe" },
  );
  const [status, stderr] = await Promise.all([child.exited, new Response(child.stderr).text()]);
  if (status !== 0) throw new Error(`${name} Caddy validation failed: ${stderr.slice(0, 2000)}`);
}

try {
  const publicConfig = renderCaddyfile({
    adminMode: "public",
    adminHostname: "admin.example.com",
    challengeDir: "/var/lib/ark/acme",
    apiUpstream: "api:3000",
  });
  const internal = publicConfig.indexOf("respond @internal 404");
  const browser = publicConfig.indexOf("reverse_proxy @browserApi");
  const unknown = publicConfig.indexOf("respond @unknownApi 404");
  const fallback = publicConfig.lastIndexOf("reverse_proxy api:3000");
  if (!(internal >= 0 && internal < browser && browser < unknown && unknown < fallback)) {
    throw new Error("Generated public route ordering does not preserve the deny boundary.");
  }
  await validate("generated-public", publicConfig);
  await validate(
    "generated-tailnet-edge",
    renderCaddyfile({ adminMode: "tailnet", challengeDir: "/var/lib/ark/acme", apiUpstream: "api:3000" }),
  );
  await validate("bootstrap-edge", await Bun.file(resolve("infra/platform/Caddyfile")).text());
  await validate("tailnet-gateway", await Bun.file(resolve("infra/platform/TailnetCaddyfile")).text());
  const design = Bun.spawn(["python3", new URL("./test-front-door-design.py", import.meta.url).pathname], {
    cwd: resolve(import.meta.dir, ".."),
    stdout: "inherit",
    stderr: "inherit",
  });
  if ((await design.exited) !== 0) throw new Error("Front-door design example checks failed.");
  console.log("Generated and static Caddy configurations validate with deny-first route ordering.");
} finally {
  await rm(directory, { recursive: true, force: true });
}
