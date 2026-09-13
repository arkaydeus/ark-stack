import type { AdminMode } from "./dns-plan.ts";

export function renderCaddyfile(input: {
  adminMode: AdminMode;
  adminHostname?: string;
  challengeDir: string;
  apiUpstream: string;
  appRoutes?: Array<{ hostname: string; upstream: string }>;
}) {
  const routes = (input.appRoutes ?? [])
    .map(
      (route) => `${route.hostname} {
  reverse_proxy ${route.upstream}
}
`,
    )
    .join("\n");
  const admin =
    input.adminMode === "public" && input.adminHostname
      ? `${input.adminHostname} {
  encode gzip
  reverse_proxy ${input.apiUpstream}
}
`
      : "";
  return `{
  admin off
}

:80 {
  @challenge path /.well-known/acme-challenge/*
  handle @challenge {
    root * ${input.challengeDir}
    file_server
  }
  handle {
    respond "Ark Stack challenge edge" 404
  }
}

${admin}${routes}`;
}

export function renderTailscaleServe(upstream = "http://127.0.0.1:8080") {
  return {
    TCP: { "443": { HTTPS: true } },
    Web: {
      "${TS_CERT_DOMAIN}:443": {
        Handlers: {
          "/": { Proxy: upstream },
        },
      },
    },
    AllowFunnel: {},
  };
}

export function funnelDisabled(config: { AllowFunnel?: Record<string, unknown> }) {
  return !config.AllowFunnel || Object.keys(config.AllowFunnel).length === 0;
}
