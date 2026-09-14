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
  route {
    @internal path /api/internal/* /api/metrics/prometheus /api/platform/maintain
    respond @internal 404
    @browserApi path /api/auth/* /api/setup/status /api/state /api/me /api/wizard /api/step-up /api/domains* /api/projects* /api/databases* /api/mailboxes* /api/aliases* /api/services* /api/sql/* /api/mail/* /api/devices/* /api/backups* /api/ses/* /api/updates/* /api/import/* /api/alerts/* /api/settings* /api/metrics
    reverse_proxy @browserApi ${input.apiUpstream} {
      header_up -X-Forwarded-Host
      header_up X-Forwarded-Proto https
      header_up Host ${input.adminHostname}
    }
    @unknownApi path /api/*
    respond @unknownApi 404
    reverse_proxy ${input.apiUpstream}
  }
}
`
      : "";
  return `{
  admin 0.0.0.0:2019
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
