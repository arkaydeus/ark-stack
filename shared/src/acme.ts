import { createToken } from "./id.ts";

export type AcmeChallenge = {
  hostname: string;
  token: string;
  keyAuthorization: string;
  expiresAt: Date;
};

export function createHttp01Challenge(hostname: string, thumbprint: string): AcmeChallenge {
  const token = createToken(16);
  return {
    hostname,
    token,
    keyAuthorization: `${token}.${thumbprint}`,
    expiresAt: new Date(Date.now() + 15 * 60 * 1000),
  };
}

export function renewalDue(expiresAt: Date | null, now = new Date(), windowDays = 30) {
  if (!expiresAt) return true;
  return expiresAt.getTime() - now.getTime() <= windowDays * 24 * 60 * 60 * 1000;
}

export function legoArgs(input: {
  email: string;
  hostname: string;
  webroot: string;
  path: string;
  staging: boolean;
  action?: "run" | "renew";
}) {
  const args = [
    "--accept-tos",
    "--email",
    input.email,
    "--http",
    "--http.webroot",
    input.webroot,
    "--domains",
    input.hostname,
    "--path",
    input.path,
  ];
  if (input.staging) args.push("--server", "https://acme-staging-v02.api.letsencrypt.org/directory");
  args.push(input.action ?? "run");
  return args;
}
