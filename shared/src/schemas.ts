import { z } from "zod";

export const adminMode = z.enum(["public", "tailnet"]);
export const dnsProvider = z.enum(["manual", "cloudflare", "other"]);

export const hostname = z
  .string()
  .trim()
  .min(3)
  .max(253)
  .regex(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i);

export const wizardInput = z.object({
  adminMode,
  baseDomain: hostname,
  dnsProvider: dnsProvider.default("manual"),
  publicIpv4: z
    .string()
    .trim()
    .regex(/^(?:\d{1,3}\.){3}\d{1,3}$/),
  publicIpv6: z.string().trim().optional(),
  adminHostname: hostname.optional(),
  databaseHostname: hostname.optional(),
  mailHostname: hostname.optional(),
  includeDatabase: z.boolean().default(true),
  includeMail: z.boolean().default(true),
  firstDatabaseName: z
    .string()
    .trim()
    .regex(/^[a-z][a-z0-9_]{0,40}$/)
    .optional(),
  firstMailboxLocalPart: z.string().trim().min(1).max(64).optional(),
});

export const domainInput = z.object({
  name: hostname,
  mailFrom: hostname.optional(),
  dmarcPolicy: z.enum(["none", "quarantine", "reject"]).default("none"),
});

export const mailboxInput = z.object({
  domainId: z.string().min(1),
  localPart: z.string().trim().min(1).max(64),
  displayName: z.string().trim().min(1).max(120),
  quotaGb: z.coerce.number().int().min(1).max(1000).default(10),
});

export const aliasInput = z.object({
  domainId: z.string().min(1),
  localPart: z.string().trim().min(1).max(64),
  description: z.string().trim().max(200).optional(),
  targets: z.array(z.string().email()).min(1).max(20),
  allowExternal: z.boolean().default(false),
});

export const databaseInput = z.object({
  clusterId: z.string().optional(),
  name: z
    .string()
    .trim()
    .regex(/^[a-z][a-z0-9_]{0,40}$/),
  withTestDatabase: z.boolean().default(false),
  withPgvector: z.boolean().default(false),
  exposure: z.enum(["public", "private"]).default("public"),
  sourceCidrs: z.array(z.string()).default([]),
});

export const projectInput = z.object({
  name: z.string().trim().min(1).max(80),
  slug: z
    .string()
    .trim()
    .regex(/^[a-z][a-z0-9-]{0,40}$/),
});

export const serviceInput = z.object({
  projectId: z.string().min(1),
  name: z.string().trim().min(1).max(63),
  compose: z
    .string()
    .min(1)
    .max(64 * 1024),
  updatePolicy: z.enum(["notify", "auto_stateless"]).default("notify"),
});

export const sqlInput = z.object({
  databaseId: z.string().min(1),
  workspaceId: z.string().min(1),
  role: z.enum(["runtime", "readonly", "migration"]),
  sql: z.string().min(1).max(20_000),
  readOnly: z.boolean().default(true),
});

export const settingsInput = z.object({
  timezone: z.string().trim().min(1).max(80),
  defaultQuotaGb: z.coerce.number().int().min(1).max(1000),
  allowExternalForwarding: z.boolean().default(false),
});

export const cidrInput = z.object({
  sourceCidrs: z.array(z.string()).max(50),
});

export const adoptInput = z.object({
  projectId: z.string().min(1),
  name: z.string().trim().min(1).max(63),
  compose: z
    .string()
    .min(1)
    .max(64 * 1024),
  containerId: z.string().min(1),
});

export const deviceInput = z.object({
  label: z.string().trim().min(1).max(80),
});

export const queueActionInput = z.object({
  action: z.enum(["retry", "delete"]),
  item: z.object({
    id: z.string().min(1),
    recipient: z.string().min(1),
    sender: z.string().default(""),
    ageSeconds: z.number().int().nonnegative(),
    state: z.enum(["deferred", "queued", "bounce"]),
  }),
});

export const maintainInput = z.object({
  version: z.string().min(1),
  images: z.array(z.string()).min(1),
  digest: z.string().min(1),
  allowStateful: z.boolean().optional(),
});
