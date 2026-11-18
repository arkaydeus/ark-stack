import { z } from "zod";

export const adminMode = z.enum(["public", "tailnet"]);
export const dnsProvider = z.enum(["manual", "cloudflare", "other"]);

export const hostname = z
  .string()
  .trim()
  .min(3)
  .max(253)
  .regex(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i);

const ipv4 = z
  .string()
  .trim()
  .refine((value) => {
    const parts = value.split(".");
    return (
      parts.length === 4 &&
      parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255)
    );
  }, "Enter a valid IPv4 address.");

const ipv6 = z
  .string()
  .trim()
  .refine((value) => {
    if (!value.includes(":")) return false;
    try {
      return new URL(`http://[${value}]/`).hostname.toLowerCase() === `[${value.toLowerCase()}]`;
    } catch {
      return false;
    }
  }, "Enter a valid IPv6 address.");

export const wizardInput = z.object({
  adminMode,
  baseDomain: hostname,
  dnsProvider: dnsProvider.default("manual"),
  publicIpv4: ipv4,
  publicIpv6: ipv6.optional(),
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
  dnsProvider: dnsProvider.default("manual"),
  mailFrom: hostname.optional(),
  dmarcPolicy: z.enum(["none", "quarantine", "reject"]).default("none"),
});

export const dnsPublishInput = z
  .object({
    planHash: z.string().regex(/^[a-f0-9]{64}$/),
    authorizeAAAAWithdrawal: z.literal(true).optional(),
    requestId: z.string().uuid().optional(),
  })
  .strict();

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

/**
 * Workload Compose projects are named `ark-<slug>`, which is the same namespace the platform's
 * own stacks live in (`ark-platform`, `ark-mail`, `ark-monitoring`, `ark-restore`). A project
 * using one of those slugs would make the agent run `docker compose up` against the control
 * plane itself, so the names are reserved.
 */
export const reservedProjectSlugs = ["platform", "mail", "monitoring", "restore", "control"] as const;

export const projectInput = z.object({
  name: z.string().trim().min(1).max(80),
  slug: z
    .string()
    .trim()
    .regex(/^[a-z][a-z0-9-]{0,40}$/)
    .refine((value) => !(reservedProjectSlugs as readonly string[]).includes(value), {
      message: "This project slug is reserved for platform stacks.",
    }),
});

export const serviceInput = z
  .object({
    projectId: z.string().min(1),
    name: z.string().trim().min(1).max(63),
    compose: z
      .string()
      .min(1)
      .max(64 * 1024),
    updatePolicy: z.enum(["notify", "auto_stateless"]).default("notify"),
    stateful: z.boolean().default(false),
  })
  .superRefine((value, context) => {
    if (value.stateful && value.updatePolicy === "auto_stateless") {
      context.addIssue({
        code: "custom",
        path: ["updatePolicy"],
        message: "Stateful services cannot use automatic stateless updates.",
      });
    }
  });

export const sqlInput = z.object({
  executionId: z.string().min(8).max(100),
  databaseId: z.string().min(1),
  workspaceId: z.string().min(1),
  role: z.enum(["runtime", "readonly", "migration"]),
  sql: z.string().min(1).max(20_000),
  readOnly: z.boolean().default(true),
});

export const sqlCancelInput = z.object({
  executionId: z.string().min(8).max(100),
  databaseId: z.string().min(1),
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
  containerId: z.string().regex(/^[a-f0-9]{12,64}$/i, "A Docker container ID is required."),
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
