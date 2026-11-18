import { type FormEvent, type ReactNode, useState } from "react";

import { Badge, statusVariant } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/input";
import type { PlatformState } from "@/lib/types";
import { act, api, formatDate } from "@/lib/utils";

import { InlineError } from "./Auth";
import { BackupTargetsPanel } from "./BackupTargets";
import { DnsReviewPanel } from "./DnsReview";

export function Overview({ state, reload }: { state: PlatformState; reload: () => Promise<void> }) {
  return (
    <div className="space-y-5">
      <section className="rounded-2xl border border-border bg-card p-6">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-primary">Host posture</p>
        <h2 className="display mt-2 text-3xl">{state.settings?.baseDomain ?? "Awaiting domain wizard"}</h2>
        <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
          Admin mode is {state.settings?.adminMode ?? "unset"}. Database and mail exposure stay independent of
          that choice. Operations survive API restarts.
        </p>
      </section>
      <section className="metric-grid">
        <Metric label="Domains" value={state.domains.length} detail="ownership and DNS" />
        <Metric
          label="Databases"
          value={state.databases.length}
          detail="generated roles, no superuser examples"
        />
        <Metric label="Mailboxes" value={state.mailboxes.length} detail="inbound independent of SES" />
        <Metric label="Services" value={state.services.length} detail="policy-checked compose" />
      </section>
      <div className="content-grid">
        <Card>
          <CardHeader>
            <CardTitle>Latest operations</CardTitle>
            <CardDescription>Queued work is not a success. Watch the step history.</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {state.operations.slice(0, 8).map((item) => (
              <div className="table-row grid-cols-[8rem_1fr_auto]" key={item.id}>
                <Badge variant={statusVariant(item.status)}>{item.status}</Badge>
                <div>
                  <strong>{item.kind}</strong>
                  <p className="text-xs text-muted-foreground">{item.error ?? formatDate(item.createdAt)}</p>
                </div>
              </div>
            ))}
            {!state.operations.length && <Empty>No operations yet.</Empty>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Alerts</CardTitle>
            <CardDescription>Stale observations are unknown, not healthy.</CardDescription>
          </CardHeader>
          <CardContent>
            {state.alerts.length ? (
              state.alerts.map((alert) => (
                <div className="mb-3 flex items-center justify-between gap-3" key={alert.id}>
                  <p>
                    <Badge variant={statusVariant(alert.resolvedAt ? "ready" : alert.severity)}>
                      {alert.resolvedAt ? "resolved" : alert.severity}
                    </Badge>{" "}
                    {alert.title}
                  </p>
                  {!alert.resolvedAt && (
                    <div className="flex gap-2">
                      {!alert.acknowledged && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            act(
                              api(`/api/alerts/${alert.id}/ack`, {
                                method: "POST",
                                body: "{}",
                              }),
                              reload,
                            )
                          }
                        >
                          Ack
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() =>
                          act(
                            api(`/api/alerts/${alert.id}/silence`, {
                              method: "POST",
                              body: JSON.stringify({ minutes: 60 }),
                            }),
                            reload,
                          )
                        }
                      >
                        Silence 1h
                      </Button>
                    </div>
                  )}
                </div>
              ))
            ) : (
              <p className="text-sm text-muted-foreground">No firing alerts.</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Metric({ label, value, detail }: { label: string; value: number; detail: string }) {
  return (
    <Card>
      <CardContent>
        <p className="text-xs uppercase tracking-[0.16em] text-muted-foreground">{label}</p>
        <strong className="display mt-2 block text-3xl">{value}</strong>
        <span className="text-sm text-muted-foreground">{detail}</span>
      </CardContent>
    </Card>
  );
}

export function DomainsView({ state, reload }: { state: PlatformState; reload: () => Promise<void> }) {
  const [openReview, setOpenReview] = useState<string | null>(null);
  return (
    <div className="space-y-5">
      {state.domains.map((domain) => (
        <Card key={domain.id}>
          <CardHeader className="flex items-start justify-between gap-4">
            <div>
              <CardTitle>{domain.name}</CardTitle>
              <CardDescription>
                Review the records for this domain and check public DNS before certificates are requested.
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant={statusVariant(domain.status)}>{domain.status}</Badge>
              {state.user.role !== "viewer" && (
                <Button
                  size="sm"
                  variant="outline"
                  aria-expanded={openReview === domain.id}
                  onClick={() => setOpenReview(openReview === domain.id ? null : domain.id)}
                >
                  {openReview === domain.id ? "Close DNS review" : "Review DNS"}
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {openReview === domain.id ? (
              <DnsReviewPanel
                reviewPath={"/api/domains/" + domain.id + "/dns"}
                owner={state.user.role === "owner"}
                reload={reload}
              />
            ) : (
              domain.records.map((record) => (
                <div className="rounded-lg border border-border p-3 text-sm" key={record.id}>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="mono">
                      {record.type} {record.relativeName}
                    </span>
                    <Badge variant={statusVariant(record.status)}>{record.status}</Badge>
                  </div>
                  <p className="mt-1 text-muted-foreground">{record.purpose}</p>
                  <code className="mt-2 block break-all text-xs">{record.expectedValue}</code>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      ))}
      <Card>
        <CardHeader>
          <CardTitle>Endpoints</CardTitle>
          <CardDescription>
            Public or private policy is per endpoint, not inherited from admin mode.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {state.endpoints.map((item) => (
            <div className="table-row grid-cols-4" key={item.id}>
              <strong>{item.hostname}</strong>
              <span>{item.kind}</span>
              <span>{item.exposure}</span>
              <Badge variant={statusVariant(item.status)}>{item.status}</Badge>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

export function ProjectsView({ state, reload }: { state: PlatformState; reload: () => Promise<void> }) {
  return (
    <FormCard
      title="Projects"
      description="A project groups compose services with optional attached databases."
      onSubmit={async (form) => {
        await api("/api/projects", {
          method: "POST",
          body: JSON.stringify({ name: form.get("name"), slug: form.get("slug") }),
        });
        await reload();
      }}
    >
      <Field label="Name" name="name" required />
      <Field label="Slug" name="slug" placeholder="shop" required />
      <div className="pt-4">
        {state.projects.map((project) => (
          <div className="table-row grid-cols-2" key={project.id}>
            <strong>{project.name}</strong>
            <span className="mono text-sm">{project.slug}</span>
          </div>
        ))}
      </div>
    </FormCard>
  );
}

async function waitForDatabaseResult(operationId: string) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    const result = await api<{
      status: string;
      available: boolean;
      error?: string;
      query?: {
        rows: unknown[];
        fingerprint: string;
        role: string;
        databaseId: string;
        truncated: boolean;
        bytes: number;
      };
      schema?: { schemas: Record<string, Record<string, unknown[]>> };
    }>(`/api/sql/results/${operationId}`);
    if (result.available) return result;
    if (["failed", "cancelled", "needs_recovery"].includes(result.status)) {
      throw new Error(result.error || "Database worker operation failed.");
    }
  }
  throw new Error("Database operation is still queued; check Operations for progress.");
}

export function DatabasesView({ state, reload }: { state: PlatformState; reload: () => Promise<void> }) {
  const [secret, setSecret] = useState<string>("");
  const [schemaOutput, setSchemaOutput] = useState<Record<string, string>>({});
  const [queryOutput, setQueryOutput] = useState<
    Record<string, { role: string; fingerprint: string; rows: unknown[]; truncated: boolean; bytes: number }>
  >({});
  return (
    <div className="space-y-5">
      <FormCard
        title="Create a database"
        description="Migration and runtime roles are generated. Public pooled access uses verify-full examples."
        onSubmit={async (form) => {
          await api("/api/databases", {
            method: "POST",
            body: JSON.stringify({
              name: form.get("name"),
              exposure: form.get("exposure"),
              withPgvector: form.has("withPgvector"),
              withTestDatabase: form.has("withTestDatabase"),
              sourceCidrs: String(form.get("sourceCidrs") ?? "")
                .split(",")
                .map((item) => item.trim())
                .filter(Boolean),
            }),
          });
          await reload();
        }}
      >
        <Field label="Name" name="name" placeholder="orders" required />
        <div>
          <label className="mb-1.5 block text-xs font-semibold">Exposure</label>
          <select name="exposure" className="select">
            <option value="public">Public TLS</option>
            <option value="private">Private only</option>
          </select>
        </div>
        <Field label="Source CIDRs" name="sourceCidrs" placeholder="optional, comma-separated" />
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" name="withPgvector" /> pgvector
        </label>
      </FormCard>
      <Card>
        <CardContent className="p-0">
          {state.databases.map((item) => (
            <div className="table-row grid-cols-[1fr_auto_auto_auto]" key={item.id}>
              <div>
                <strong>{item.name}</strong>
                <p className="text-xs text-muted-foreground">
                  {item.roles.map((role) => role.kind).join(", ")}
                </p>
              </div>
              <Badge variant={statusVariant(item.status)}>{item.status}</Badge>
              <span>{item.exposure}</span>
              <div className="flex flex-wrap gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    void api<{ connectionString: string }>(`/api/databases/${item.id}/credential`, {
                      method: "POST",
                      body: "{}",
                    })
                      .then((result) => setSecret(result.connectionString))
                      .catch((cause: Error) => setSecret(cause.message))
                  }
                >
                  Reveal runtime once
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() =>
                    act(
                      api(`/api/databases/${item.id}/rotate`, {
                        method: "POST",
                        body: JSON.stringify({ kind: "runtime" }),
                      }),
                      reload,
                    )
                  }
                >
                  Rotate runtime
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    setSchemaOutput((current) => ({ ...current, [item.id]: "Schema inspection queued…" }));
                    void api<{ operationId: string }>(`/api/databases/${item.id}/schema`, {
                      method: "POST",
                      body: "{}",
                    })
                      .then((queued) => waitForDatabaseResult(queued.operationId))
                      .then((result) =>
                        setSchemaOutput((current) => ({
                          ...current,
                          [item.id]: JSON.stringify(result.schema?.schemas ?? {}),
                        })),
                      )
                      .catch((error) =>
                        setSchemaOutput((current) => ({
                          ...current,
                          [item.id]: error instanceof Error ? error.message : "Schema inspection failed.",
                        })),
                      );
                  }}
                >
                  Schema
                </Button>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
      {secret && (
        <Card>
          <CardContent>
            <p className="text-sm text-muted-foreground">Copy now. This response is no-store and one-time.</p>
            <code className="mt-2 block break-all text-xs">{secret}</code>
          </CardContent>
        </Card>
      )}
      {Object.entries(schemaOutput).map(([databaseId, output]) => (
        <Card key={databaseId}>
          <CardContent>
            <p className="text-sm font-semibold">
              Schema · {state.databases.find((item) => item.id === databaseId)?.name ?? databaseId}
            </p>
            <code className="mt-2 block max-h-64 overflow-auto whitespace-pre-wrap text-xs">{output}</code>
          </CardContent>
        </Card>
      ))}
      <FormCard
        title="SQL workspace"
        description="Bound to one database and role. Read-only by default. Results stay with this workspace."
        onSubmit={async (form) => {
          const databaseId = String(form.get("databaseId"));
          const role = String(form.get("role"));
          const sql = String(form.get("sql"));
          const executionId = crypto.randomUUID();
          const queued = await api<{
            operationId: string;
          }>("/api/sql/query", {
            method: "POST",
            body: JSON.stringify({
              executionId,
              databaseId,
              workspaceId: databaseId,
              role,
              sql,
              readOnly: form.has("readOnly"),
            }),
          });
          const completed = await waitForDatabaseResult(queued.operationId);
          if (!completed.query) throw new Error("Database worker returned no query result.");
          const result = completed.query;
          setQueryOutput((current) => ({
            ...current,
            [databaseId]: {
              role: result.role,
              fingerprint: result.fingerprint,
              rows: result.rows,
              truncated: result.truncated,
              bytes: result.bytes,
            },
          }));
        }}
      >
        <div>
          <label className="mb-1.5 block text-xs font-semibold">Database</label>
          <select name="databaseId" className="select" required>
            {state.databases.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1.5 block text-xs font-semibold">Role</label>
          <select name="role" className="select">
            <option value="readonly">readonly</option>
            <option value="runtime">runtime</option>
            <option value="migration">migration</option>
          </select>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" name="readOnly" defaultChecked /> Read-only transaction
        </label>
        <div className="md:col-span-2">
          <label className="mb-1.5 block text-xs font-semibold">SQL</label>
          <textarea
            name="sql"
            className="min-h-28 w-full rounded-lg border border-input bg-background p-3 font-mono text-xs"
            defaultValue="select current_user, current_database()"
          />
        </div>
      </FormCard>
      {Object.entries(queryOutput).map(([databaseId, output]) => (
        <Card key={databaseId}>
          <CardContent>
            <p className="text-sm font-semibold">
              Results · {output.role}@
              {state.databases.find((item) => item.id === databaseId)?.name ?? databaseId}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              {output.fingerprint} · {output.bytes} bytes
              {output.truncated ? " · truncated at server limit" : ""}
            </p>
            <code className="mt-2 block max-h-64 overflow-auto whitespace-pre-wrap text-xs">
              {JSON.stringify(output.rows)}
            </code>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

export function EmailView({ state, reload }: { state: PlatformState; reload: () => Promise<void> }) {
  const domainId = state.domains[0]?.id;
  const [password, setPassword] = useState("");
  return (
    <div className="space-y-5">
      <div className="metric-grid">
        {state.mailDomains.map((item) => (
          <Card key={item.id}>
            <CardContent>
              <p>Inbound {item.inboundStatus}</p>
              <p>Outbound {item.outboundStatus}</p>
              <p>Client {item.clientStatus}</p>
              <p className="mt-2 text-xs text-muted-foreground">
                SES {state.providers?.ses ? "credentials present" : "not configured"} · Stalwart{" "}
                {state.providers?.stalwart ? "reachable config" : "desired-state only"}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>
      <div className="flex flex-wrap gap-2">
        {state.mailboxes[0] && (
          <Button
            variant="outline"
            onClick={() =>
              act(
                api("/api/mail/reconcile", {
                  method: "POST",
                  body: JSON.stringify({ mailboxId: state.mailboxes[0].id }),
                }),
                reload,
              )
            }
          >
            Reconcile Stalwart
          </Button>
        )}
        {state.domains[0] && (
          <Button
            variant="outline"
            onClick={() =>
              act(
                api("/api/ses/reconcile", {
                  method: "POST",
                  body: JSON.stringify({ domainId: state.domains[0].id }),
                }),
                reload,
              )
            }
          >
            Reconcile SES
          </Button>
        )}
      </div>
      <FormCard
        title="Add mailbox"
        description="Portal login and mailbox passwords stay separate."
        onSubmit={async (form) => {
          await api("/api/mailboxes", {
            method: "POST",
            body: JSON.stringify({
              domainId,
              localPart: form.get("localPart"),
              displayName: form.get("displayName"),
              quotaGb: Number(form.get("quotaGb") || 10),
            }),
          });
          await reload();
        }}
      >
        <Field label="Local part" name="localPart" required />
        <Field label="Display name" name="displayName" required />
        <Field label="Quota GB" name="quotaGb" type="number" defaultValue={10} />
      </FormCard>
      <Card>
        <CardContent className="p-0">
          {state.mailboxes.map((item) => (
            <div className="table-row grid-cols-[1fr_auto_auto]" key={item.id}>
              <div>
                <strong>{item.address}</strong>
                <p className="text-xs text-muted-foreground">{item.displayName}</p>
              </div>
              <Badge variant={statusVariant(item.lifecycle)}>{item.lifecycle}</Badge>
              <div className="flex gap-2">
                {item.credentialAvailable && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() =>
                      void api<{ password: string }>(`/api/mailboxes/${item.id}/credential`, {
                        method: "POST",
                        body: "{}",
                      }).then((result) => setPassword(result.password))
                    }
                  >
                    View once
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() =>
                    act(
                      api(`/api/mailboxes/${item.id}/lifecycle`, {
                        method: "POST",
                        body: JSON.stringify({
                          lifecycle: item.lifecycle === "suspended" ? "active" : "suspended",
                        }),
                      }),
                      reload,
                    )
                  }
                >
                  {item.lifecycle === "suspended" ? "Resume" : "Suspend"}
                </Button>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
      <FormCard
        title="Add alias"
        description="Loops and collisions are rejected before save."
        onSubmit={async (form) => {
          await api("/api/aliases", {
            method: "POST",
            body: JSON.stringify({
              domainId,
              localPart: form.get("localPart"),
              targets: String(form.get("targets"))
                .split(",")
                .map((item) => item.trim())
                .filter(Boolean),
            }),
          });
          await reload();
        }}
      >
        <Field label="Local part" name="localPart" required />
        <Field label="Targets" name="targets" placeholder="a@example.com, b@example.com" required />
      </FormCard>
      {state.aliases.map((item) => (
        <div key={item.id} className="flex items-center justify-between gap-3 text-sm">
          <span>
            {item.address} → {item.targets.join(", ")}{" "}
            <Badge variant={statusVariant(item.status)}>{item.status}</Badge>
          </span>
          {item.status === "active" && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                if (!window.confirm(`Delete alias ${item.address}? This requires a recent delete step-up.`))
                  return;
                act(
                  api(`/api/aliases/${item.id}`, {
                    method: "DELETE",
                    body: JSON.stringify({}),
                  }),
                  reload,
                );
              }}
            >
              Delete
            </Button>
          )}
        </div>
      ))}
      {password && <code className="block rounded-lg border border-border p-3 text-xs">{password}</code>}
      <FormCard
        title="Device credential"
        description="Creates a native Stalwart app password. Reveal it once after the operation succeeds."
        onSubmit={async (form) => {
          await api(`/api/mailboxes/${form.get("mailboxId")}/devices`, {
            method: "POST",
            body: JSON.stringify({ label: form.get("label") }),
          });
          await reload();
        }}
      >
        <div>
          <label className="mb-1.5 block text-xs font-semibold">Mailbox</label>
          <select name="mailboxId" className="select" required>
            {state.mailboxes.map((item) => (
              <option key={item.id} value={item.id}>
                {item.address}
              </option>
            ))}
          </select>
        </div>
        <Field label="Device label" name="label" placeholder="phone" required />
      </FormCard>
      {(state.devices ?? []).map((item) => (
        <div className="flex items-center justify-between text-sm" key={item.id}>
          <span>
            {item.label} {item.revokedAt ? "(revoked)" : ""}
          </span>
          {!item.revokedAt && (
            <div className="flex gap-2">
              {item.secretId && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    void api<{ password: string }>(`/api/devices/${item.id}/credential`, {
                      method: "POST",
                      body: "{}",
                    }).then((result) => setPassword(result.password))
                  }
                >
                  Reveal once
                </Button>
              )}
              <Button
                size="sm"
                variant="ghost"
                onClick={() =>
                  act(api(`/api/devices/${item.id}/revoke`, { method: "POST", body: "{}" }), reload)
                }
              >
                Revoke
              </Button>
            </div>
          )}
        </div>
      ))}
      <Button
        variant="outline"
        onClick={() =>
          void api<{ items: Array<{ id: string; recipient: string; state: string; ageSeconds: number }> }>(
            "/api/mail/queue",
          ).then((result) =>
            setPassword(
              result.items.map((item) => `${item.state} ${item.recipient} ${item.ageSeconds}s`).join("\n") ||
                "Queue empty",
            ),
          )
        }
      >
        Refresh mail queue
      </Button>
    </div>
  );
}

const SAMPLE_COMPOSE = `services:
  demo:
    image: docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    ports:
      - "8088:80"
`;

async function observeService(id: string, kind: "logs" | "stats") {
  const queued = await api<{ operationId: string }>(`/api/services/${id}/observe`, {
    method: "POST",
    body: JSON.stringify({ kind }),
  });
  for (let attempt = 0; attempt < 40; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    const result = await api<{
      status: string;
      available: boolean;
      error?: string;
      lines?: string[];
      stats?: Record<string, unknown>;
    }>(`/api/services/${id}/observations/${queued.operationId}`);
    if (result.available) return result;
    if (["failed", "cancelled", "needs_recovery"].includes(result.status)) {
      throw new Error(result.error || `Service ${kind} observation failed.`);
    }
  }
  throw new Error(`Service ${kind} observation is still queued; check Operations for progress.`);
}

async function discoverServices() {
  const queued = await api<{ operationId: string }>("/api/services/discover", {
    method: "POST",
    body: "{}",
  });
  for (let attempt = 0; attempt < 40; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    const result = await api<{
      status: string;
      available: boolean;
      error?: string;
      unmanaged?: Array<{ name: string; image: string }>;
    }>(`/api/services/discovery/${queued.operationId}`);
    if (result.available) return result.unmanaged ?? [];
    if (["failed", "cancelled", "needs_recovery"].includes(result.status)) {
      throw new Error(result.error || "Host discovery failed.");
    }
  }
  throw new Error("Host discovery is still queued; check Operations for progress.");
}

export function ServicesView({ state, reload }: { state: PlatformState; reload: () => Promise<void> }) {
  const projectId = state.projects[0]?.id;
  const [logs, setLogs] = useState("");
  return (
    <div className="space-y-5">
      <FormCard
        title="Register a service"
        description="The agent rejects sockets, privileged mode, host namespaces, and floating latest tags."
        onSubmit={async (form) => {
          await api("/api/services", {
            method: "POST",
            body: JSON.stringify({
              projectId,
              name: form.get("name"),
              compose: form.get("compose"),
              stateful: form.get("stateful") === "on",
            }),
          });
          await reload();
        }}
      >
        <Field label="Service name" name="name" defaultValue="demo" required />
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" name="stateful" />
          This workload owns persistent application data
        </label>
        <div className="md:col-span-2">
          <label className="mb-1.5 block text-xs font-semibold">Approved Compose subset</label>
          <textarea
            name="compose"
            className="min-h-40 w-full rounded-lg border border-input bg-background p-3 font-mono text-xs"
            defaultValue={SAMPLE_COMPOSE}
          />
        </div>
      </FormCard>
      <Card>
        <CardContent className="p-0">
          {state.services.map((item) => (
            <div className="table-row grid-cols-[1fr_auto_auto_auto_auto]" key={item.id}>
              <div>
                <strong>{item.name}</strong>
                <p className="text-xs text-muted-foreground">
                  {item.status} · {item.stateful ? "stateful" : "stateless"} · observed{" "}
                  {formatDate(item.observedAt)}
                </p>
              </div>
              <Button
                size="sm"
                onClick={() =>
                  act(api(`/api/services/${item.id}/restart`, { method: "POST", body: "{}" }), reload)
                }
              >
                Restart
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() =>
                  act(api(`/api/services/${item.id}/stop`, { method: "POST", body: "{}" }), reload)
                }
              >
                Stop
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  setLogs("Log observation queued…");
                  void observeService(item.id, "logs")
                    .then((result) => setLogs(result.lines?.join("\n") || "No log lines returned."))
                    .catch((error) =>
                      setLogs(error instanceof Error ? error.message : "Log request failed."),
                    );
                }}
              >
                Logs
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  setLogs("Stats observation queued…");
                  void observeService(item.id, "stats")
                    .then((result) => setLogs(JSON.stringify(result.stats ?? {}, null, 2)))
                    .catch((error) =>
                      setLogs(error instanceof Error ? error.message : "Stats request failed."),
                    );
                }}
              >
                Stats
              </Button>
            </div>
          ))}
        </CardContent>
      </Card>
      {logs && <pre className="overflow-auto rounded-lg border border-border p-3 text-xs">{logs}</pre>}
      <Button
        variant="outline"
        onClick={() => {
          setLogs("Host discovery queued…");
          void discoverServices()
            .then((items) =>
              setLogs(
                items.map((item) => `${item.name} ${item.image}`).join("\n") || "No unmanaged containers.",
              ),
            )
            .catch((error) => setLogs(error instanceof Error ? error.message : "Host discovery failed."));
        }}
      >
        Discover unmanaged containers
      </Button>
    </div>
  );
}

export function ActivityView({ state }: { state: PlatformState }) {
  return (
    <div className="space-y-4">
      {state.operations.map((item) => (
        <Card key={item.id}>
          <CardHeader>
            <CardTitle className="flex items-center gap-3">
              {item.kind}
              <Badge variant={statusVariant(item.status)}>{item.status}</Badge>
            </CardTitle>
            <CardDescription>{item.error ?? formatDate(item.createdAt)}</CardDescription>
          </CardHeader>
          <CardContent>
            {state.steps
              .filter((step) => step.operationId === item.id)
              .map((step) => (
                <p key={step.id} className="text-sm">
                  {step.name} — {step.status}
                </p>
              ))}
          </CardContent>
        </Card>
      ))}
      <Card>
        <CardHeader>
          <CardTitle>Audit</CardTitle>
          <CardDescription>Runtime roles cannot delete these rows from the API.</CardDescription>
        </CardHeader>
        <CardContent>
          {state.audit.map((item) => (
            <p key={item.id} className="text-sm">
              {item.action} {item.resourceType} · {formatDate(item.createdAt)}
            </p>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

export function BackupsView({ state, reload }: { state: PlatformState; reload: () => Promise<void> }) {
  return (
    <div className="space-y-5">
      {state.user.role === "owner" && <BackupTargetsPanel />}
      <div className="flex flex-wrap gap-2">
        <Button
          onClick={() =>
            act(
              api("/api/backups", {
                method: "POST",
                body: JSON.stringify({ kind: "platform-postgres", targetId: "platform" }),
              }),
              reload,
            )
          }
        >
          Capture platform backup
        </Button>
      </div>
      {state.backups.map((item) => (
        <Card key={item.id}>
          <CardContent className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <strong>{item.kind}</strong>
              <p className="text-sm text-muted-foreground">
                {item.status === "local"
                  ? "On the VPS only; exported off-VPS with the next snapshot."
                  : `Upload ${item.status}.`}{" "}
                Restore proof {item.restoreVerified ? "verified" : "not yet run"}.
              </p>
            </div>
            {/* The restore test runs against one exact backup, so the action belongs on the row
                that identifies it rather than on a target-wide button. */}
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() =>
                  act(
                    api("/api/backups/restore-test", {
                      method: "POST",
                      body: JSON.stringify({
                        kind: item.kind,
                        targetId: item.targetId,
                        backupId: item.id,
                      }),
                    }),
                    reload,
                  )
                }
              >
                Isolated restore test
              </Button>
              {item.status === "integrity_ok" && !item.restoreVerified && (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    if (
                      !window.confirm(
                        "Confirm the restored copy booted and served its data? This marks the backup as restore proof for stateful updates.",
                      )
                    )
                      return;
                    act(
                      api(`/api/backups/${item.id}/verify-restore`, {
                        method: "POST",
                        body: JSON.stringify({
                          confirmation: "restored copy booted and served its data",
                        }),
                      }),
                      reload,
                    );
                  }}
                >
                  Mark restore verified
                </Button>
              )}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

export function UpdatesView({ state, reload }: { state: PlatformState; reload: () => Promise<void> }) {
  return (
    <div className="space-y-5">
      <Button onClick={() => act(api("/api/updates/detect", { method: "POST", body: "{}" }), reload)}>
        Resolve registry digests
      </Button>
      <Card>
        <CardHeader>
          <CardTitle>Update policy</CardTitle>
          <CardDescription>
            Notify-and-approve is the default. Stateful rollback is not “run an old image”.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {state.services.map((item) => {
            const candidate = state.updateCandidates?.find((row) => row.serviceId === item.id);
            return (
              <div className="table-row grid-cols-[1fr_auto_auto_auto]" key={item.id}>
                <div>
                  <strong>{item.name}</strong>
                  <p className="mono text-xs text-muted-foreground">
                    {candidate?.candidateDigest ?? item.imageDigest ?? "digest pending"}
                  </p>
                </div>
                <span>{item.updatePolicy}</span>
                <span>{candidate?.requiresApproval ? "approval required" : "auto allowed"}</span>
                {candidate?.candidateDigest && (
                  <Button
                    size="sm"
                    onClick={() =>
                      act(
                        api("/api/updates/apply", {
                          method: "POST",
                          body: JSON.stringify({ serviceId: item.id, digest: candidate.candidateDigest }),
                        }),
                        reload,
                      )
                    }
                  >
                    Apply digest
                  </Button>
                )}
              </div>
            );
          })}
        </CardContent>
      </Card>
    </div>
  );
}

export function SettingsView({ state, reload }: { state: PlatformState; reload: () => Promise<void> }) {
  const [message, setMessage] = useState("");
  return (
    <div className="space-y-5">
      <FormCard
        title="Sensitive-action verification"
        description="Creates a single-use grant bound to this session, action, and the exact request JSON the API will hash. Session refreshes do not extend it."
        onSubmit={async (form) => {
          const raw = String(form.get("request") ?? "").trim() || "{}";
          const request = JSON.parse(raw) as Record<string, unknown>;
          const result = await api<{ action: string; expiresAt: string }>("/api/step-up", {
            method: "POST",
            body: JSON.stringify({
              password: form.get("password"),
              action: form.get("action"),
              request,
            }),
          });
          setMessage(`Verified ${result.action} until ${formatDate(result.expiresAt)}.`);
        }}
      >
        <div>
          <label className="mb-1.5 block text-xs font-semibold">Action</label>
          <select name="action" className="select">
            <option value="secret.reveal">Reveal credentials / query data</option>
            <option value="credential.rotate">Rotate credentials</option>
            <option value="exposure.public">Change public exposure</option>
            <option value="restore.overwrite">Test a restore</option>
            <option value="platform.update">Apply updates</option>
            <option value="resource.delete">Delete resources</option>
            <option value="role.grant">Change access roles</option>
          </select>
        </div>
        <Field label="Request binding JSON" name="request" placeholder='{"secretId":"sec_..."}' required />
        <Field
          label="Current password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
        />
      </FormCard>
      <FormCard
        title="Platform settings"
        description="Auth origin is the exact configured HTTPS origin, never a Host header."
        onSubmit={async (form) => {
          await api("/api/settings", {
            method: "PUT",
            body: JSON.stringify({
              timezone: form.get("timezone"),
              defaultQuotaGb: Number(form.get("defaultQuotaGb")),
              allowExternalForwarding: form.has("allowExternalForwarding"),
            }),
          });
          await reload();
        }}
      >
        <Field label="Timezone" name="timezone" defaultValue={state.settings?.timezone} required />
        <Field
          label="Default mailbox quota"
          name="defaultQuotaGb"
          type="number"
          defaultValue={state.settings?.defaultQuotaGb}
        />
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            name="allowExternalForwarding"
            defaultChecked={state.settings?.allowExternalForwarding}
          />
          Allow external alias forwarding
        </label>
      </FormCard>
      <RegionSettings state={state} reload={reload} />
      <DbIngressSettings state={state} reload={reload} />
      <Card>
        <CardHeader>
          <CardTitle>Administrator MFA</CardTitle>
          <CardDescription>
            Enrollment is required before owner mutations. Recovery codes are local, not email-only.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm">Two-factor enabled: {state.user.twoFactorEnabled ? "yes" : "no"}</p>
          <p className="text-sm text-muted-foreground">
            Re-enrollment is available only through the local recovery workflow; MFA cannot be disabled from
            an ordinary authenticated session.
          </p>
          {message && <p className="text-sm text-muted-foreground">{message}</p>}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Administration mode</CardTitle>
          <CardDescription>
            Mode changes are durable operations. A failed private path will not republish the dashboard.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex gap-2">
          <Button
            type="button"
            variant="outline"
            onClick={() =>
              act(
                api("/api/settings/mode", {
                  method: "POST",
                  body: JSON.stringify({ adminMode: "public" }),
                }),
                reload,
              )
            }
          >
            Public HTTPS
          </Button>
          <Button
            type="button"
            variant="outline"
            onClick={() =>
              act(
                api("/api/settings/mode", {
                  method: "POST",
                  body: JSON.stringify({ adminMode: "tailnet" }),
                }),
                reload,
              )
            }
          >
            Tailnet only
          </Button>
        </CardContent>
      </Card>
      <FormCard
        title="Import inventory"
        description="Read-only compare. Legacy users are never imported as owners."
        onSubmit={async (form) => {
          await api("/api/import/scan", {
            method: "POST",
            body: JSON.stringify({
              source: form.get("source"),
              domains: String(form.get("domains") ?? "")
                .split(",")
                .map((item) => item.trim())
                .filter(Boolean),
            }),
          });
          await reload();
        }}
      >
        <div>
          <label className="mb-1.5 block text-xs font-semibold">Source</label>
          <select name="source" className="select">
            <option value="orkmail">Orkmail</option>
            <option value="pgstack">PgStack</option>
            <option value="compose">Compose</option>
          </select>
        </div>
        <Field label="Incoming domains" name="domains" placeholder="mail.example.com" />
      </FormCard>
    </div>
  );
}

/**
 * Region preset (front door §3.15). It only drives suggestions: the Vercel function region,
 * the backup bucket region hint and the docs wording. SES keeps its own AWS_REGION.
 */
function RegionSettings({ state, reload }: { state: PlatformState; reload: () => Promise<void> }) {
  const region = state.region;
  const [message, setMessage] = useState("");
  if (!region) return null;
  const isOwner = state.user.role === "owner";
  const summary = (
    <dl className="grid gap-2 text-sm md:col-span-2 md:grid-cols-[max-content_1fr] md:gap-x-6">
      <dt className="text-muted-foreground">Region</dt>
      <dd>
        {region.label} <span className="mono text-xs text-muted-foreground">{region.region}</span>
      </dd>
      <dt className="text-muted-foreground">VPS region (recorded)</dt>
      <dd>{region.vpsRegionLabel ?? "Not recorded"}</dd>
      <dt className="text-muted-foreground">Suggested Vercel function region</dt>
      <dd>
        <span className="mono">{region.vercelRegion}</span> ({region.vercelLocation})
      </dd>
      <dt className="text-muted-foreground">vercel.json</dt>
      <dd>
        <code className="mono text-xs">{region.vercelSnippet}</code>
      </dd>
      <dt className="text-muted-foreground">Suggested backup bucket region</dt>
      <dd>
        <span className="mono">{region.backupRegionHint}</span>, or your provider&apos;s nearest location
      </dd>
      <dt className="text-muted-foreground">Pick a VPS in</dt>
      <dd>{region.docsLabel}</dd>
      <dd className="text-xs text-muted-foreground md:col-span-2">{region.latencyHint}</dd>
    </dl>
  );
  if (!isOwner) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Region</CardTitle>
          <CardDescription>Only an owner can change the region.</CardDescription>
        </CardHeader>
        <CardContent>{summary}</CardContent>
      </Card>
    );
  }
  return (
    <FormCard
      title="Region"
      description="Drives the suggested Vercel function region, the backup bucket region and the docs wording. Ark does not choose the VPS, and this never changes the SES region (AWS_REGION). Saving needs your password."
      onSubmit={async (form) => {
        setMessage("");
        const label = String(form.get("vpsRegionLabel") ?? "").trim();
        const request = { region: String(form.get("region") ?? ""), vpsRegionLabel: label || null };
        await api("/api/step-up", {
          method: "POST",
          body: JSON.stringify({ password: form.get("regionPassword"), action: "platform.update", request }),
        });
        const saved = await api<{ label: string; vercelRegion: string }>("/api/settings/region", {
          method: "PUT",
          body: JSON.stringify(request),
        });
        await reload();
        setMessage(`Region saved: ${saved.label}, Vercel ${saved.vercelRegion}.`);
      }}
    >
      {summary}
      <div>
        <label htmlFor="region" className="mb-1.5 block text-xs font-semibold">
          Region
        </label>
        <select id="region" name="region" className="select" defaultValue={region.region} key={region.region}>
          {region.options.map((option) => (
            <option key={option.region} value={option.region}>
              {option.label} (Vercel {option.vercelRegion})
            </option>
          ))}
        </select>
      </div>
      <Field
        key={region.vpsRegionLabel ?? ""}
        label="VPS region label (optional)"
        name="vpsRegionLabel"
        placeholder="Hetzner ash"
        maxLength={64}
        defaultValue={region.vpsRegionLabel ?? ""}
      />
      <Field
        label="Current password"
        name="regionPassword"
        type="password"
        autoComplete="current-password"
        required
      />
      {message && <p className="text-sm text-muted-foreground md:col-span-2">{message}</p>}
    </FormCard>
  );
}

/**
 * Per-source limits on the public database port (front door §3.11). nftables enforces them for
 * every source on tcp/5432, with IPv6 sources grouped by /64. Vercel functions share AWS egress
 * addresses, so the defaults are generous.
 */
function DbIngressSettings({ state, reload }: { state: PlatformState; reload: () => Promise<void> }) {
  const limits = state.dbIngress;
  const [message, setMessage] = useState("");
  if (!limits) return null;
  const summary = (
    <dl className="grid gap-2 text-sm md:col-span-2 md:grid-cols-[max-content_1fr] md:gap-x-6">
      <dt className="text-muted-foreground">Concurrent connections per source</dt>
      <dd>
        {limits.maxConnectionsPerSource}{" "}
        <span className="text-xs text-muted-foreground">
          (default {limits.defaults.maxConnectionsPerSource})
        </span>
      </dd>
      <dt className="text-muted-foreground">New connections per source</dt>
      <dd>
        {limits.newConnectionsPerSecond}/second, burst {limits.newConnectionBurst}{" "}
        <span className="text-xs text-muted-foreground">
          (default {limits.defaults.newConnectionsPerSecond}/second, burst{" "}
          {limits.defaults.newConnectionBurst})
        </span>
      </dd>
      <dd className="text-xs text-muted-foreground md:col-span-2">
        Applies to tcp/{limits.port}. IPv4 sources are limited per address and IPv6 sources per{" "}
        {limits.ipv6Grouping}. Drops are exported as ark_nft_drop_packets_total.
      </dd>
    </dl>
  );
  if (state.user.role !== "owner") {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Public database port limits</CardTitle>
          <CardDescription>Only an owner can change these limits.</CardDescription>
        </CardHeader>
        <CardContent>{summary}</CardContent>
      </Card>
    );
  }
  const key = `${limits.maxConnectionsPerSource}-${limits.newConnectionsPerSecond}-${limits.newConnectionBurst}`;
  return (
    <FormCard
      title="Public database port limits"
      description="Caps each source's concurrent connections and new-connection rate on the public PostgreSQL port. Vercel functions share AWS egress addresses, so keep these generous. Saving needs your password."
      onSubmit={async (form) => {
        setMessage("");
        const request = {
          maxConnectionsPerSource: Number(form.get("maxConnectionsPerSource")),
          newConnectionsPerSecond: Number(form.get("newConnectionsPerSecond")),
          newConnectionBurst: Number(form.get("newConnectionBurst")),
        };
        await api("/api/step-up", {
          method: "POST",
          body: JSON.stringify({
            password: form.get("dbIngressPassword"),
            action: "platform.update",
            request,
          }),
        });
        await api("/api/settings/db-ingress", { method: "PUT", body: JSON.stringify(request) });
        await reload();
        setMessage("Limits saved. The firewall rules are being reapplied.");
      }}
    >
      {summary}
      <Field
        key={`conn-${key}`}
        label="Concurrent connections per source"
        name="maxConnectionsPerSource"
        type="number"
        required
        min={limits.bounds.maxConnectionsPerSource.min}
        max={limits.bounds.maxConnectionsPerSource.max}
        defaultValue={limits.maxConnectionsPerSource}
      />
      <Field
        key={`rate-${key}`}
        label="New connections per second, per source"
        name="newConnectionsPerSecond"
        type="number"
        required
        min={limits.bounds.newConnectionsPerSecond.min}
        max={limits.bounds.newConnectionsPerSecond.max}
        defaultValue={limits.newConnectionsPerSecond}
      />
      <Field
        key={`burst-${key}`}
        label="New-connection burst"
        name="newConnectionBurst"
        type="number"
        required
        min={limits.bounds.newConnectionBurst.min}
        max={limits.bounds.newConnectionBurst.max}
        defaultValue={limits.newConnectionBurst}
      />
      <Field
        label="Current password"
        name="dbIngressPassword"
        type="password"
        autoComplete="current-password"
        required
      />
      {message && <p className="text-sm text-muted-foreground md:col-span-2">{message}</p>}
    </FormCard>
  );
}

function FormCard({
  title,
  description,
  onSubmit,
  children,
}: {
  title: string;
  description: string;
  onSubmit: (form: FormData) => Promise<void>;
  children: ReactNode;
}) {
  const [error, setError] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    setError("");
    try {
      await onSubmit(form);
      formElement.reset();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not save.");
    }
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="grid gap-4 md:grid-cols-2" onSubmit={submit}>
          {children}
          {error && (
            <div className="md:col-span-2">
              <InlineError>{error}</InlineError>
            </div>
          )}
          <div className="md:col-span-2">
            <Button>Save</Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function Empty({ children }: { children: ReactNode }) {
  return <div className="empty-state">{children}</div>;
}
