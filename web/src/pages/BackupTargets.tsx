// Off-VPS backup targets (docs/design/front-door.md §3.18, FD-21, FD-30). Owner-only: configure the
// S3-compatible destination from a provider recipe and the home machine's rest-server over the
// tailnet, see append-only status, recovery points and health, and run the append-only canary.
// Credentials are write-only.
import { useCallback, useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/input";
import { act, api, formatDate } from "@/lib/utils";

import { InlineError } from "./Auth";

type Provider = "aws" | "b2" | "r2" | "minio" | "other";
type Recipe = {
  provider: Provider;
  label: string;
  endpointExample: string;
  pathStyle: boolean;
  regionOverride?: string;
  immutability: string[];
  writer: string[];
  notes: string[];
};
type Target = {
  id: string;
  kind: "s3" | "tailnet_rest";
  name: string;
  provider: Provider | "rest_server";
  restUrl: string | null;
  pinned: { stableId: string | null; ip: string | null } | null;
  endpoint: string | null;
  region: string | null;
  bucket: string | null;
  prefix: string;
  pathStyle: boolean;
  enabled: boolean;
  recoveryWindowDays: number;
  hasVerifier: boolean;
  appendOnlyStatus: string;
  appendOnlyCheckedAt: string | null;
  appendOnlyEvidence: { findings?: Array<{ kind: string; message: string }> } | null;
  retentionUntil: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
};
type Health = {
  healthy: boolean;
  reasons: string[];
  targets: Array<{
    id: string;
    healthy: boolean;
    appendOnly: { status: string; label: string; current: boolean };
    sources: Array<{ source: string; lastRecoverableAt: string | null; lastAttemptFailed: boolean }>;
  }>;
};
type TailnetRecipe = { label: string; urlExample: string; server: string[]; notes: string[] };
type TargetsResponse = {
  targets: Target[];
  health: Health;
  recipes: Record<Provider, Recipe>;
  tailnetRecipe: TailnetRecipe;
  regionHint: string;
  writerPolicy: Record<string, unknown>;
  bucketProtectionPolicy: Record<string, unknown>;
};

function randomPassword() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes))
    .replace(/[+/=]/g, "")
    .slice(0, 40);
}

export function BackupTargetsPanel() {
  const [data, setData] = useState<TargetsResponse | null>(null);
  const [error, setError] = useState("");
  const [provider, setProvider] = useState<Provider>("aws");
  const [editing, setEditing] = useState<Target | null>(null);
  const [generated, setGenerated] = useState("");
  const [message, setMessage] = useState("");
  const [editingHome, setEditingHome] = useState<Target | null>(null);
  const [homeGenerated, setHomeGenerated] = useState("");
  const [homeMessage, setHomeMessage] = useState("");
  const load = useCallback(async () => {
    try {
      setData(await api<TargetsResponse>("/api/backups/targets"));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not load backup targets.");
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);
  if (error) return <InlineError>{error}</InlineError>;
  if (!data) return null;
  const recipe = data.recipes[provider];
  const health = (id: string) => data.health.targets.find((item) => item.id === id);

  async function saveHome(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    setHomeMessage("");
    const text = (name: string) => String(form.get(name) ?? "").trim();
    const request: Record<string, unknown> = {
      ...(editingHome ? { id: editingHome.id } : {}),
      name: text("name"),
      restUrl: text("restUrl"),
      recoveryWindowDays: Number(text("recoveryWindowDays") || "30"),
      password: String(form.get("restPassword") ?? "") || undefined,
      repositoryPassword: text("repositoryPassword") || undefined,
    };
    for (const key of Object.keys(request)) if (request[key] === undefined) delete request[key];
    try {
      await api("/api/step-up", {
        method: "POST",
        body: JSON.stringify({
          password: form.get("password"),
          action: "credential.rotate",
          request: { backupTarget: "tailnet_rest", ...request },
        }),
      });
      await api("/api/backups/targets/tailnet_rest", { method: "PUT", body: JSON.stringify(request) });
      formElement.reset();
      setEditingHome(null);
      setHomeGenerated("");
      setHomeMessage("Saved and pinned. The append-only check is running; refresh in a minute.");
      await load();
    } catch (cause) {
      setHomeMessage(cause instanceof Error ? cause.message : "Could not save the home target.");
    }
  }

  async function save(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    setMessage("");
    const text = (name: string) => String(form.get(name) ?? "").trim();
    const optional = (name: string) => text(name) || undefined;
    const request: Record<string, unknown> = {
      ...(editing ? { id: editing.id } : {}),
      name: text("name"),
      provider,
      endpoint: text("endpoint"),
      region: text("region"),
      bucket: text("bucket"),
      prefix: text("prefix") || "ark",
      pathStyle: form.get("pathStyle") === "on",
      recoveryWindowDays: Number(text("recoveryWindowDays") || "30"),
      accessKeyId: optional("accessKeyId"),
      secretAccessKey: optional("secretAccessKey"),
      repositoryPassword: optional("repositoryPassword"),
      verifierAccountId: optional("verifierAccountId"),
      verifierToken: optional("verifierToken"),
    };
    for (const key of Object.keys(request)) if (request[key] === undefined) delete request[key];
    try {
      await api("/api/step-up", {
        method: "POST",
        body: JSON.stringify({
          password: form.get("password"),
          action: "credential.rotate",
          request: { backupTarget: "s3", ...request },
        }),
      });
      await api("/api/backups/targets/s3", { method: "PUT", body: JSON.stringify(request) });
      formElement.reset();
      setEditing(null);
      setGenerated("");
      setMessage("Saved. The append-only check is running; refresh in a minute.");
      await load();
    } catch (cause) {
      setMessage(cause instanceof Error ? cause.message : "Could not save the target.");
    }
  }

  return (
    <div className="space-y-5">
      <Card>
        <CardHeader>
          <CardTitle>Off-VPS backups</CardTitle>
          <CardDescription>
            PostgreSQL (both clusters), mail and reviewed volumes leave the VPS as encrypted restic snapshots.
            Healthy only when every target has a fresh recovery point and passes the append-only check.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <Badge variant={data.health.healthy ? "success" : "danger"}>
            {data.health.healthy ? "Backups healthy" : "Backups unhealthy"}
          </Badge>
          {data.health.reasons.map((reason) => (
            <p key={reason} className="text-sm text-muted-foreground">
              {reason}
            </p>
          ))}
        </CardContent>
      </Card>

      {data.targets.map((target) => {
        const status = health(target.id);
        const appendOnly = status?.appendOnly;
        const home = target.kind === "tailnet_rest";
        return (
          <Card key={target.id}>
            <CardHeader>
              <CardTitle>
                {target.name} ·{" "}
                {home
                  ? data.tailnetRecipe.label
                  : (data.recipes[target.provider as Provider]?.label ?? target.provider)}
              </CardTitle>
              <CardDescription className="mono">
                {home
                  ? `${target.restUrl} → pinned ${target.pinned?.stableId ?? "?"} (${target.pinned?.ip ?? "?"}) via backup-ts`
                  : `${target.endpoint} / ${target.bucket} / ${target.prefix} (${target.pathStyle ? "path-style" : "virtual-host"}, ${target.region})`}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <div className="flex flex-wrap gap-2">
                <Badge
                  variant={
                    appendOnly?.current
                      ? "success"
                      : appendOnly?.status === "deletable"
                        ? "danger"
                        : "warning"
                  }
                >
                  {appendOnly?.label ?? target.appendOnlyStatus}
                </Badge>
                <Badge variant={status?.healthy ? "success" : "danger"}>
                  {status?.healthy ? "healthy" : "unhealthy"}
                </Badge>
              </div>
              {home ? (
                <p className="text-muted-foreground">
                  Checked {target.appendOnlyCheckedAt ? formatDate(target.appendOnlyCheckedAt) : "never"};
                  rest-server --append-only refuses deletes, and pruning runs on the home machine. Last
                  success {target.lastSuccessAt ? formatDate(target.lastSuccessAt) : "never"}.
                </p>
              ) : (
                <p className="text-muted-foreground">
                  Checked {target.appendOnlyCheckedAt ? formatDate(target.appendOnlyCheckedAt) : "never"};
                  retention verified until{" "}
                  {target.retentionUntil ? formatDate(target.retentionUntil) : "unknown"} (window{" "}
                  {target.recoveryWindowDays} days). Last success{" "}
                  {target.lastSuccessAt ? formatDate(target.lastSuccessAt) : "never"}.
                </p>
              )}
              {status?.sources.map((source) => (
                <p key={source.source}>
                  <span className="mono">{source.source}</span>: last recoverable{" "}
                  {source.lastRecoverableAt ? formatDate(source.lastRecoverableAt) : "none yet"}
                  {source.lastAttemptFailed ? " (last export failed)" : ""}
                </p>
              ))}
              {target.lastError && <InlineError>{target.lastError}</InlineError>}
              {target.appendOnlyEvidence?.findings?.slice(0, 6).map((finding) => (
                <p key={finding.message} className="text-xs text-muted-foreground">
                  {finding.kind}: {finding.message}
                </p>
              ))}
              {!home && (
                <>
                  <details>
                    <summary className="cursor-pointer text-xs">Writer policy (AWS IAM / MinIO)</summary>
                    <pre className="mono overflow-x-auto text-xs">
                      {JSON.stringify(data.writerPolicy[target.id], null, 2)}
                    </pre>
                  </details>
                  <details>
                    <summary className="cursor-pointer text-xs">
                      Bucket protection policy (AWS / MinIO)
                    </summary>
                    <p className="text-xs text-muted-foreground">
                      Attach this separate bucket policy to protect the exact repository config. Keep
                      permission to replace it off this server.
                    </p>
                    <pre className="mono overflow-x-auto text-xs">
                      {JSON.stringify(data.bucketProtectionPolicy[target.id], null, 2)}
                    </pre>
                  </details>
                </>
              )}
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    act(api(`/api/backups/targets/${target.id}/verify`, { method: "POST", body: "{}" }), load)
                  }
                >
                  Run append-only check
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    if (home) {
                      setEditingHome(target);
                      return;
                    }
                    setEditing(target);
                    setProvider(target.provider as Provider);
                  }}
                >
                  Edit
                </Button>
              </div>
            </CardContent>
          </Card>
        );
      })}

      <Card>
        <CardHeader>
          <CardTitle>{editing ? `Edit ${editing.name}` : "Add an S3-compatible target"}</CardTitle>
          <CardDescription>
            Follow the provider recipe so a compromised server cannot erase backups. Credentials are
            write-only; leave them empty to keep the current ones. Saving needs your password and runs the
            append-only check.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-4">
            <label htmlFor="backup-provider" className="mb-1.5 block text-xs font-semibold">
              Provider
            </label>
            <select
              id="backup-provider"
              className="select"
              value={provider}
              onChange={(event) => setProvider(event.target.value as Provider)}
            >
              {Object.values(data.recipes).map((item) => (
                <option key={item.provider} value={item.provider}>
                  {item.label}
                </option>
              ))}
            </select>
            <div className="mt-3 space-y-1 text-sm">
              <p className="font-semibold">Make history immutable</p>
              {recipe.immutability.map((line) => (
                <p key={line} className="text-muted-foreground">
                  {line}
                </p>
              ))}
              <p className="font-semibold">Writer credential</p>
              {recipe.writer.concat(recipe.notes).map((line) => (
                <p key={line} className="text-muted-foreground">
                  {line}
                </p>
              ))}
            </div>
          </div>
          <form
            key={`${editing?.id ?? "new"}-${provider}`}
            className="grid gap-4 md:grid-cols-2"
            onSubmit={save}
          >
            <Field label="Name" name="name" required defaultValue={editing?.name ?? recipe.label} />
            <Field
              label="Endpoint"
              name="endpoint"
              required
              placeholder={recipe.endpointExample}
              defaultValue={editing?.endpoint ?? ""}
            />
            <Field
              label={`Region (suggested: ${recipe.regionOverride ?? data.regionHint})`}
              name="region"
              required
              defaultValue={editing?.region ?? recipe.regionOverride ?? data.regionHint}
            />
            <Field label="Bucket" name="bucket" required defaultValue={editing?.bucket ?? ""} />
            <Field label="Prefix" name="prefix" defaultValue={editing?.prefix ?? "ark"} />
            <Field
              label="Recovery window (days)"
              name="recoveryWindowDays"
              type="number"
              min={1}
              max={3650}
              defaultValue={String(editing?.recoveryWindowDays ?? 30)}
            />
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                name="pathStyle"
                defaultChecked={editing?.pathStyle ?? recipe.pathStyle}
              />{" "}
              Path-style addressing
            </label>
            <span />
            <Field label="Access key ID" name="accessKeyId" required={!editing} autoComplete="off" />
            <Field
              label="Secret access key"
              name="secretAccessKey"
              type="password"
              required={!editing}
              autoComplete="off"
            />
            {!editing && (
              <div className="md:col-span-2 space-y-1">
                <Field
                  label="restic repository password (store it off-host; it cannot change)"
                  name="repositoryPassword"
                  type="text"
                  required
                  minLength={24}
                  value={generated}
                  onChange={(event) => setGenerated(event.target.value)}
                  autoComplete="off"
                />
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  onClick={() => setGenerated(randomPassword())}
                >
                  Generate
                </Button>
              </div>
            )}
            {provider === "r2" && (
              <>
                <Field
                  label="Cloudflare account ID (lock-rule verifier)"
                  name="verifierAccountId"
                  autoComplete="off"
                />
                <Field
                  label="Read-only Cloudflare API token"
                  name="verifierToken"
                  type="password"
                  autoComplete="off"
                />
              </>
            )}
            <Field
              label="Current password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
            {message && <p className="text-sm text-muted-foreground md:col-span-2">{message}</p>}
            <div className="flex gap-2 md:col-span-2">
              <Button>Save target</Button>
              {editing && (
                <Button type="button" variant="ghost" onClick={() => setEditing(null)}>
                  Cancel
                </Button>
              )}
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{editingHome ? `Edit ${editingHome.name}` : "Add a home machine target"}</CardTitle>
          <CardDescription>
            Backups also go to rest-server on your home machine, over the tailnet through Ark's own backup
            node (tag:ark-backup). Saving pins the machine from the backup node's current view, needs your
            password and runs the append-only check.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-4 space-y-1 text-sm">
            {data.tailnetRecipe.server.concat(data.tailnetRecipe.notes).map((line) => (
              <p key={line} className="text-muted-foreground">
                {line}
              </p>
            ))}
            <Button
              size="sm"
              variant="outline"
              onClick={() => act(api("/api/backups/tailnet/observe", { method: "POST", body: "{}" }), load)}
            >
              Observe the backup tailnet now
            </Button>
          </div>
          <form key={editingHome?.id ?? "new-home"} className="grid gap-4 md:grid-cols-2" onSubmit={saveHome}>
            <Field label="Name" name="name" required defaultValue={editingHome?.name ?? "home"} />
            <Field
              label="REST URL"
              name="restUrl"
              required
              placeholder={data.tailnetRecipe.urlExample}
              defaultValue={editingHome?.restUrl ?? ""}
            />
            <Field
              label="Recovery window (days)"
              name="recoveryWindowDays"
              type="number"
              min={1}
              max={3650}
              defaultValue={String(editingHome?.recoveryWindowDays ?? 30)}
            />
            <Field
              label="htpasswd password (user = first path segment)"
              name="restPassword"
              type="password"
              required={!editingHome}
              autoComplete="off"
            />
            {!editingHome && (
              <div className="md:col-span-2 space-y-1">
                <Field
                  label="restic repository password (store it off-host; it cannot change)"
                  name="repositoryPassword"
                  type="text"
                  required
                  minLength={24}
                  value={homeGenerated}
                  onChange={(event) => setHomeGenerated(event.target.value)}
                  autoComplete="off"
                />
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  onClick={() => setHomeGenerated(randomPassword())}
                >
                  Generate
                </Button>
              </div>
            )}
            <Field
              label="Current password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
            {homeMessage && <p className="text-sm text-muted-foreground md:col-span-2">{homeMessage}</p>}
            <div className="flex gap-2 md:col-span-2">
              <Button>Save home target</Button>
              {editingHome && (
                <Button type="button" variant="ghost" onClick={() => setEditingHome(null)}>
                  Cancel
                </Button>
              )}
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
