import { type FormEvent, useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/input";
import { api, formatDate } from "@/lib/utils";

type Client = { id: string; name: string; environment: string };
type Database = { id: string };
type Integration = {
  projectId: string;
  target: "production" | "preview";
  gitBranch: string | null;
  tokenExpiresAt: string;
  tokenExpiryStatus: "valid" | "expiring" | "expired";
  lastPushAt: string | null;
  lastPushStatus: "pushing" | "failed" | "delivered" | "cancelled" | null;
};
type IntegrationStatus = {
  connectEnabled: boolean;
  eligible: boolean;
  requiresReconnect: boolean;
  integration: Integration | null;
};
const connectionPath = (database: Database, clientId: string) =>
  `/api/databases/${database.id}/clients/${clientId}/vercel-integration`;

export function VercelRolloverPanel({ database }: { database: Database }) {
  const [clients, setClients] = useState<Client[] | null>(null);
  const [selected, setSelected] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    void api<{ clients: Client[] }>(`/api/databases/${database.id}/clients`, { signal: controller.signal })
      .then(({ clients: found }) => {
        setClients(found);
        setError("");
        setSelected((current) =>
          found.some((client) => client.id === current) ? current : (found[0]?.id ?? ""),
        );
      })
      .catch((cause: Error) => {
        if (!controller.signal.aborted) setError(cause.message);
      });
    return () => controller.abort();
  }, [database]);
  const client = clients?.find(({ id }) => id === selected);

  return (
    <section aria-label="Vercel certificate rollover" className="space-y-4 border-t border-border px-4 py-5">
      <div className="max-w-[70ch] space-y-2 text-sm">
        <h3 className="font-semibold">Vercel certificate rollover</h3>
        <p>
          A Vercel project token can change environment variables and deploy arbitrary code to that project,
          including on its production domain. If the VPS or any service with Ark’s shared root key is
          compromised, the attacker can decrypt the token and reach the project’s users, sessions and other
          secrets.
        </p>
        <p className="text-muted-foreground">
          The API, which serves the public login origin when enabled, and the database, domain, mail and
          backup workers all hold that key and have database access. Ark requires an expiring, project-scoped
          token and audits every use. Disconnecting deletes Ark’s copy of the token and deploy hook. Manual
          rollover is available for production apps that hold sensitive user data.
        </p>
        <p className="text-muted-foreground">
          Before connecting, deploy an app that reads <code>ARK_DB_CLIENT_CERT_B64</code> and{" "}
          <code>ARK_DB_CLIENT_KEY_B64</code> and confirm that the reviewed database ingress policy admits its
          Vercel traffic.
        </p>
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      {!clients && !error && (
        <p role="status" className="text-sm text-muted-foreground">
          Loading database clients…
        </p>
      )}
      {clients?.length === 0 && (
        <p className="text-sm text-muted-foreground">This database has no clients.</p>
      )}
      {!!clients?.length && (
        <label className="block max-w-sm text-xs font-semibold">
          Database client
          <select
            className="select mt-1.5"
            value={selected}
            onChange={(event) => setSelected(event.target.value)}
          >
            {clients.map(({ id, name, environment }) => (
              <option key={id} value={id}>
                {name} · {environment}
              </option>
            ))}
          </select>
        </label>
      )}
      {client && <VercelConnection key={client.id} database={database} client={client} />}
    </section>
  );
}

function VercelConnection({ database, client }: { database: Database; client: Client }) {
  const path = connectionPath(database, client.id);
  const [status, setStatus] = useState<IntegrationStatus | null>(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    void api<IntegrationStatus>(connectionPath(database, client.id), { signal: controller.signal })
      .then(setStatus)
      .catch((cause: Error) => {
        if (!controller.signal.aborted) setError(cause.message);
      });
    return () => controller.abort();
  }, [database, client.id]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const submitter = (event.nativeEvent as SubmitEvent).submitter as HTMLButtonElement | null;
    const intent =
      submitter?.value ??
      (status?.integration ? "test" : status?.requiresReconnect ? "disconnect" : "connect");
    const form = event.currentTarget;
    const data = new FormData(form);
    const password = String(data.get("vercelOwnerPassword") ?? "");
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const request = { databaseId: database.id, clientId: client.id, vercelIntegration: intent };
      if (intent === "connect") {
        const gitBranch = String(data.get("vercelBranch") ?? "").trim();
        const selection = {
          projectId: String(data.get("vercelProject") ?? "").trim(),
          teamId: String(data.get("vercelTeam") ?? "").trim(),
          otherProjectId: String(data.get("vercelOtherProject") ?? "").trim(),
          target: client.environment,
          ...(gitBranch ? { gitBranch } : {}),
        };
        const token = String(data.get("vercelToken") ?? "").trim();
        const deployHook = String(data.get("vercelHook") ?? "").trim();
        const digest = await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(JSON.stringify([token, deployHook])),
        );
        const credentialDigest = Array.from(new Uint8Array(digest), (byte) =>
          byte.toString(16).padStart(2, "0"),
        ).join("");
        await stepUp(password, { ...request, ...selection, credentialDigest });
        await api(path, { method: "PUT", body: JSON.stringify({ ...selection, token, deployHook }) });
        setMessage("Vercel connected.");
      } else {
        await stepUp(password, request);
        if (intent === "test") {
          await api(`${path}/test`, { method: "POST", body: "{}" });
          setMessage("Vercel verified the project token and deploy hook.");
        } else {
          await api(path, { method: "DELETE" });
          setMessage("Vercel disconnected. Continue with manual rollover.");
        }
      }
      setStatus(await api<IntegrationStatus>(path));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The Vercel action failed.");
    } finally {
      for (const name of ["vercelOwnerPassword", "vercelToken", "vercelHook"]) {
        const field = form.elements.namedItem(name);
        if (field instanceof HTMLInputElement) field.value = "";
      }
      setBusy(false);
    }
  }

  const integration = status?.integration;
  const connected = integration || status?.requiresReconnect;
  return (
    <div className="space-y-3">
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      {message && (
        <p role="status" className="text-sm">
          {message}
        </p>
      )}
      {!status && !error && (
        <p role="status" className="text-sm text-muted-foreground">
          Loading Vercel settings…
        </p>
      )}
      {status && !status.connectEnabled && (
        <p className="text-sm text-muted-foreground">
          Connection is disabled pending live verification of Vercel’s project token scope. Use manual
          rollover.
        </p>
      )}
      {status?.requiresReconnect && (
        <p role="alert" className="text-sm">
          This connection predates scope verification. Disconnect it to set up verified rollover.
        </p>
      )}
      {integration && (
        <dl className="grid max-w-xl gap-2 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-muted-foreground">Project</dt>
            <dd className="break-all">{integration.projectId}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Target</dt>
            <dd>
              {integration.target}
              {integration.gitBranch ? ` · ${integration.gitBranch}` : ""}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Token expiry</dt>
            <dd>{formatDate(integration.tokenExpiresAt)}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Last delivery</dt>
            <dd>
              {integration.lastPushStatus
                ? `${integration.lastPushStatus} · ${formatDate(integration.lastPushAt)}`
                : "Awaiting a certificate rollover"}
            </dd>
          </div>
        </dl>
      )}
      {integration && integration.tokenExpiryStatus !== "valid" && (
        <p role="alert" className="text-sm">
          <strong>
            {integration.tokenExpiryStatus === "expired"
              ? "Vercel token expired."
              : "Vercel token expires within 30 days."}
          </strong>{" "}
          Reconnect with a new project token or use manual rollover.
        </p>
      )}
      {integration?.lastPushStatus === "failed" && (
        <p role="alert" className="text-sm text-destructive">
          Vercel delivery failed. Check the delivery alert before using the manual rollover guide to replace
          both sensitive values in project {integration.projectId} for {integration.target}
          {integration.gitBranch ? ` branch ${integration.gitBranch}` : ""}. Redeploy and verify database
          access before confirming.
        </p>
      )}
      {status?.connectEnabled && !status.eligible && !connected && (
        <p className="text-sm text-muted-foreground">
          Connect an active production or preview client with an Ark-generated key.
        </p>
      )}
      {!!status && (connected || (status.connectEnabled && status.eligible)) && (
        <form onSubmit={(event) => void submit(event)} className="max-w-2xl space-y-3">
          {!connected && (
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Vercel project ID" name="vercelProject" placeholder="prj_…" required />
              <Field label="Vercel team ID" name="vercelTeam" placeholder="team_…" required />
              <Field
                label="Other project ID in the same team"
                name="vercelOtherProject"
                placeholder="prj_…"
                required
              />
              {client.environment === "preview" && (
                <Field label="Preview branch (defaults to the deploy hook branch)" name="vercelBranch" />
              )}
              <Field label="Project token" name="vercelToken" type="password" autoComplete="off" required />
              <Field label="Deploy hook URL" name="vercelHook" type="password" autoComplete="off" required />
            </div>
          )}
          <div className="max-w-sm">
            <Field
              label="Your Ark password"
              name="vercelOwnerPassword"
              type="password"
              autoComplete="current-password"
              required
            />
          </div>
          <div className="flex flex-wrap gap-2">
            {connected ? (
              <>
                <Button
                  type="submit"
                  variant="outline"
                  value="test"
                  disabled={busy || !status.connectEnabled || !integration}
                >
                  Test connection
                </Button>
                <Button type="submit" variant="outline" value="disconnect" disabled={busy}>
                  Disconnect
                </Button>
              </>
            ) : (
              <Button type="submit" value="connect" disabled={busy}>
                Connect Vercel
              </Button>
            )}
          </div>
        </form>
      )}
    </div>
  );
}

async function stepUp(password: string, request: object) {
  await api("/api/step-up", {
    method: "POST",
    body: JSON.stringify({ password, action: "credential.rotate", request }),
  });
}
