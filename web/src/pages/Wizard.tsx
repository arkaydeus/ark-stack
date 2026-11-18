import { type FormEvent, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/input";
import { api } from "@/lib/utils";

import { InlineError } from "./Auth";

export function Wizard({ onDone }: { onDone: () => Promise<void> }) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(event.currentTarget);
    try {
      await api("/api/wizard", {
        method: "POST",
        body: JSON.stringify({
          adminMode: form.get("adminMode"),
          baseDomain: form.get("baseDomain"),
          dnsProvider: form.get("dnsProvider"),
          publicIpv4: form.get("publicIpv4"),
          publicIpv6: form.get("publicIpv6") || undefined,
          adminHostname: form.get("adminHostname") || undefined,
          databaseHostname: form.get("databaseHostname") || undefined,
          mailHostname: form.get("mailHostname") || undefined,
          includeDatabase: form.has("includeDatabase"),
          includeMail: form.has("includeMail"),
          firstDatabaseName: form.get("firstDatabaseName") || undefined,
          firstMailboxLocalPart: form.get("firstMailboxLocalPart") || undefined,
        }),
      });
      await onDone();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Wizard failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto max-w-3xl space-y-6 p-6">
      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-primary">Guided setup</p>
        <h1 className="display mt-2 text-4xl">Choose how this host is reached, then publish DNS.</h1>
        <p className="mt-3 text-muted-foreground">
          Administration mode never decides whether databases or mail are public. Those policies stay
          independent.
        </p>
      </div>
      <form className="space-y-5" onSubmit={submit}>
        <Card>
          <CardHeader>
            <CardTitle>Administration exposure</CardTitle>
            <CardDescription>Both modes use Better Auth and mandatory administrator MFA.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4 md:grid-cols-2">
            <label className="rounded-xl border border-border p-4">
              <input type="radio" name="adminMode" value="public" defaultChecked />
              <strong className="ml-2">Public HTTPS</strong>
              <p className="mt-2 text-sm text-muted-foreground">
                Serve the desk at admin.example.com through the public edge.
              </p>
            </label>
            <label className="rounded-xl border border-border p-4">
              <input type="radio" name="adminMode" value="tailnet" />
              <strong className="ml-2">Tailnet only</strong>
              <p className="mt-2 text-sm text-muted-foreground">
                No public admin route. Tailscale Serve to a loopback gateway.
              </p>
            </label>
            <Field label="Base domain" name="baseDomain" placeholder="example.com" required />
            <Field label="Public IPv4" name="publicIpv4" placeholder="203.0.113.10" required />
            <Field label="Public IPv6 (optional)" name="publicIpv6" placeholder="2001:db8::10" />
            <Field label="Admin hostname (optional)" name="adminHostname" placeholder="admin.example.com" />
            <Field
              label="Database hostname (optional)"
              name="databaseHostname"
              placeholder="db.example.com"
            />
            <Field label="Mail hostname (optional)" name="mailHostname" placeholder="mail.example.com" />
            <div>
              <label className="mb-1.5 block text-xs font-semibold" htmlFor="dnsProvider">
                DNS provider
              </label>
              <select id="dnsProvider" name="dnsProvider" className="select">
                <option value="manual">Manual / other</option>
                <option value="cloudflare">Cloudflare (publish after review)</option>
              </select>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>First services</CardTitle>
            <CardDescription>Credentials are generated automatically and shown once.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4 md:grid-cols-2">
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" name="includeDatabase" defaultChecked /> Public database endpoint
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" name="includeMail" defaultChecked /> Incoming mail
            </label>
            <Field label="First database name" name="firstDatabaseName" placeholder="orders" />
            <Field label="First mailbox local part" name="firstMailboxLocalPart" placeholder="hello" />
          </CardContent>
        </Card>
        {error && <InlineError>{error}</InlineError>}
        <Button disabled={busy}>{busy ? "Queuing provisioning…" : "Generate DNS plan and continue"}</Button>
      </form>
    </main>
  );
}
