// Gate users (docs/design/front-door.md §3.9.6, FD-12). Owner-only: list, create and delete the
// accounts that sign in on the login origin for "Ark login" (SSO) routes, and reveal a new user's
// temporary password exactly once. Every change needs the owner's password (a single-use step-up).
import { Check, Copy } from "lucide-react";
import { type FormEvent, useCallback, useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/input";
import type { PlatformState } from "@/lib/types";
import { api, formatDate } from "@/lib/utils";

import { InlineError } from "./Auth";

type GateUser = {
  id: string;
  email: string;
  name: string;
  createdAt: string;
  createdBy: string | null;
  mfaEnrolled: boolean;
  temporaryPassword: "unrevealed" | "revealed" | "none";
  routes: Array<{ routeId: string; hostname: string | null }>;
  activeSessions: number;
};

// The step-up bindings must equal the server's (shared/src/gate.ts `gateUser*Binding`).
const createBinding = (request: Record<string, unknown>) => ({ ...request, gateUsers: "create" });
const deleteBinding = (userId: string) => ({ gateUsers: "delete", userId });
const revealBinding = (userId: string) => ({ gateUserTemporaryPassword: userId });

async function stepUp(password: string, action: "role.grant" | "secret.reveal", request: object) {
  await api("/api/step-up", { method: "POST", body: JSON.stringify({ password, action, request }) });
}

export function GateUsersView({ state }: { state: PlatformState }) {
  const isOwner = state.user.role === "owner";
  const [users, setUsers] = useState<GateUser[] | null>(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [ownerPassword, setOwnerPassword] = useState("");
  const [revealed, setRevealed] = useState<{ email: string; password: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    try {
      setUsers((await api<{ users: GateUser[] }>("/api/gate/users")).users);
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not load gate users.");
    }
  }, []);
  useEffect(() => {
    if (state.user.role === "owner") void load();
    // App refresh replaces state; keep the view mounted so the once-only password stays visible.
  }, [state, load]);

  if (!isOwner) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Gate users</CardTitle>
          <CardDescription>Only an owner can manage gate users.</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  async function run(work: () => Promise<void>) {
    if (!ownerPassword) {
      setMessage("Enter your password first; every change is confirmed with it.");
      return;
    }
    setBusy(true);
    setMessage("");
    try {
      await work();
    } catch (cause) {
      setMessage(cause instanceof Error ? cause.message : "The request failed.");
    } finally {
      setBusy(false);
      await load();
    }
  }

  async function reveal(user: Pick<GateUser, "id" | "email">) {
    await stepUp(ownerPassword, "secret.reveal", revealBinding(user.id));
    const result = await api<{ password: string }>(
      `/api/gate/users/${encodeURIComponent(user.id)}/temporary-password`,
      { method: "POST", body: "{}" },
    );
    setCopied(false);
    setRevealed({ email: user.email, password: result.password });
  }

  function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const request: Record<string, unknown> = { email: String(data.get("email") ?? "").trim() };
    const name = String(data.get("name") ?? "").trim();
    if (name) request.name = name;
    void run(async () => {
      await stepUp(ownerPassword, "role.grant", createBinding(request));
      const { user } = await api<{ user: GateUser }>("/api/gate/users", {
        method: "POST",
        body: JSON.stringify(request),
      });
      form.reset();
      await reveal(user);
    });
  }

  function remove(user: GateUser) {
    if (
      !window.confirm(
        `Delete ${user.email}? Their sessions and route access are removed, and open connections to their routes are closed.`,
      )
    )
      return;
    void run(async () => {
      await stepUp(ownerPassword, "role.grant", deleteBinding(user.id));
      await api(`/api/gate/users/${encodeURIComponent(user.id)}`, { method: "DELETE", body: "{}" });
      if (revealed?.email === user.email) setRevealed(null);
      setMessage(`Deleted ${user.email}.`);
    });
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Gate users</CardTitle>
          <CardDescription>
            People you let through “Ark login” routes. They sign in only on the login origin, must set up an
            authenticator app on their first sign-in, and have no access to Ark. Add them to a route’s access
            list to let them in.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Field
            label="Your password (confirms each change)"
            name="gate-owner-password"
            type="password"
            autoComplete="current-password"
            value={ownerPassword}
            onChange={(event) => setOwnerPassword(event.target.value)}
          />
          {message && <p className="text-sm text-muted-foreground">{message}</p>}
          {revealed && (
            <div
              className="space-y-2 rounded-lg border border-amber-300/40 bg-amber-500/10 p-3 text-sm"
              role="status"
            >
              <p>
                Temporary password for <strong>{revealed.email}</strong>. It is shown only once; give it to
                them privately.
              </p>
              <div className="flex items-center gap-2">
                <code className="mono break-all" data-testid="gate-temporary-password">
                  {revealed.password}
                </code>
                <Button
                  size="icon"
                  variant="ghost"
                  aria-label="Copy temporary password"
                  onClick={() =>
                    void navigator.clipboard.writeText(revealed.password).then(() => setCopied(true))
                  }
                >
                  {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
                </Button>
              </div>
              <Button size="sm" variant="outline" onClick={() => setRevealed(null)}>
                Done, hide it
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Add a gate user</CardTitle>
          <CardDescription>
            Ark generates a temporary password and shows it once after the user is created.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end" onSubmit={create}>
            <Field label="Email" name="email" type="email" autoComplete="off" required />
            <Field label="Name (optional)" name="name" autoComplete="off" />
            <Button disabled={busy}>{busy ? "Working…" : "Create"}</Button>
          </form>
        </CardContent>
      </Card>

      {error && <InlineError>{error}</InlineError>}
      {users && (
        <Card>
          <CardHeader>
            <CardTitle>
              {users.length ? `${users.length} gate user${users.length === 1 ? "" : "s"}` : "No gate users"}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {users.map((user) => (
              <div
                key={user.id}
                className="flex flex-wrap items-start justify-between gap-3 border-b border-border pb-3 last:border-0"
              >
                <div className="min-w-0 space-y-1 text-sm">
                  <p>
                    <strong>{user.email}</strong> <span className="text-muted-foreground">{user.name}</span>
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <Badge variant={user.mfaEnrolled ? "success" : "warning"}>
                      {user.mfaEnrolled ? "authenticator set up" : "authenticator pending"}
                    </Badge>
                    {user.temporaryPassword === "unrevealed" && (
                      <Badge variant="warning">temporary password not shown yet</Badge>
                    )}
                    <Badge variant="neutral">
                      {user.activeSessions} session{user.activeSessions === 1 ? "" : "s"}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Created {formatDate(user.createdAt)} · Routes:{" "}
                    {user.routes.length
                      ? user.routes.map((route) => route.hostname ?? route.routeId).join(", ")
                      : "none"}
                  </p>
                </div>
                <div className="flex gap-2">
                  {user.temporaryPassword === "unrevealed" && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy}
                      onClick={() => void run(() => reveal(user))}
                    >
                      Reveal temporary password
                    </Button>
                  )}
                  <Button size="sm" variant="ghost" disabled={busy} onClick={() => remove(user)}>
                    Delete
                  </Button>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
