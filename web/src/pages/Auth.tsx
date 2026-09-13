import { CircleAlert, KeyRound, RefreshCw } from "lucide-react";
import { type FormEvent, type ReactNode, useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/input";
import { authClient } from "@/lib/auth-client";
import { api } from "@/lib/utils";

export function InlineError({ children }: { children: ReactNode }) {
  return (
    <div
      className="flex items-start gap-2 rounded-lg border border-red-300/30 bg-red-500/10 p-3 text-sm text-red-100"
      role="alert"
    >
      <CircleAlert className="mt-0.5 size-4 shrink-0" />
      <span>{children}</span>
    </div>
  );
}

export function AuthScreen() {
  const [setupRequired, setSetupRequired] = useState<boolean | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [twoFactor, setTwoFactor] = useState(false);

  useEffect(() => {
    api<{ required: boolean }>("/api/setup/status")
      .then((result) => setSetupRequired(result.required))
      .catch((cause: Error) => setError(cause.message));
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(event.currentTarget);
    const email = String(form.get("email"));
    const password = String(form.get("password"));
    try {
      if (setupRequired) {
        const response = await fetch("/api/auth/sign-up/email", {
          method: "POST",
          credentials: "include",
          headers: { "content-type": "application/json", "x-setup-token": String(form.get("setupToken")) },
          body: JSON.stringify({ name: String(form.get("name")), email, password }),
        });
        const result = (await response.json()) as { message?: string; error?: string };
        if (!response.ok) throw new Error(result.error ?? result.message ?? "Administrator setup failed.");
        window.location.reload();
        return;
      }
      const result = await authClient.signIn.email({ email, password });
      if (result.error) throw new Error(result.error.message ?? "Sign in failed.");
      if ((result.data as { twoFactorRedirect?: boolean } | null)?.twoFactorRedirect) {
        setTwoFactor(true);
        return;
      }
      window.location.reload();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Sign in failed.");
    } finally {
      setBusy(false);
    }
  }

  if (twoFactor) {
    return (
      <main className="grid min-h-screen place-items-center p-6">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>Verify your sign-in</CardTitle>
            <CardDescription>
              Enter a TOTP or recovery code. MFA is required for administrators.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form
              className="space-y-4"
              onSubmit={(event) => {
                event.preventDefault();
                const form = new FormData(event.currentTarget);
                setBusy(true);
                const request = form.has("recovery")
                  ? authClient.twoFactor.verifyBackupCode({ code: String(form.get("code")) })
                  : authClient.twoFactor.verifyTotp({ code: String(form.get("code")) });
                void request
                  .then((result) => {
                    if (result.error) setError(result.error.message ?? "Verification failed.");
                    else window.location.reload();
                  })
                  .finally(() => setBusy(false));
              }}
            >
              <Field label="Verification code" name="code" autoComplete="one-time-code" required />
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" name="recovery" /> Use a recovery code
              </label>
              {error && <InlineError>{error}</InlineError>}
              <Button disabled={busy}>Verify and sign in</Button>
            </form>
          </CardContent>
        </Card>
      </main>
    );
  }

  return (
    <main className="grid min-h-screen lg:grid-cols-2">
      <section className="hidden flex-col justify-between p-12 lg:flex">
        <p className="text-xs font-semibold uppercase tracking-[0.2em] text-primary">Ark Stack</p>
        <div>
          <h1 className="display text-5xl leading-tight">
            One host. Databases, mail, and services under one desk.
          </h1>
          <p className="mt-5 max-w-md text-muted-foreground">
            Guided domains, generated credentials, and a policy-enforcing Docker agent. Better Auth on both
            public and tailnet administration.
          </p>
        </div>
        <p className="mono text-xs text-muted-foreground">admin · db · mail · compose</p>
      </section>
      <section className="grid place-items-center p-6">
        <form className="w-full max-w-md space-y-4" onSubmit={submit}>
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-primary">Control plane</p>
            <h2 className="display mt-2 text-3xl">{setupRequired ? "Create the owner" : "Sign in"}</h2>
            <p className="mt-2 text-sm text-muted-foreground">
              {setupRequired
                ? "This single-use bootstrap closes after the first administrator exists."
                : "Sessions stay on the configured origin. Tailscale identity is not enough."}
            </p>
          </div>
          {setupRequired && <Field label="Name" name="name" autoComplete="name" required />}
          <Field label="Email" name="email" type="email" autoComplete="email" required />
          <Field
            label="Password"
            name="password"
            type="password"
            minLength={12}
            autoComplete={setupRequired ? "new-password" : "current-password"}
            required
          />
          {setupRequired && (
            <Field label="Setup token" name="setupToken" type="password" autoComplete="off" required />
          )}
          {error && <InlineError>{error}</InlineError>}
          <Button className="w-full" disabled={busy || setupRequired === null}>
            {busy ? <RefreshCw className="size-4 animate-spin" /> : <KeyRound className="size-4" />}
            {setupRequired ? "Create administrator" : "Sign in"}
          </Button>
        </form>
      </section>
    </main>
  );
}
