// Front door routes and protocol guidance (docs/design/front-door.md §3.8.2, §3.8.3, FD-14, FD-26).
// Lists every route with its listener, TLS mode and who it admits, lets an owner create TLS-TCP,
// raw-TCP and postgres routes and enable or disable them, and explains which protocols can be routed
// by name (TLS from the first byte, on 443, a shared SNI port or the 5432 router) and which need a
// dedicated raw port. HTTP routes have per-route controls (FD-23): a per-client rate limit and
// required client certificates, and mTLS routes of any kind list, issue and revoke their client
// certificates.

import { type FormEvent, Fragment, useEffect, useState } from "react";

import { HTTP_RATE_LIMIT_BOUNDS } from "@ark-stack/shared/http-rate-limit";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, Input, Label } from "@/components/ui/input";
import type { FrontListeners, FrontRouteSummary, PlatformState, RouteClientCertificates } from "@/lib/types";
import { ApiError, api, parseCidrList } from "@/lib/utils";

import { InlineError } from "./Auth";
import { DnsReviewPanel } from "./DnsReview";

const KIND_LABEL: Record<string, string> = {
  http: "HTTP route (443)",
  tls: "tls route (SNI)",
  tcp: "tcp route (dedicated port)",
  postgres: "postgres route (5432 SNI)",
};

function admitsBadge(route: FrontRouteSummary) {
  if (!route.l4) return null;
  if (route.l4.admits === "internet") return <Badge variant="warning">internet (confirmed)</Badge>;
  if (route.l4.admits === "nobody") return <Badge variant="danger">nobody (empty list)</Badge>;
  return <Badge variant="info">{route.l4.sourceCidrs.length} CIDR(s)</Badge>;
}

export function FrontRoutesView({ state }: { state: PlatformState }) {
  const isOwner = state.user.role === "owner";
  const canReviewDns = state.user.role !== "viewer";
  const [routes, setRoutes] = useState<FrontRouteSummary[] | null>(null);
  const [listeners, setListeners] = useState<FrontListeners | null>(null);
  const [error, setError] = useState("");
  const [openDns, setOpenDns] = useState<string | null>(null);
  const [openPanel, setOpenPanel] = useState<{ id: string; panel: "controls" | "certificates" } | null>(null);
  const toggle = (id: string, panel: "controls" | "certificates") =>
    setOpenPanel((open) => (open?.id === id && open.panel === panel ? null : { id, panel }));
  const [refreshRevision, setRefreshRevision] = useState(0);
  const refresh = () => setRefreshRevision((revision) => revision + 1);
  const routeRevision = JSON.stringify(state.operations.map(({ id, status }) => [id, status]));

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      api<{ routes: FrontRouteSummary[] }>("/api/front/routes"),
      api<FrontListeners>("/api/front/listeners"),
    ])
      .then(([list, ports]) => {
        if (cancelled) return;
        setRoutes(list.routes);
        setListeners(ports);
        setError("");
      })
      .catch(
        (cause) => !cancelled && setError(cause instanceof Error ? cause.message : "Could not load routes."),
      );
    return () => {
      cancelled = true;
    };
    // Refresh the route list after operations and direct edits without remounting the DNS review.
    // oxlint-disable-next-line react/exhaustive-effect-dependencies
  }, [routeRevision, refreshRevision]);

  const columns = isOwner
    ? "grid-cols-[1.4fr_1fr_0.7fr_0.9fr_1fr_auto_auto]"
    : "grid-cols-[1.4fr_1fr_0.7fr_0.9fr_1fr_auto]";

  return (
    <div className="space-y-4">
      {error && <InlineError>{error}</InlineError>}
      <Card>
        <CardHeader>
          <CardTitle>Routes</CardTitle>
          <CardDescription>
            Public hostnames relayed to tailnet services. TLS-TCP and raw-TCP routes deny every source until
            their CIDR list admits one; only an owner-confirmed “allow internet” opens a route to everyone.
            Only owners can change routes. Changes that widen access require password verification.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className={`table-head ${columns}`}>
            <span>Hostname</span>
            <span>Kind</span>
            <span>Port</span>
            <span>Mode</span>
            <span>Admits</span>
            <span>Status</span>
            {isOwner && <span>Actions</span>}
          </div>
          {routes?.length === 0 && <p className="empty-state">No routes yet.</p>}
          {routes?.map((route) => (
            <Fragment key={route.id}>
              <div className={`table-row ${columns}`}>
                <strong className="truncate">{route.hostname}</strong>
                <span>{KIND_LABEL[route.kind] ?? route.kind}</span>
                <span>
                  <span className="mono">{route.listenPort}</span>
                  {route.l4?.compatPort != null && (
                    <span className="block text-xs text-muted-foreground">
                      compat <span className="mono">{route.l4.compatPort}</span>
                    </span>
                  )}
                </span>
                <span className="flex flex-wrap items-center gap-1">
                  <span className="mono">{route.l4?.tlsMode ?? route.accessMode ?? "-"}</span>
                  {route.mtls && <Badge variant="info">client certificate</Badge>}
                  {route.rateLimit && (
                    <Badge variant="neutral">
                      {route.rateLimit.requests}/{route.rateLimit.window}
                    </Badge>
                  )}
                </span>
                <span>{admitsBadge(route) ?? <span className="text-muted-foreground">-</span>}</span>
                <span className="flex flex-wrap items-center gap-2">
                  <Badge variant={route.enabled ? "success" : "neutral"}>
                    {route.enabled ? "enabled" : "disabled"}
                  </Badge>
                  <Badge variant={route.status === "ready" ? "success" : "warning"}>{route.status}</Badge>
                  {isOwner && route.kind === "http" && (
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-expanded={openPanel?.id === route.id && openPanel.panel === "controls"}
                      onClick={() => toggle(route.id, "controls")}
                    >
                      Controls
                    </Button>
                  )}
                  {isOwner && hasClientCertificates(route) && (
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-expanded={openPanel?.id === route.id && openPanel.panel === "certificates"}
                      onClick={() => toggle(route.id, "certificates")}
                    >
                      Certificates
                    </Button>
                  )}
                  {route.domain && canReviewDns && (
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-expanded={openDns === route.id}
                      onClick={() => setOpenDns((open) => (open === route.id ? null : route.id))}
                    >
                      DNS
                    </Button>
                  )}
                </span>
                {isOwner && <RouteActions route={route} onChanged={refresh} />}
                {route.lastError && <p className="col-span-full text-xs text-red-200">{route.lastError}</p>}
              </div>
              {isOwner && openPanel?.id === route.id && openPanel.panel === "controls" && (
                <div className="border-t border-border p-4">
                  <HttpControlsPanel route={route} onChanged={refresh} />
                </div>
              )}
              {isOwner && openPanel?.id === route.id && openPanel.panel === "certificates" && (
                <div className="border-t border-border p-4">
                  <ClientCertificatesPanel route={route} />
                </div>
              )}
              {openDns === route.id && route.domain && canReviewDns && (
                <div className="border-t border-border p-4">
                  <DnsReviewPanel reviewPath={`/api/front/routes/${route.id}/dns`} owner={isOwner} />
                </div>
              )}
            </Fragment>
          ))}
        </CardContent>
      </Card>

      {isOwner && listeners && <CreateRouteForm listeners={listeners} onCreated={refresh} />}

      {listeners && (
        <Card>
          <CardHeader>
            <CardTitle>Listeners</CardTitle>
            <CardDescription>
              Shared SNI ports are chosen at install time (each is a published port on the edge node).
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p>
              <strong>443</strong>: HTTP routes, the login origin, the admin site and{" "}
              <span className="mono">tls</span> routes, told apart by SNI.
            </p>
            <p>
              <strong>Shared SNI ports</strong>:{" "}
              {listeners.sharedSniPorts.available.map((port) => (
                <Badge
                  key={port}
                  className="mr-1"
                  variant={listeners.sharedSniPorts.enabled.includes(port) ? "success" : "neutral"}
                >
                  {port} {listeners.sharedSniPorts.enabled.includes(port) ? "enabled" : "off"}
                </Badge>
              ))}
            </p>
            <p>
              <strong>
                {listeners.tcpPorts.start}–{listeners.tcpPorts.end}
              </strong>
              : one raw TCP route per port (<span className="mono">plain</span> only), or a postgres route’s
              compatibility port. Never TLS-capable route kinds, and never the platform or mail ports{" "}
              <span className="mono">{listeners.reservedPorts.join(", ")}</span>.
            </p>
            {listeners.postgres && (
              <p>
                <strong>{listeners.postgres.port}</strong>: <span className="mono">postgres</span> routes by
                SNI (direct TLS), and PgBouncer for Ark databases (classic SSLRequest) behind one pooler-wide
                source policy.
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {listeners?.postgres && <PostgresRouteGuidance postgres={listeners.postgres} />}

      <Card>
        <CardHeader>
          <CardTitle>Which protocols can be routed by name?</CardTitle>
          <CardDescription>
            Only protocols that start TLS with the first byte carry a hostname (SNI) the edge can route on.
            Everything else needs a dedicated port from the raw range, or should stay on the tailnet.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="table-head grid-cols-[1.5fr_1fr_1fr_0.6fr_1.6fr]">
            <span>Protocol</span>
            <span>TLS from the first byte?</span>
            <span>Route by name?</span>
            <span>Kind</span>
            <span>Notes</span>
          </div>
          {(listeners?.guidance ?? []).map((row) => (
            <div className="table-row grid-cols-[1.5fr_1fr_1fr_0.6fr_1.6fr] text-sm" key={row.protocol}>
              <strong>{row.protocol}</strong>
              <span>{row.tlsFirst}</span>
              <span>{row.byName}</span>
              <span className="mono">{row.kind ?? "-"}</span>
              <span className="text-muted-foreground">{row.notes}</span>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>TLS modes</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p>
            <span className="mono">passthrough</span>: the target terminates TLS with its own certificate; the
            edge relays after matching SNI. Harden the target (client certificates or strong authentication).
          </p>
          <p>
            <span className="mono">terminate_mtls</span>: the edge terminates TLS with the hostname’s
            certificate and requires a client certificate from the route’s own CA, checked against its CRL,
            then forwards plaintext over WireGuard.
          </p>
          <p>
            <span className="mono">terminate</span>: as above without client certificates; it needs a
            restricted, non-empty CIDR list.
          </p>
          <p>
            <span className="mono">postgres</span> routes use the same three modes on 5432: passthrough for
            PostgreSQL ≥ 17 targets (they terminate direct TLS themselves), terminate or terminate_mtls for
            older targets.
          </p>
          <p>
            <span className="mono">plain</span> (tcp routes only): a raw relay on a dedicated port. It needs a
            non-empty CIDR list, or “allow internet” with the protocol’s own authentication confirmed (for
            example SSH), both under an exposure.public step-up.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

function hasClientCertificates(route: FrontRouteSummary) {
  return route.kind === "http" ? route.mtls === true : route.l4?.tlsMode === "terminate_mtls";
}

const RATE_WINDOW = /^([1-9][0-9]{0,5})(s|m|h)$/;
const WINDOW_SECONDS = { s: 1, m: 60, h: 3_600 } as const;

/** Client-side check of a rate limit (FD-23); the API applies the same bounds. */
function rateLimitError(requests: number, window: string) {
  if (!Number.isInteger(requests) || requests < 1 || requests > HTTP_RATE_LIMIT_BOUNDS.requests.max)
    return `Requests must be a whole number from 1 to ${HTTP_RATE_LIMIT_BOUNDS.requests.max}.`;
  const match = RATE_WINDOW.exec(window);
  const seconds = match ? Number(match[1]) * WINDOW_SECONDS[match[2] as keyof typeof WINDOW_SECONDS] : 0;
  if (!match || seconds < 1 || seconds > 3_600) return "The window must be from 1s to 1h, such as 10s or 1m.";
  return "";
}

/** Owner controls of an HTTP route (FD-23). The API decides when a change needs step-up. */
function HttpControlsPanel({ route, onChanged }: { route: FrontRouteSummary; onChanged: () => void }) {
  const [baseline, setBaseline] = useState(route);
  const [limited, setLimited] = useState(Boolean(route.rateLimit));
  const [mtls, setMtls] = useState(route.mtls === true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");
  const [needsPassword, setNeedsPassword] = useState(false);

  function clearStepUp() {
    setNeedsPassword(false);
    setSaved("");
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const requests = Number(String(form.get("requests") ?? "").trim());
    const period = String(form.get("window") ?? "").trim();
    setError("");
    setSaved("");
    const invalid = limited ? rateLimitError(requests, period) : "";
    if (invalid) {
      setError(invalid);
      return;
    }
    const limitChanged =
      limited !== Boolean(baseline.rateLimit) ||
      (limited && (requests !== baseline.rateLimit?.requests || period !== baseline.rateLimit.window));
    const mtlsChanged = mtls !== Boolean(baseline.mtls);
    if (!limitChanged && !mtlsChanged) return;
    const body = {
      version: baseline.version,
      ...(limitChanged ? { rateLimit: limited ? { requests, window: period } : null } : {}),
      ...(mtlsChanged ? { mtls } : {}),
    };
    if (
      mtlsChanged &&
      mtls &&
      !needsPassword &&
      !window.confirm("Require a client certificate? Open connections without one are closed.")
    )
      return;
    setBusy(true);
    try {
      if (needsPassword) {
        await api("/api/step-up", {
          method: "POST",
          body: JSON.stringify({
            password: form.get("password"),
            action: "exposure.public",
            request: { routeId: route.id, ...body },
          }),
        });
      }
      const updated = await api<{ route: FrontRouteSummary }>(`/api/front/routes/${route.id}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      });
      setBaseline(updated.route);
      setNeedsPassword(false);
      setSaved("Saved. The edge applies the change within seconds.");
      onChanged();
    } catch (cause) {
      if (cause instanceof ApiError && cause.code === "exposure_step_up_required") {
        setNeedsPassword(true);
      } else {
        if (cause instanceof ApiError && cause.status === 409) setNeedsPassword(false);
        setError(cause instanceof Error ? cause.message : "Could not save the route controls.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="grid gap-4 md:grid-cols-2" onSubmit={submit}>
      <label className="flex items-start gap-2 text-sm md:col-span-2">
        <input
          type="checkbox"
          className="mt-1"
          checked={limited}
          disabled={busy}
          onChange={(event) => {
            setLimited(event.target.checked);
            clearStepUp();
          }}
        />
        <span>
          Limit requests per client
          <span className="block text-xs text-muted-foreground">
            Requests over the limit from one client address get 429 with Retry-After, before the login gate
            and the upstream.
          </span>
        </span>
      </label>
      {limited && (
        <>
          <Field
            label="Requests"
            name="requests"
            type="number"
            min={1}
            max={HTTP_RATE_LIMIT_BOUNDS.requests.max}
            defaultValue={baseline.rateLimit?.requests ?? 60}
            onChange={clearStepUp}
            disabled={busy}
            required
          />
          <Field
            label="Per window (1s to 1h)"
            name="window"
            defaultValue={baseline.rateLimit?.window ?? "1m"}
            onChange={clearStepUp}
            disabled={busy}
            pattern="[1-9][0-9]*(s|m|h)"
            required
          />
        </>
      )}
      <label className="flex items-start gap-2 text-sm md:col-span-2">
        <input
          type="checkbox"
          className="mt-1"
          checked={mtls}
          disabled={busy}
          onChange={(event) => {
            setMtls(event.target.checked);
            clearStepUp();
          }}
        />
        <span>
          Require a client certificate (mTLS)
          <span className="block text-xs text-muted-foreground">
            The TLS handshake fails without an unrevoked certificate from this route’s own CA. Works with
            either access mode: with Ark login, users need both a certificate and a sign-in. Switching it off
            retires the CA and every certificate it issued.
          </span>
        </span>
      </label>
      {needsPassword && (
        <Field
          label="Verify your password to widen access"
          name="password"
          type="password"
          autoComplete="current-password"
          disabled={busy}
          required
        />
      )}
      {error && (
        <div className="md:col-span-2">
          <InlineError>{error}</InlineError>
        </div>
      )}
      {saved && <p className="text-sm md:col-span-2">{saved}</p>}
      <div className="md:col-span-2">
        <Button disabled={busy}>Save controls</Button>
      </div>
    </form>
  );
}

/**
 * Client certificates of an mTLS route (terminate_mtls, FD-14; HTTP mTLS, FD-23). Issuing needs a
 * credential.rotate step-up bound to the route and the exact request; revoking tightens and needs none.
 */
function ClientCertificatesPanel({ route }: { route: FrontRouteSummary }) {
  const [list, setList] = useState<RouteClientCertificates | null>(null);
  const [revision, setRevision] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [issued, setIssued] = useState<{
    certPem: string;
    caCertPem: string;
    keySecretId: string | null;
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    api<RouteClientCertificates>(`/api/front/routes/${route.id}/client-certificates`)
      .then((value) => !cancelled && setList(value))
      .catch((cause) => !cancelled && setError(cause instanceof Error ? cause.message : "Could not load."));
    return () => {
      cancelled = true;
    };
    // `revision` reloads the list after an issue or revoke.
    // oxlint-disable-next-line react/exhaustive-effect-dependencies
  }, [route.id, revision]);

  async function issue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const csrPem = String(form.get("csrPem") ?? "").trim();
    const body: Record<string, string> = { name: String(form.get("name") ?? "").trim() };
    if (csrPem) body.csrPem = csrPem;
    setBusy(true);
    setError("");
    setIssued(null);
    try {
      await api("/api/step-up", {
        method: "POST",
        body: JSON.stringify({
          password: form.get("password"),
          action: "credential.rotate",
          request: { routeId: route.id, ...body },
        }),
      });
      const result = await api<{ certPem: string; caCertPem: string; keySecretId: string | null }>(
        `/api/front/routes/${route.id}/client-certificates`,
        { method: "POST", body: JSON.stringify(body) },
      );
      formElement.reset();
      setIssued(result);
      setRevision((value) => value + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not issue the certificate.");
    } finally {
      setBusy(false);
    }
  }

  async function revoke(certificateId: string, name: string) {
    if (!window.confirm(`Revoke ${name}? Its connections to ${route.hostname} are closed.`)) return;
    setBusy(true);
    setError("");
    try {
      await api(`/api/front/routes/${route.id}/client-certificates/${certificateId}/revoke`, {
        method: "POST",
        body: "{}",
      });
      setRevision((value) => value + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not revoke the certificate.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4 text-sm">
      {error && <InlineError>{error}</InlineError>}
      {list?.ca && (
        <p>
          Route CA <span className="mono">{list.ca.id}</span> ({list.ca.status}). Clients must present a
          certificate it issued; revoked and expired certificates are refused in the TLS handshake.
        </p>
      )}
      {list && list.certificates.length === 0 && <p className="empty-state">No client certificates yet.</p>}
      {list?.certificates.map((item) => (
        <div key={item.id} className="flex flex-wrap items-center gap-2">
          <strong>{item.subjectCn}</strong>
          <span className="mono text-xs">{item.serial}</span>
          <Badge variant={item.status === "issued" ? "success" : "neutral"}>{item.status}</Badge>
          <span className="text-xs text-muted-foreground">expires {item.notAfter.slice(0, 10)}</span>
          {item.status === "issued" && (
            <Button
              size="sm"
              variant="outline"
              disabled={busy}
              onClick={() => void revoke(item.id, item.subjectCn)}
            >
              Revoke
            </Button>
          )}
        </div>
      ))}
      <form className="grid gap-4 md:grid-cols-2" onSubmit={issue}>
        <Field label="Certificate name" name="name" placeholder="laptop-alice" maxLength={64} required />
        <Field
          label="Current password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
        />
        <div className="md:col-span-2">
          <Label htmlFor={`csr-${route.id}`}>CSR (optional)</Label>
          <textarea
            id={`csr-${route.id}`}
            name="csrPem"
            className="min-h-20 w-full rounded-lg border border-input bg-background p-3 font-mono text-xs"
            placeholder="-----BEGIN CERTIFICATE REQUEST----- (empty: Ark generates a key you reveal once)"
          />
        </div>
        <div className="md:col-span-2">
          <Button disabled={busy}>Issue certificate</Button>
        </div>
      </form>
      {issued && (
        <div className="space-y-2">
          <p>
            Issued.{" "}
            {issued.keySecretId
              ? `Reveal the generated private key once as secret ${issued.keySecretId} (secret.reveal step-up).`
              : "Use the private key of your CSR."}
          </p>
          <pre className="mono overflow-x-auto rounded-lg border border-border p-3 text-xs">
            {issued.certPem}
          </pre>
        </div>
      )}
    </div>
  );
}

/** Owner actions on one route: enabling needs an exposure.public step-up bound to the route id. */
function RouteActions({ route, onChanged }: { route: FrontRouteSummary; onChanged: () => void }) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function enable(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const password = String(new FormData(event.currentTarget).get("password") ?? "");
    setBusy(true);
    setError("");
    try {
      const request = { routeId: route.id };
      await api("/api/step-up", {
        method: "POST",
        body: JSON.stringify({ password, action: "exposure.public", request }),
      });
      await api(`/api/front/routes/${route.id}/enable`, { method: "POST", body: "{}" });
      setConfirming(false);
      onChanged();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not enable the route.");
    } finally {
      setBusy(false);
    }
  }

  async function disable() {
    setBusy(true);
    setError("");
    try {
      // Disabling tightens exposure, so it needs no step-up.
      await api(`/api/front/routes/${route.id}/disable`, { method: "POST", body: "{}" });
      onChanged();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not disable the route.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <span className="flex flex-col items-end gap-2">
      {route.enabled ? (
        <Button size="sm" variant="outline" disabled={busy} onClick={() => void disable()}>
          Disable
        </Button>
      ) : confirming ? (
        <form className="flex items-center gap-2" onSubmit={enable}>
          <Input
            name="password"
            type="password"
            autoComplete="current-password"
            placeholder="Current password"
            aria-label={`Current password to enable ${route.hostname}`}
            className="h-8 w-40"
            required
          />
          <Button size="sm" disabled={busy}>
            Enable
          </Button>
          <Button size="sm" type="button" variant="ghost" onClick={() => setConfirming(false)}>
            Cancel
          </Button>
        </form>
      ) : (
        <Button
          size="sm"
          variant="outline"
          disabled={route.status !== "ready"}
          onClick={() => setConfirming(true)}
        >
          Enable…
        </Button>
      )}
      {error && <span className="max-w-xs text-xs text-red-200">{error}</span>}
    </span>
  );
}

type CreateKind = "tls" | "tcp" | "postgres";
type TlsMode = "passthrough" | "terminate" | "terminate_mtls";

const TLS_MODE_HINT: Record<TlsMode, string> = {
  passthrough: "The target terminates TLS with its own certificate.",
  terminate: "The edge terminates TLS; needs a restricted, non-empty CIDR list.",
  terminate_mtls: "The edge terminates TLS and requires a client certificate from the route’s CA.",
};

/** Owner form for `tls`, `tcp` and `postgres` routes; creating needs an exposure.public step-up. */
function CreateRouteForm({ listeners, onCreated }: { listeners: FrontListeners; onCreated: () => void }) {
  const [kind, setKind] = useState<CreateKind>("tls");
  const [tlsMode, setTlsMode] = useState<TlsMode>("passthrough");
  const [allowInternet, setAllowInternet] = useState(false);
  const [compatEnabled, setCompatEnabled] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [created, setCreated] = useState<{
    hostname: string;
    records: Array<{ type: string; name: string; value: string; required: boolean }>;
  } | null>(null);
  const postgres = listeners.postgres;
  const compatRange = postgres?.compatPorts ?? listeners.tcpPorts;
  const compatAllowed = kind === "postgres" && tlsMode === "passthrough";
  const internetAllowed = kind === "tcp" || tlsMode !== "terminate";

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const text = (name: string) => String(form.get(name) ?? "").trim();
    setError("");
    setCreated(null);
    const openToInternet = allowInternet && internetAllowed;
    const body: Record<string, unknown> = {
      kind,
      hostname: text("hostname"),
      target: text("target"),
      targetPort: Number(text("targetPort")),
      sourceCidrs: openToInternet ? [] : parseCidrList(text("sourceCidrs")),
      allowInternet: openToInternet,
    };
    if (kind === "tls") {
      body.listenPort = Number(text("listenPort"));
      body.tlsMode = tlsMode;
    } else if (kind === "tcp") {
      body.listenPort = Number(text("listenPort"));
      body.tlsMode = "plain";
      body.allowPlaintext = form.has("allowPlaintext");
      body.protocolAuthConfirmed = form.has("protocolAuthConfirmed");
    } else {
      // Postgres routes always listen on the 5432 router; omit listenPort.
      body.tlsMode = tlsMode;
      body.compatPort = compatAllowed && compatEnabled ? Number(text("compatPort")) : null;
    }
    if (
      openToInternet &&
      !window.confirm(`Open ${String(body.hostname)} to every source on the internet once it is enabled?`)
    ) {
      return;
    }
    setBusy(true);
    try {
      await api("/api/step-up", {
        method: "POST",
        body: JSON.stringify({ password: form.get("password"), action: "exposure.public", request: body }),
      });
      const result = await api<{
        route: FrontRouteSummary;
        records: Array<{ type: string; name: string; value: string; required: boolean }>;
      }>("/api/front/routes", { method: "POST", body: JSON.stringify(body) });
      formElement.reset();
      setAllowInternet(false);
      setCompatEnabled(false);
      setCreated({ hostname: result.route.hostname, records: result.records });
      onCreated();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not create the route.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Create a TLS, TCP or postgres route</CardTitle>
        <CardDescription>
          New routes start disabled and deny every source until their CIDR list admits one. Enable a route
          once it is ready (ACL probe, DNS and certificate). Creating needs your password for an
          exposure.public step-up.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form className="grid gap-4 md:grid-cols-2" onSubmit={submit}>
          <div>
            <Label htmlFor="routeKind">Kind</Label>
            <select
              id="routeKind"
              className="select"
              value={kind}
              onChange={(event) => setKind(event.target.value as CreateKind)}
            >
              <option value="tls">tls: TLS-TCP by SNI (443 or a shared SNI port)</option>
              <option value="tcp">tcp: raw TCP on a dedicated port</option>
              {postgres && <option value="postgres">postgres: PostgreSQL by SNI on {postgres.port}</option>}
            </select>
          </div>
          <Field label="Hostname" name="hostname" placeholder="db.example.com" required />
          <Field label="Tailnet target" name="target" placeholder="pg-host.tailnet.ts.net" required />
          <Field
            label="Target port"
            name="targetPort"
            type="number"
            min={1}
            max={65535}
            defaultValue={kind === "postgres" ? 5432 : undefined}
            key={`targetPort-${kind}`}
            required
          />

          {kind === "tls" && (
            <div>
              <Label htmlFor="listenPort">Listen port</Label>
              <select
                id="listenPort"
                name="listenPort"
                className="select"
                defaultValue={listeners.sniRouterPort}
              >
                <option value={listeners.sniRouterPort}>{listeners.sniRouterPort} (SNI router)</option>
                {listeners.sharedSniPorts.enabled.map((port) => (
                  <option key={port} value={port}>
                    {port} (shared SNI port)
                  </option>
                ))}
              </select>
            </div>
          )}
          {kind === "tcp" && (
            <Field
              label={`Dedicated port (${listeners.tcpPorts.start}–${listeners.tcpPorts.end})`}
              name="listenPort"
              type="number"
              min={listeners.tcpPorts.start}
              max={listeners.tcpPorts.end}
              required
            />
          )}
          {kind === "postgres" && postgres && (
            <div>
              <Label>Listen port</Label>
              <p className="flex h-10 items-center text-sm">
                <span className="mono">{postgres.port}</span>
                <span className="ml-2 text-xs text-muted-foreground">
                  always the 5432 router (direct TLS by SNI)
                </span>
              </p>
            </div>
          )}

          {kind !== "tcp" && (
            <div>
              <Label htmlFor="tlsMode">TLS mode</Label>
              <select
                id="tlsMode"
                className="select"
                value={tlsMode}
                onChange={(event) => setTlsMode(event.target.value as TlsMode)}
              >
                {(["passthrough", "terminate", "terminate_mtls"] as const).map((mode) => (
                  <option key={mode} value={mode}>
                    {mode}
                  </option>
                ))}
              </select>
              <p className="mt-1 text-xs text-muted-foreground">
                {kind === "postgres"
                  ? "passthrough for PG ≥ 17; terminate/terminate_mtls for older targets. "
                  : ""}
                {TLS_MODE_HINT[tlsMode]}
              </p>
            </div>
          )}

          {kind === "postgres" && postgres && (
            <div className="md:col-span-2 rounded-lg border border-border p-3">
              <label className="flex items-start gap-2 text-sm">
                <input
                  type="checkbox"
                  className="mt-1"
                  checked={compatAllowed && compatEnabled}
                  disabled={!compatAllowed}
                  onChange={(event) => setCompatEnabled(event.target.checked)}
                />
                <span>
                  Compatibility port (off by default)
                  <span className="block text-xs text-muted-foreground">
                    A fallback for drivers without direct TLS: a dedicated raw port from {compatRange.start}–
                    {compatRange.end} relayed to the target, which answers classic SSLRequest itself. It
                    inherits this route’s CIDRs and limits. Passthrough only.
                  </span>
                </span>
              </label>
              {compatAllowed && compatEnabled && (
                <div className="mt-3 max-w-xs">
                  <Field
                    label="Compatibility port"
                    name="compatPort"
                    type="number"
                    min={compatRange.start}
                    max={compatRange.end}
                    required
                  />
                </div>
              )}
            </div>
          )}

          <div className="md:col-span-2">
            <Label htmlFor="routeCidrs">Source CIDRs</Label>
            <textarea
              id="routeCidrs"
              name="sourceCidrs"
              className="min-h-20 w-full rounded-lg border border-input bg-background p-3 font-mono text-xs disabled:opacity-50"
              placeholder={"203.0.113.0/24\n2001:db8::/48"}
              disabled={allowInternet && internetAllowed}
            />
            <p className="mt-1 text-xs text-muted-foreground">
              One per line or comma-separated. Empty denies every source; the route cannot be enabled until it
              admits someone.
            </p>
          </div>
          <label className="flex items-start gap-2 text-sm md:col-span-2">
            <input
              type="checkbox"
              className="mt-1"
              checked={allowInternet && internetAllowed}
              disabled={!internetAllowed}
              onChange={(event) => setAllowInternet(event.target.checked)}
            />
            <span>
              Allow the internet
              <span className="block text-xs text-muted-foreground">
                {internetAllowed
                  ? "Every source may connect once the route is enabled; saved as your exposure.public confirmation."
                  : "terminate (no client certificates) needs a restricted CIDR list."}
              </span>
            </span>
          </label>

          {kind === "tcp" && (
            <>
              <label className="flex items-start gap-2 text-sm">
                <input type="checkbox" name="allowPlaintext" className="mt-1" required />
                <span>
                  Allow plaintext
                  <span className="block text-xs text-muted-foreground">
                    The protocol may cross the internet without TLS.
                  </span>
                </span>
              </label>
              <label className="flex items-start gap-2 text-sm">
                <input type="checkbox" name="protocolAuthConfirmed" className="mt-1" />
                <span>
                  The protocol authenticates itself
                  <span className="block text-xs text-muted-foreground">
                    Required to allow the internet (for example SSH).
                  </span>
                </span>
              </label>
            </>
          )}

          {kind === "postgres" && (
            <p className="text-xs text-muted-foreground md:col-span-2">
              Harden the target before enabling the route: see the target checklist and driver guidance under
              “Postgres routes” below.
            </p>
          )}

          <Field
            label="Current password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
          />
          {error && (
            <div className="md:col-span-2">
              <InlineError>{error}</InlineError>
            </div>
          )}
          {created && (
            <div className="space-y-1 text-sm md:col-span-2">
              <p>
                Created <strong>{created.hostname}</strong> (disabled). Publish these DNS records, then enable
                it once it is ready:
              </p>
              {created.records.map((record) => (
                <p key={`${record.type}-${record.name}`} className="mono text-xs">
                  {record.type} {record.name} {record.value}
                  {record.required ? "" : " (optional)"}
                </p>
              ))}
            </div>
          )}
          <div className="md:col-span-2">
            <Button disabled={busy}>Create route</Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

/** Target hardening, client settings and driver support for `postgres` routes (§3.8.3). */
function PostgresRouteGuidance({ postgres }: { postgres: NonNullable<FrontListeners["postgres"]> }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Postgres routes ({postgres.port})</CardTitle>
        <CardDescription>
          Clients that open TLS directly (sslnegotiation=direct) are routed to a tailnet PostgreSQL by SNI.
          Classic SSLRequest connections on {postgres.port} reach PgBouncer for Ark databases, never a route.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5 text-sm">
        <ul className="list-disc space-y-1 pl-5">
          {postgres.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
          <li>
            Compatibility ports come from {postgres.compatPorts.start}–{postgres.compatPorts.end}, are off by
            default and work with passthrough only.
          </li>
        </ul>

        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-[0.08em] text-muted-foreground">
            Target-hardening checklist
          </h3>
          <ol className="list-decimal space-y-2 pl-5">
            {postgres.checklist.map((item) => (
              <li key={item.id}>
                <strong>{item.title}</strong>
                <span className="block text-muted-foreground">{item.detail}</span>
              </li>
            ))}
          </ol>
        </section>

        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-[0.08em] text-muted-foreground">
            Driver support for direct TLS
          </h3>
          <div className="rounded-lg border border-border">
            <div className="table-head grid-cols-[1.4fr_1.4fr_0.7fr_0.7fr]">
              <span>Client</span>
              <span>Option</span>
              <span>Since</span>
              <span>Status</span>
            </div>
            {postgres.drivers.map((driver) => (
              <div className="table-row grid-cols-[1.4fr_1.4fr_0.7fr_0.7fr]" key={driver.client}>
                <strong>{driver.client}</strong>
                <span className="mono text-xs">{driver.option}</span>
                <span className="text-muted-foreground">{driver.since}</span>
                <span>
                  <Badge variant={driver.verified ? "success" : "warning"}>
                    {driver.verified ? "verified" : "unverified"}
                  </Badge>
                </span>
              </div>
            ))}
          </div>
          <p className="mt-2 text-xs text-muted-foreground">
            Unverified rows come from driver documentation and were not prototyped; test them before relying
            on them, or use the compatibility port.
          </p>
        </section>

        <p
          className="rounded-lg border border-amber-300/30 bg-amber-500/10 p-3 text-xs text-amber-100"
          role="note"
        >
          Ark databases on the same port: {postgres.poolerBoundary}
        </p>
      </CardContent>
    </Card>
  );
}
