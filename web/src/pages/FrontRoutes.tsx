// Front door routes and protocol guidance (docs/design/front-door.md §3.8.2, FD-14). Lists every
// route with its listener, TLS mode and who it admits, and explains which protocols can be routed by
// name (TLS from the first byte, on 443 or a shared SNI port) and which need a dedicated raw port.

import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { FrontListeners, FrontRouteSummary, PlatformState } from "@/lib/types";
import { api } from "@/lib/utils";

import { InlineError } from "./Auth";

const KIND_LABEL: Record<string, string> = {
  http: "HTTP route (443)",
  tls: "tls route (SNI)",
  tcp: "tcp route (dedicated port)",
  postgres: "postgres route (FD-26)",
};

function admitsBadge(route: FrontRouteSummary) {
  if (!route.l4) return null;
  if (route.l4.admits === "internet") return <Badge variant="warning">internet (confirmed)</Badge>;
  if (route.l4.admits === "nobody") return <Badge variant="danger">nobody (empty list)</Badge>;
  return <Badge variant="info">{route.l4.sourceCidrs.length} CIDR(s)</Badge>;
}

/** Loads once per mount; App remounts it (by key) when the platform's operation list changes. */
export function FrontRoutesView(_props: { state: PlatformState }) {
  const [routes, setRoutes] = useState<FrontRouteSummary[] | null>(null);
  const [listeners, setListeners] = useState<FrontListeners | null>(null);
  const [error, setError] = useState("");

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
      })
      .catch(
        (cause) => !cancelled && setError(cause instanceof Error ? cause.message : "Could not load routes."),
      );
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="space-y-4">
      {error && <InlineError>{error}</InlineError>}
      <Card>
        <CardHeader>
          <CardTitle>Routes</CardTitle>
          <CardDescription>
            Public hostnames relayed to tailnet services. TLS-TCP and raw-TCP routes deny every source until
            their CIDR list admits one; only an owner-confirmed “allow internet” opens a route to everyone.
            Route changes are owner-only and need a step-up.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="table-head grid-cols-[1.4fr_1fr_0.6fr_0.9fr_1fr_auto]">
            <span>Hostname</span>
            <span>Kind</span>
            <span>Port</span>
            <span>Mode</span>
            <span>Admits</span>
            <span>Status</span>
          </div>
          {routes?.length === 0 && <p className="empty-state">No routes yet.</p>}
          {routes?.map((route) => (
            <div className="table-row grid-cols-[1.4fr_1fr_0.6fr_0.9fr_1fr_auto]" key={route.id}>
              <strong className="truncate">{route.hostname}</strong>
              <span>{KIND_LABEL[route.kind] ?? route.kind}</span>
              <span className="mono">{route.listenPort}</span>
              <span className="mono">{route.l4?.tlsMode ?? route.accessMode ?? "-"}</span>
              <span>{admitsBadge(route) ?? <span className="text-muted-foreground">-</span>}</span>
              <span className="flex gap-2">
                <Badge variant={route.enabled ? "success" : "neutral"}>
                  {route.enabled ? "enabled" : "disabled"}
                </Badge>
                <Badge variant={route.status === "ready" ? "success" : "warning"}>{route.status}</Badge>
              </span>
            </div>
          ))}
        </CardContent>
      </Card>

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
              : one raw TCP route per port (<span className="mono">plain</span> only). Never TLS-capable route
              kinds, and never the platform or mail ports{" "}
              <span className="mono">{listeners.reservedPorts.join(", ")}</span>.
            </p>
          </CardContent>
        </Card>
      )}

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
            <span className="mono">plain</span> (tcp routes only): a raw relay on a dedicated port. It needs a
            non-empty CIDR list, or “allow internet” with the protocol’s own authentication confirmed (for
            example SSH), both under an exposure.public step-up.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
