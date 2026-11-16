// Front door ACL snippet (docs/design/front-door.md §3.7, FD-07). Ark never writes the tailnet
// policy: the owner copies this snippet into it. Owner-only, like route management.

import { Check, Copy } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { FrontAclSnippet, PlatformState } from "@/lib/types";
import { api, cn, formatDate } from "@/lib/utils";

import { InlineError } from "./Auth";

export function FrontAclView({ state }: { state: PlatformState }) {
  const isOwner = state.user.role === "owner";
  const [scope, setScope] = useState("global");
  const [response, setData] = useState<FrontAclSnippet | null>(null);
  const [routes, setRoutes] = useState<FrontAclSnippet["routes"]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const requestId = useRef(0);
  const data =
    !loading &&
    !error &&
    (scope === "global"
      ? response?.scope === "global"
      : response?.scope === "route" && response.routeId === scope)
      ? response
      : null;

  const load = useCallback(async (next: string) => {
    const id = ++requestId.current;
    setData(null);
    setLoading(true);
    setError("");
    try {
      const path = next === "global" ? "/api/front/acl" : `/api/front/routes/${encodeURIComponent(next)}/acl`;
      const result = await api<FrontAclSnippet>(path);
      if (id !== requestId.current) return;
      if (next === "global" ? result.scope !== "global" : result.scope !== "route" || result.routeId !== next)
        throw new Error("The server returned a different ACL scope. Regenerate to retry.");
      setData(result);
      if (result.scope === "global") setRoutes(result.routes);
    } catch (cause) {
      if (id !== requestId.current) return;
      setError(cause instanceof Error ? cause.message : "Could not load the ACL snippet.");
    } finally {
      if (id === requestId.current) setLoading(false);
    }
  }, []);

  const invalidateRequests = useCallback(() => {
    requestId.current++;
  }, []);
  useEffect(() => {
    if (isOwner) void load(scope);
    return invalidateRequests;
  }, [isOwner, scope, load, invalidateRequests]);

  if (!isOwner) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Front door ACL</CardTitle>
          <CardDescription>Only an owner can view the tailnet policy snippet.</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Tailscale policy snippet</CardTitle>
          <CardDescription>
            Paste this into your tailnet policy file. It lets the edge node reach only the routed{" "}
            <span className="mono">host:port</span> targets, and the backup node only its backup target. Ark
            does not hold any Tailscale credential and never writes your policy. The{" "}
            <span className="mono">tests</span> block checks sampled TCP and UDP ports on known nodes and Ark
            tags. It catches broad allow-all rules, but cannot prove isolation on untested ports, other
            protocols, or unobserved nodes. Review all existing grants and ACLs before saving; use the local
            policy audit described in the operating guide for the full TCP/UDP port complement on known nodes.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-end gap-3">
            <div>
              <label htmlFor="acl-scope" className="mb-1.5 block text-xs font-semibold">
                Scope
              </label>
              <select
                id="acl-scope"
                className="select"
                value={scope}
                onChange={(event) => setScope(event.target.value)}
              >
                <option value="global">All routes and backup targets</option>
                {routes.map((route) => (
                  <option key={route.id} value={route.id}>
                    {route.hostname}:{route.listenPort} ({route.kind}, {route.status})
                  </option>
                ))}
              </select>
            </div>
            {data && <CopyButton key={`${scope}-${data.digest}`} text={data.snippet} label="Copy snippet" />}
            <Button variant="outline" onClick={() => void load(scope)} disabled={loading}>
              Regenerate
            </Button>
          </div>
          {loading && <p role="status">Loading the selected scope’s snippet…</p>}
          {error && <InlineError>{error}</InlineError>}
          {data && (
            <>
              <p className="text-xs text-muted-foreground">
                Generated {formatDate(data.generatedAt)}
                {data.tailnet ? ` for tailnet ${data.tailnet}` : ""} · digest{" "}
                <span className="mono">{data.digest.slice(0, 12)}</span>
              </p>
              {data.omitted.length > 0 && (
                <div className="rounded-lg border border-amber-300/30 bg-amber-500/10 p-3 text-sm">
                  <p className="font-semibold">Not granted</p>
                  <ul className="mt-1 list-disc pl-5">
                    {data.omitted.map((item) => (
                      <li key={`${item.kind}-${item.id}`}>
                        {item.kind} <span className="mono">{item.id}</span>: {item.reason}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <pre className="max-h-[32rem] overflow-auto rounded-lg border border-border p-3 text-xs">
                {data.snippet}
              </pre>
            </>
          )}
        </CardContent>
      </Card>

      {data && <DiffCard data={data} />}

      <div className="content-grid">
        <Card>
          <CardHeader>
            <CardTitle>Tailnet Lock</CardTitle>
            <CardDescription>Recommended for every tailnet that carries public routes.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p>
              Grants are only as trustworthy as the machines they name. With{" "}
              <a
                className="underline"
                href="https://tailscale.com/docs/features/tailnet-lock"
                target="_blank"
                rel="noreferrer"
              >
                Tailnet Lock
              </a>{" "}
              enabled, a new node cannot join until a trusted signing node you control signs its key, so a
              compromised coordination server cannot slip a node in under{" "}
              <span className="mono">tag:ark-edge</span> or impersonate a route target.
            </p>
            <ol className="list-decimal space-y-1 pl-5">
              <li>
                Initialise Tailnet Lock from two or more of your own devices (
                <span className="mono">tailscale lock init</span>), and keep the disablement secrets offline.
              </li>
              <li>
                After the edge node joins with its tagged auth key, sign it from a signing node:{" "}
                <span className="mono">tailscale lock sign &lt;node key&gt;</span>. Do the same for the backup
                node and every route target.
              </li>
              <li>
                Re-sign after replacing a machine. An unsigned target stays unreachable, so its route waits.
              </li>
            </ol>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>SSH policy example</CardTitle>
            <CardDescription>
              Optional Tailscale SSH to the Ark VPS (<span className="mono">tag:ark-vps</span>). It is not
              part of the snippet above.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p>
              <span className="mono">&quot;action&quot;: &quot;check&quot;</span> makes the user sign in again
              before a session starts, so a stolen laptop alone cannot open a shell. Add{" "}
              <span className="mono">root</span> to <span className="mono">users</span> only if you need it.
            </p>
            {data && (
              <>
                <pre className="overflow-auto rounded-lg border border-border p-3 text-xs">
                  {data.sshExample}
                </pre>
                <CopyButton text={data.sshExample} label="Copy SSH example" />
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function DiffCard({ data }: { data: FrontAclSnippet }) {
  const [changesOnly, setChangesOnly] = useState(true);
  const changes = data.diff?.filter((line) => line.op !== "same").length ?? 0;
  // Old and new line numbers identify each diff line uniquely.
  let oldLine = 0;
  let newLine = 0;
  const keyed = (data.diff ?? []).map((line) => {
    if (line.op !== "add") oldLine++;
    if (line.op !== "remove") newLine++;
    return { ...line, key: `${line.op}-${oldLine}-${newLine}` };
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>Changes since the last generated snippet</CardTitle>
        <CardDescription>
          {data.previous
            ? `Compared with the snippet generated ${formatDate(data.previous.generatedAt)} (digest ${data.previous.digest.slice(0, 12)}). Update your policy with the added and removed lines.`
            : "This is the first snippet Ark generated for this scope, so there is nothing to compare yet."}
        </CardDescription>
      </CardHeader>
      {data.diff && (
        <CardContent className="space-y-3">
          <div className="flex items-center gap-3">
            <Badge variant={changes ? "warning" : "neutral"}>{changes} changed lines</Badge>
            <Button variant="outline" size="sm" onClick={() => setChangesOnly((value) => !value)}>
              {changesOnly ? "Show full diff" : "Show changes only"}
            </Button>
          </div>
          <pre className="max-h-[24rem] overflow-auto rounded-lg border border-border p-3 text-xs">
            {keyed
              .filter((line) => !changesOnly || line.op !== "same")
              .map((line) => (
                <div
                  key={line.key}
                  className={cn(
                    line.op === "add" && "bg-emerald-500/15 text-emerald-200",
                    line.op === "remove" && "bg-red-500/15 text-red-200",
                  )}
                >
                  {line.op === "add" ? "+ " : line.op === "remove" ? "- " : "  "}
                  {line.line}
                </div>
              ))}
          </pre>
        </CardContent>
      )}
    </Card>
  );
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);
  return (
    <Button
      variant="outline"
      onClick={() => {
        setFailed(false);
        navigator.clipboard
          .writeText(text)
          .then(() => {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 2000);
          })
          .catch(() => setFailed(true));
      }}
    >
      {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
      {failed ? "Copy failed: select the text" : copied ? "Copied" : label}
    </Button>
  );
}
