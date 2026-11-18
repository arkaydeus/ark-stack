// The pooler-wide source policy on public PostgreSQL 5432 (docs/design/front-door.md §3.8.3, FD-26).
// Classic SSLRequest carries no database name, so PgBouncer enforces one policy for every Ark
// database; each database's CIDRs (and each legacy Vercel client) are only a request for that policy. This
// panel states that boundary, lists the requests and their conflicts, and lets an owner review and
// save one common policy. It never presents a database's own CIDRs as isolating it.

import { type FormEvent, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, Label } from "@/components/ui/input";
import type { PlatformState, PoolerPolicyFull, PoolerPolicyStatus, PoolerRequestSource } from "@/lib/types";
import { api, formatDate, parseCidrList } from "@/lib/utils";

import { InlineError } from "./Auth";

export const POOLER_POLICY_PANEL_ID = "pooler-policy";

const STATUS: Record<
  PoolerPolicyStatus,
  { label: string; variant: "success" | "warning" | "danger" | "neutral" }
> = {
  fenced: { label: "closed by safety fence", variant: "danger" },
  published: { label: "published", variant: "success" },
  no_public_databases: { label: "no public databases", variant: "neutral" },
  review_required: { label: "review required", variant: "warning" },
  unconfirmed_internet: { label: "internet not confirmed", variant: "warning" },
  deny_all: { label: "deny all", variant: "danger" },
  invalid_policy: { label: "invalid policy", variant: "danger" },
};

export function scrollToPoolerPolicy() {
  document.getElementById(POOLER_POLICY_PANEL_ID)?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function isFull(policy: NonNullable<PlatformState["poolerPolicy"]>): policy is PoolerPolicyFull {
  return "requestsFingerprint" in policy;
}

function sourceLabel(source: PoolerRequestSource, state: PlatformState) {
  if (source.kind === "database") return { kind: "database", name: source.name };
  const database = state.databases.find((item) => item.id === source.databaseId);
  return { kind: "Vercel client", name: database ? `${source.name} (${database.name})` : source.name };
}

/** "Public database port (5432)": status, boundary, saved policy, requests, conflicts and the owner editor. */
export function PoolerPolicyPanel({ state, reload }: { state: PlatformState; reload: () => Promise<void> }) {
  // Kept here, not in the editor: a save reloads the inventory, which remounts the editor.
  const [notice, setNotice] = useState<{ error: string } | { message: string } | null>(null);
  const policy = state.poolerPolicy;
  if (!policy) return null;
  const status = STATUS[policy.status] ?? { label: policy.status, variant: "neutral" as const };
  const full = isFull(policy) ? policy : null;
  return (
    <Card id={POOLER_POLICY_PANEL_ID} className="scroll-mt-6">
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <CardTitle>Public database port (5432)</CardTitle>
          <Badge variant="info">pooler-wide</Badge>
          <Badge variant={status.variant}>{status.label}</Badge>
        </div>
        <CardDescription>{policy.message}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-5 text-sm">
        <p className="rounded-lg border border-amber-300/30 bg-amber-500/10 p-3 text-amber-100" role="note">
          {policy.boundary}
        </p>

        {policy.conflict && !full && (
          <InlineError>
            Public databases request conflicting sources; an owner has to review one common pooler-wide policy
            before 5432 is published.
          </InlineError>
        )}

        {full && (
          <>
            {full.conflicts.length > 0 && (
              <div className="space-y-2">
                {full.conflicts.map((conflict) => (
                  <InlineError key={conflict.reason}>
                    <strong className="mr-1">
                      {conflict.reason === "different_cidrs"
                        ? "Different CIDRs requested."
                        : "Restricted and unrestricted requests share the pooler."}
                    </strong>
                    {conflict.message}
                  </InlineError>
                ))}
              </div>
            )}

            <section className="space-y-1">
              <h3 className="text-xs font-semibold uppercase tracking-[0.08em] text-muted-foreground">
                Saved pooler-wide policy
              </h3>
              <p>
                {full.policy.allowInternet ? (
                  <>
                    <Badge variant="warning">internet</Badge>{" "}
                    <span className="text-muted-foreground">
                      every source may reach PgBouncer
                      {full.policy.internetConfirmedAt
                        ? ` (owner-confirmed ${formatDate(full.policy.internetConfirmedAt)})`
                        : " (not confirmed by an owner step-up)"}
                    </span>
                  </>
                ) : full.policy.sourceCidrs.length ? (
                  <span className="mono">{full.policy.sourceCidrs.join(", ")}</span>
                ) : (
                  <Badge variant="danger">nobody (empty list)</Badge>
                )}
              </p>
              <p className="text-xs text-muted-foreground">
                {full.policy.reviewedAt
                  ? `Last reviewed ${formatDate(full.policy.reviewedAt)}${full.reviewed ? " against the current requests." : "; the requests have changed since."}`
                  : "Never reviewed."}{" "}
                {full.matchesRequests && "Every request matches the saved policy."}
              </p>
            </section>

            <section>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-[0.08em] text-muted-foreground">
                Requests ({full.distinctRequests.length} distinct)
              </h3>
              <div className="rounded-lg border border-border">
                <div className="table-head grid-cols-[0.8fr_1.2fr_1.6fr]">
                  <span>Source</span>
                  <span>Name</span>
                  <span>Requested sources</span>
                </div>
                {full.requests.length === 0 && (
                  <p className="empty-state">No public database requests 5432.</p>
                )}
                {full.requests.map((request) => {
                  const label = sourceLabel(request.source, state);
                  return (
                    <div className="table-row grid-cols-[0.8fr_1.2fr_1.6fr]" key={request.source.id}>
                      <span className="text-muted-foreground">{label.kind}</span>
                      <strong className="truncate">{label.name}</strong>
                      <span>
                        {request.unrestricted ? (
                          <Badge variant="warning">unrestricted</Badge>
                        ) : (
                          <span className="mono">{request.sourceCidrs.join(", ")}</span>
                        )}
                      </span>
                    </div>
                  );
                })}
              </div>
              <p className="mt-2 text-xs text-muted-foreground">
                A request is never enforced per database and requests are never merged automatically. Vercel
                clients have no stable egress addresses, so they always request an unrestricted pooler.
              </p>
            </section>

            {state.user.role === "owner" ? (
              <PoolerPolicyEditor
                key={`${full.requestsFingerprint}:${full.policy.allowInternet}:${full.policy.sourceCidrs.join(",")}`}
                policy={full}
                reload={reload}
                onNotice={setNotice}
              />
            ) : (
              <p className="text-xs text-muted-foreground">
                Only an owner can review and save the pooler policy.
              </p>
            )}
            {notice && "error" in notice && <InlineError>{notice.error}</InlineError>}
            {notice && "message" in notice && (
              <p className="text-sm text-muted-foreground">{notice.message}</p>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

function PoolerPolicyEditor({
  policy,
  reload,
  onNotice,
}: {
  policy: PoolerPolicyFull;
  reload: () => Promise<void>;
  onNotice: (notice: { error: string } | { message: string } | null) => void;
}) {
  const [cidrs, setCidrs] = useState(policy.policy.sourceCidrs.join("\n"));
  const [allowInternet, setAllowInternet] = useState(policy.policy.allowInternet);
  const [busy, setBusy] = useState(false);
  const parsed = parseCidrList(cidrs);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const password = String(new FormData(formElement).get("poolerPassword") ?? "");
    onNotice(null);
    if (
      allowInternet &&
      !policy.policy.allowInternet &&
      !window.confirm(
        "Allow the internet on public 5432? Every source will reach PgBouncer for every public Ark database.",
      )
    ) {
      return;
    }
    // The body echoes the requests fingerprint this panel displayed; the API refuses (409) if the
    // databases' requests changed since, so a save always covers exactly what was reviewed.
    const request = {
      sourceCidrs: allowInternet ? [] : parsed,
      allowInternet,
      reviewedRequests: policy.requestsFingerprint,
    };
    setBusy(true);
    try {
      await api("/api/step-up", {
        method: "POST",
        body: JSON.stringify({ password, action: "exposure.public", request }),
      });
      await api("/api/databases/pooler-policy", { method: "PUT", body: JSON.stringify(request) });
      formElement.reset();
      onNotice({ message: "Pooler-wide policy saved. The edge and PgBouncer are being reapplied." });
      await reload();
    } catch (cause) {
      onNotice({ error: cause instanceof Error ? cause.message : "Could not save the pooler policy." });
      // A 409 means the requests changed under the review: reload so the owner reviews them again.
      await reload().catch(() => undefined);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="grid gap-4 border-t border-border pt-4 md:grid-cols-2" onSubmit={save}>
      <div className="md:col-span-2">
        <h3 className="text-xs font-semibold uppercase tracking-[0.08em] text-muted-foreground">
          Review the pooler-wide policy
        </h3>
        <p className="mt-1 text-xs text-muted-foreground">
          One list for every public Ark database. Saving records that you reviewed the{" "}
          {policy.requests.length} request(s) above (review{" "}
          <span className="mono">{policy.requestsFingerprint.slice(0, 12)}</span>) and needs your password for
          an exposure.public step-up.
        </p>
      </div>
      <div className="md:col-span-2">
        <Label htmlFor="poolerCidrs">Pooler-wide source CIDRs</Label>
        <textarea
          id="poolerCidrs"
          className="min-h-24 w-full rounded-lg border border-input bg-background p-3 font-mono text-xs disabled:opacity-50"
          placeholder={"203.0.113.0/24\n2001:db8::/48"}
          value={cidrs}
          disabled={allowInternet}
          onChange={(event) => setCidrs(event.target.value)}
        />
        <p className="mt-1 text-xs text-muted-foreground">
          One per line or comma-separated. Open or near-open prefixes are refused; use “Allow the internet”
          instead.
        </p>
      </div>
      <label className="flex items-start gap-2 md:col-span-2">
        <input
          type="checkbox"
          className="mt-1"
          checked={allowInternet}
          onChange={(event) => setAllowInternet(event.target.checked)}
        />
        <span>
          Allow the internet
          <span className="block text-xs text-muted-foreground">
            Needed for Vercel clients. Every source may then reach PgBouncer for every public database; roles,
            passwords and TLS remain the only gate.
          </span>
        </span>
      </label>
      {!allowInternet && parsed.length === 0 && (
        <p className="text-xs text-amber-200 md:col-span-2">
          An empty list denies every source (5432 stays closed).
        </p>
      )}
      <Field
        label="Current password"
        name="poolerPassword"
        type="password"
        autoComplete="current-password"
        required
      />
      <div className="md:col-span-2">
        <Button disabled={busy}>Review and save pooler-wide policy</Button>
      </div>
    </form>
  );
}
