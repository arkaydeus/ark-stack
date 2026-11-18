import {
  type DnsPublishStatus,
  type DomainDnsReview,
  type DnsReviewRecord,
} from "@ark-stack/shared/dns-review";
import { type FormEvent, useEffect, useRef, useState } from "react";

import { Badge, statusVariant } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/utils";

import { InlineError } from "./Auth";

const ipv6Text = {
  eligible: "IPv6 is eligible for publishing.",
  withdrawal_pending: "IPv6 removal pending. Ark will confirm removal through public DNS.",
  a_only: "Publishing A only. IPv6 is disabled or its preflight has not passed.",
};

const watchDuration = 30 * 60_000;

const removalText = {
  manual: "Remove at provider",
  review: "Review deletion",
  automatic: "Removal authorized",
  propagating: "Waiting for DNS caches",
};

async function loadReview(path: string) {
  try {
    return { review: await api<DomainDnsReview>(path), providerError: "" };
  } catch (error) {
    const review = await api<DomainDnsReview>(path + "?local=1").catch(() => {
      throw error;
    });
    return { review, providerError: error instanceof Error ? error.message : "Cloudflare review failed." };
  }
}

function DnsRecordTable({ records }: { records: DnsReviewRecord[] }) {
  if (!records.length) return <p className="text-sm text-muted-foreground">No records to configure.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-border text-xs text-muted-foreground">
          <tr>
            <th scope="col" className="p-2">
              Type
            </th>
            <th scope="col" className="p-2">
              Host
            </th>
            <th scope="col" className="p-2">
              Value
            </th>
            <th scope="col" className="p-2">
              TTL
            </th>
            <th scope="col" className="p-2">
              Status
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {records.map((record) => (
            <tr key={record.id}>
              <td className="p-2">{record.type}</td>
              <td className="p-2">
                <code title={record.name}>{record.relativeName}</code>
                {record.relativeName !== record.name && (
                  <p className="text-xs text-muted-foreground">{record.name}</p>
                )}
              </td>
              <td className="p-2">
                <code className="break-all">
                  {record.priority !== undefined && record.priority + " "}
                  {record.value}
                </code>
              </td>
              <td className="p-2">{record.ttl}s</td>
              <td className="p-2">
                <Badge variant={record.providerRemoval ? "warning" : statusVariant(record.status)}>
                  {record.providerRemoval ? removalText[record.providerRemoval] : record.status}
                </Badge>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function DnsReviewPanel({
  reviewPath,
  owner,
  reload,
}: {
  reviewPath: string;
  owner: boolean;
  reload?: () => Promise<void>;
}) {
  const [review, setReview] = useState<DomainDnsReview | null>(null);
  const [failure, setFailure] = useState("");
  const [feedback, setFeedback] = useState("");
  const [busy, setBusy] = useState(true);
  const [authorizedPlan, setAuthorizedPlan] = useState<string | null>(null);
  const [enabling, setEnabling] = useState(false);
  const [publishPath, setPublishPath] = useState<string | null>(null);
  const [publishProgress, setPublishProgress] = useState("");
  const reloadRef = useRef(reload);
  useEffect(() => {
    reloadRef.current = reload;
  }, [reload]);
  const watchUntil = useRef(0);

  useEffect(() => {
    let active = true;
    setAuthorizedPlan(null);
    watchUntil.current = 0;
    loadReview(reviewPath)
      .then(async ({ review: received, providerError }) => {
        if (!active) return;
        setReview(received);
        setFailure(providerError);
        if (received.provider !== "cloudflare") {
          await api("/api/domains/" + received.domainId + "/dns/watch", { method: "POST", body: "{}" });
          if (active) watchUntil.current = Date.now() + watchDuration;
        }
      })
      .catch((error: Error) => {
        if (active) setFailure(error.message);
      })
      .finally(() => {
        if (active) setBusy(false);
      });
    const timer = setInterval(() => {
      if (Date.now() >= watchUntil.current) return;
      void api<DomainDnsReview>(reviewPath)
        .then((result) => {
          if (active) setReview(result);
        })
        .catch(() => {});
    }, 120_000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [reviewPath]);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setFailure("");
    setFeedback("");
    setPublishProgress("");
    try {
      await action();
      const result = await loadReview(reviewPath);
      setReview(result.review);
      setAuthorizedPlan((current) => (current === result.review.cloudflare?.planHash ? current : null));
      setFailure(result.providerError);
    } catch (error) {
      setFailure(error instanceof Error ? error.message : "DNS request failed.");
    } finally {
      setBusy(false);
    }
  }

  async function verify() {
    await api("/api/domains/" + review!.domainId + "/verify", { method: "POST", body: "{}" });
    if (review!.provider !== "cloudflare") watchUntil.current = Date.now() + watchDuration;
    setFeedback("DNS verification queued.");
  }

  useEffect(() => {
    if (!publishPath) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function poll(path: string) {
      try {
        // A conflict is also a terminal operation result. Its body carries the progress.
        const response = await fetch(path, { signal: controller.signal });
        if (!response.ok && response.status !== 409) throw new Error("Could not read DNS publish status.");
        const result = (await response.json()) as DnsPublishStatus;
        if (controller.signal.aborted) return;
        if (
          result.status === "failed" ||
          result.status === "cancelled" ||
          result.status === "needs_recovery"
        ) {
          setFailure(result.error ?? "Cloudflare publish did not complete. Reload the DNS review.");
          setBusy(false);
          setPublishPath(null);
          return;
        }
        if (result.status === "succeeded") {
          setFeedback("Cloudflare changes applied. Public DNS verification is queued.");
          const next = await loadReview(reviewPath).catch(() => null);
          if (controller.signal.aborted) return;
          if (next) setReview(next.review);
          setFailure(next?.providerError ?? "Reload the DNS review to see the updated records.");
          setBusy(false);
          setPublishPath(null);
          void reloadRef.current?.();
          return;
        }
        setPublishProgress(
          result.total === null
            ? "Cloudflare publish queued…"
            : `Checking Cloudflare records (${result.applied} of ${result.total})…`,
        );
      } catch {
        if (controller.signal.aborted) return;
        setPublishProgress("Reconnecting to the DNS publish operation…");
      }
      timer = setTimeout(() => void poll(path), 1_000);
    }
    void poll(publishPath);
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [publishPath, reviewPath]);

  async function publish() {
    if (!review?.cloudflare || busy) return;
    const { planHash } = review.cloudflare;
    const path = "/api/domains/" + review.domainId + "/publish";
    const submission = {
      planHash,
      authorizeAAAAWithdrawal: authorizedPlan === planHash || undefined,
      requestId: crypto.randomUUID?.(),
    };
    setReview(null);
    setAuthorizedPlan(null);
    setFailure("");
    setFeedback("");
    setBusy(true);
    setPublishProgress("Submitting Cloudflare publish…");
    try {
      const send = () =>
        api<{ operationId: string }>(path, {
          method: "POST",
          body: JSON.stringify(submission),
        });
      // Retrying a dropped submission uses the same identity and returns the same operation.
      const result = await send().catch((error) =>
        error instanceof TypeError ? send() : Promise.reject(error),
      );
      setPublishPath(path + "/" + result.operationId);
    } catch (error) {
      setFailure(error instanceof Error ? error.message : "DNS publish request failed.");
      setBusy(false);
    }
  }

  async function revoke() {
    await api("/api/domains/" + review!.domainId + "/aaaa/authorization", { method: "DELETE" });
    setAuthorizedPlan(null);
    setFeedback("Automatic IPv6 withdrawal authorization revoked.");
  }

  async function toggle(enabled: boolean, password?: string) {
    const domainId = review!.domainId;
    if (enabled) {
      await api("/api/step-up", {
        method: "POST",
        body: JSON.stringify({ password, action: "exposure.public", request: { domainId, enabled } }),
      });
    }
    await api("/api/domains/" + domainId + "/aaaa", { method: "PUT", body: JSON.stringify({ enabled }) });
    setEnabling(false);
    setFeedback(
      enabled
        ? "IPv6 publishing is enabled when preflight passes."
        : "IPv6 publishing disabled. DNS verification is queued.",
    );
    await reload?.();
  }

  function enable(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const password = String(new FormData(event.currentTarget).get("password"));
    void run(() => toggle(true, password));
  }

  if (!review) {
    return (
      <section className="space-y-3" aria-label="DNS review" aria-busy={busy}>
        {busy && (
          <p role="status" className="text-sm text-muted-foreground">
            {publishProgress || "Loading DNS review…"}
          </p>
        )}
        {failure && <InlineError>{failure}</InlineError>}
        {!busy && feedback && (
          <p role="status" className="text-sm text-muted-foreground">
            {feedback}
          </p>
        )}
        {!busy && (
          <Button size="sm" variant="outline" onClick={() => void run(async () => {})}>
            Reload DNS review
          </Button>
        )}
      </section>
    );
  }

  const diff = review.cloudflare;
  const names = new Map(review.records.map((record) => [record.id, record.relativeName]));
  return (
    <section className="space-y-4" aria-label={"DNS review for " + review.zone} aria-busy={busy}>
      {failure && <InlineError>{failure}</InlineError>}
      {review.lastError && <InlineError>{review.lastError}</InlineError>}
      <p className="text-sm">{ipv6Text[review.ipv6Status]}</p>
      {review.guides.length > 0 && (
        <div className="space-y-2">
          {review.guides.map((guide) => (
            <details key={guide.title} className="rounded-lg border border-border px-3 py-2 text-sm">
              <summary className="cursor-pointer font-medium">{guide.title}</summary>
              <ol className="my-2 list-decimal space-y-1 pl-5 text-muted-foreground">
                {guide.steps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
              {guide.url && (
                <a href={guide.url} className="text-primary underline underline-offset-2">
                  Namecheap DNS instructions
                </a>
              )}
            </details>
          ))}
        </div>
      )}
      {diff && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Cloudflare changes for {review.zone}</h3>
          <ul className="divide-y divide-border rounded-lg border border-border">
            {diff.actions.map((action) => {
              const before = action.before ?? action.deletionScope?.record;
              return (
                <li className="grid gap-2 p-3 text-sm sm:grid-cols-[5rem_1fr_2fr]" key={action.recordId}>
                  <span>
                    <Badge
                      variant={
                        action.action === "delete" || action.action === "blocked" ? "warning" : "neutral"
                      }
                    >
                      {action.action}
                    </Badge>
                  </span>
                  <span className="break-all">
                    {action.after?.type ?? before?.type} <code>{names.get(action.recordId)}</code>
                    <span className="block text-xs text-muted-foreground">
                      {action.after?.name ?? before?.name}
                    </span>
                  </span>
                  <div className="min-w-0 space-y-1 break-all">
                    {before && action.action !== "keep" && (
                      <p className="text-muted-foreground">
                        Current <code>{before.content}</code> ·{" "}
                        {before.ttl === 1 ? "Auto TTL" : before.ttl + "s"}
                        {before.proxied ? " · Proxied" : ""}
                      </p>
                    )}
                    {action.after && (
                      <p>
                        <code>{action.after.content}</code> · {action.after.ttl}s · DNS only
                      </p>
                    )}
                    {action.reason && <p>{action.reason}</p>}
                    {action.deletionScope && (
                      <p className="text-xs text-muted-foreground">
                        Record <code>{action.deletionScope.record.id}</code>
                        {action.before ? "" : " · Already absent from Cloudflare"}
                      </p>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
          {owner && diff.actions.some((action) => action.canAuthorizeWithdrawal) && (
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-1"
                disabled={busy}
                checked={authorizedPlan === diff.planHash}
                onChange={(event) => setAuthorizedPlan(event.currentTarget.checked ? diff.planHash : null)}
              />
              <span>Allow Ark to withdraw its AAAA records in this review if IPv6 becomes ineligible.</span>
            </label>
          )}
        </div>
      )}
      <DnsRecordTable
        records={diff ? review.records.filter((record) => record.providerRemoval) : review.records}
      />
      <div className="flex flex-wrap gap-2">
        {diff?.actions.some((action) => action.action !== "blocked") && (
          <Button size="sm" disabled={busy} onClick={() => void publish()}>
            Publish reviewed DNS
          </Button>
        )}
        <Button size="sm" variant="outline" disabled={busy} onClick={() => void run(verify)}>
          Recheck DNS
        </Button>
        <Button size="sm" variant="outline" disabled={busy} onClick={() => void run(async () => {})}>
          Reload review
        </Button>
        {owner && review.automaticWithdrawalAuthorized && (
          <Button size="sm" variant="outline" disabled={busy} onClick={() => void run(revoke)}>
            Revoke automatic withdrawal
          </Button>
        )}
        {owner &&
          (review.aaaaEnabled ? (
            <Button size="sm" variant="outline" disabled={busy} onClick={() => void run(() => toggle(false))}>
              Disable IPv6 DNS
            </Button>
          ) : (
            <Button
              size="sm"
              variant="outline"
              disabled={busy}
              onClick={() => setEnabling(!enabling)}
              aria-expanded={enabling}
            >
              Enable IPv6 DNS
            </Button>
          ))}
      </div>
      {enabling && (
        <form onSubmit={enable} className="flex flex-wrap items-end gap-2">
          <label className="space-y-1 text-sm">
            <span className="block">Confirm your password</span>
            <Input name="password" type="password" autoComplete="current-password" required />
          </label>
          <Button size="sm" disabled={busy}>
            Confirm IPv6 publishing
          </Button>
        </form>
      )}
      {(feedback || busy) && (
        <p role="status" className="text-sm text-muted-foreground">
          {busy ? "Working on DNS…" : feedback}
        </p>
      )}
    </section>
  );
}
