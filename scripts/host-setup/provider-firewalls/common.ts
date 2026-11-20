// Helpers shared by the provider firewall API adapters (one module per provider in this directory).
import type { FirewallContext, FirewallResult } from "../provider-firewall.ts";

/**
 * Asks before an adapter changes the provider: `undefined` means go ahead, otherwise the pending
 * result to return. Scripted runs need --approve-provider-firewall.
 */
export async function approveProviderChange(
  context: FirewallContext,
  provider: string,
): Promise<FirewallResult | undefined> {
  if (context.approved) return undefined;
  const finish = `Re-run host:setup interactively, or with --approve-provider-firewall, to apply the ${provider} firewall changes above.`;
  if (!context.interactive) {
    return {
      status: "pending",
      note: `The ${provider} firewall changes were shown but not approved.`,
      finish,
    };
  }
  const answer = await context.ui.ask(`Apply these changes to ${provider}? (yes/no)`, "");
  if (/^y(?:es)?$/i.test(answer.trim())) return undefined;
  return { status: "pending", note: `The ${provider} firewall changes were declined.`, finish };
}

/** Sorted, de-duplicated ports as single ports and contiguous ranges ("80", "20001-20010"). */
export function portRanges(ports: number[]) {
  const sorted = [...new Set(ports)].toSorted((a, b) => a - b);
  const ranges: string[] = [];
  for (let index = 0; index < sorted.length;) {
    let end = index;
    while (end + 1 < sorted.length && sorted[end + 1] === sorted[end]! + 1) end++;
    ranges.push(end === index ? String(sorted[index]) : `${sorted[index]}-${sorted[end]}`);
    index = end + 1;
  }
  return ranges;
}

export const errorText = (error: unknown) => (error instanceof Error ? error.message : String(error));
