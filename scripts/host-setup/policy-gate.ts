// The guided setup's confirmation before it enrols an Ark node into a tailnet whose policy lets that
// node reach every device (Tailscale's default rule does).
//
// The key sources call it: with the rules found in a policy read through the API
// (tailscale-api.ts), or without any when the policy cannot be read (pasted keys). It asks, or takes
// a scripted run's flags, and either returns or pauses setup. It only pauses while a node the policy
// concerns is still to be enrolled: enrolled nodes never hold up a re-run. The outcome is kept in
// the state file with the matching rules only, so an acceptance lasts until those rules change.
import { ARK_BACKUP_TAG, ARK_EDGE_TAG, ARK_VPS_TAG } from "@ark-stack/shared";

import type { Options } from "./answers.ts";
import type { SetupState } from "./state.ts";
import { SetupPaused, type Ui } from "./system.ts";
import {
  ENROLLED_TAGS,
  catchAllRules,
  rulesDigest,
  type CatchAllRule,
  type EnrolledTag,
} from "./tailnet-policy.ts";

/** Typed in full to continue with a catch-all rule; never `y`, `yes` or Enter. */
export const ACCEPT_WORD = "accept";
const ACCEPT_FLAG = "--accept-broad-tailnet-policy";
const REVIEWED_FLAG = "--tailnet-policy-reviewed";
const ACCESS_CONTROLS = "Access controls (https://login.tailscale.com/admin/acls)";

export interface PolicyGate {
  /** The rules found in the policy just read, and the Ark tags this run still has to enrol. */
  found(rules: CatchAllRule[], pending: EnrolledTag[]): Promise<void>;
  /** The policy cannot be read (no API credential). */
  unread(pending: EnrolledTag[]): Promise<void>;
  /** Whether a node with one of these tags must not be enrolled before another review. */
  unresolved(pending: EnrolledTag[]): boolean;
}

export type PolicyGateOptions = {
  ui: Ui;
  interactive: boolean;
  options: Pick<Options, "nonInteractive" | "acceptBroadTailnetPolicy" | "tailnetPolicyReviewed">;
  state: SetupState;
  save: () => void;
  resumeCommand: string;
};

const LABELS: Record<EnrolledTag, string> = {
  [ARK_EDGE_TAG]: `the internet-facing edge (${ARK_EDGE_TAG})`,
  [ARK_VPS_TAG]: `this VPS (${ARK_VPS_TAG})`,
  [ARK_BACKUP_TAG]: `the backup node (${ARK_BACKUP_TAG})`,
};

function joined(items: string[]) {
  return items.length < 2 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`;
}

/** What catch-all rules allow, in plain words. `tags` come with the edge first. */
function meaning(tags: readonly EnrolledTag[]) {
  const [first, ...others] = tags.map((tag) => LABELS[tag]);
  return [
    `This lets ${first} open connections to every device on your tailnet,`,
    "on the ports the rule names. Anyone who takes it over could try to reach your laptops, phones and servers.",
    ...(others.length ? [`It lets ${joined(others)} do the same.`] : []),
    `In Ark's model ${ARK_EDGE_TAG} reaches only the services you publish.`,
  ];
}

const DEFAULT_RULE = catchAllRules({ grants: [{ src: ["*"], dst: ["*"], ip: ["*"] }] })[0]!;

function suggestion(rules: CatchAllRule[]) {
  const lines: string[] = [];
  for (const rule of rules) {
    if (rule.replacement) lines.push("Suggested replacement:", `  ${rule.replacement}`);
    else {
      lines.push(
        "Suggested replacement: remove the rule, or name the tags and devices that need it",
        "  (the Ark tags need none of it; Ark generates a grant for each published service).",
      );
    }
  }
  if (rules.some((rule) => rule.coversOtherTags && rule.replacement))
    lines.push(
      "Other tagged machines lose the access this rule gives them, unless you name their tags in it.",
    );
  if (rules.some((rule) => rule.replacement))
    lines.push(
      "If you use exit nodes, Tailscale requires a rule for them whose destination is autogroup:internet:",
      '  {"src": ["autogroup:member"], "dst": ["autogroup:internet"], "ip": ["*"]}',
    );
  lines.push(
    "Once the Ark tags are declared, add policy tests that deny the edge, also for devices of your own:",
    `  "tests": [{"src": "${ARK_EDGE_TAG}", "deny": ["${ARK_VPS_TAG}:22"]}]`,
    "Setup never edits or removes your own rules.",
  );
  return lines;
}

const ruleLine = (rule: Pick<CatchAllRule, "kind" | "text">) => `${rule.kind} ${rule.text}`;

export function policyGate(input: PolicyGateOptions): PolicyGate {
  const { ui, interactive, options, state, save } = input;
  const scripted = !interactive && options.nonInteractive;
  /** Tags this run may not enrol yet. */
  let open: readonly EnrolledTag[] = ENROLLED_TAGS;

  const say = (lines: string[]) => {
    for (const line of lines) ui.print(line ? `      ${line}` : "");
  };
  const record = (review: Omit<NonNullable<SetupState["tailnetPolicy"]>, "at">) => {
    state.tailnetPolicy = { ...review, at: new Date().toISOString() };
    save();
  };
  const ask = async (question: string) => (await ui.ask(question, "")).trim().toLowerCase();

  function pause(reason: string, pending: EnrolledTag[], fix: string, flags: [string, string][]): never {
    const mode = options.nonInteractive || interactive ? "" : " --non-interactive";
    const scriptedHelp = interactive
      ? []
      : flags.flatMap(([flag, what]) => ["", `Or, ${what}:`, "", `  ${input.resumeCommand}${mode} ${flag}`]);
    const skip =
      pending.length && !pending.includes(ARK_VPS_TAG)
        ? ["", "To leave the nodes that have not joined for later, add --skip-edge and omit --backup-node."]
        : [];
    throw new SetupPaused(
      [
        `Stopped before enrolling ${joined(pending)}: ${reason}`,
        "",
        `${fix} Then resume with:`,
        "",
        `  ${input.resumeCommand}`,
        ...scriptedHelp,
        ...skip,
      ].join("\n"),
    );
  }

  return {
    unresolved: (pending) => pending.some((tag) => open.includes(tag)),

    async found(rules, pending) {
      if (!rules.length) {
        open = [];
        record({ status: "clear", read: true });
        return;
      }
      const digest = rulesDigest(rules);
      const shown = rules.map(ruleLine);
      const previous = state.tailnetPolicy;
      ui.print("");
      say([
        `Warning: your tailnet policy has ${rules.length === 1 ? "a catch-all rule" : "catch-all rules"}:`,
        ...shown.map((line) => `  ${line}`),
      ]);
      if (previous?.status === "accepted" && previous.digest === digest) {
        say([`You accepted ${rules.length === 1 ? "it" : "them"} on ${previous.at}; continuing.`]);
        open = [];
        return;
      }
      const tags = ENROLLED_TAGS.filter((tag) => rules.some((rule) => rule.tags.includes(tag)));
      say(["", ...meaning(tags), "", ...suggestion(rules), ""]);
      // A fresh host is always gated; later only for the nodes the rules concern.
      const concerned = (tag: EnrolledTag) => tag === ARK_VPS_TAG || tags.includes(tag);
      const blocking = pending.some(concerned);
      let accepted = scripted && options.acceptBroadTailnetPolicy;
      if (interactive) {
        accepted =
          (await ask(
            `Type ${ACCEPT_WORD} to continue with ${rules.length === 1 ? "this rule" : "these rules"} in place (anything else ${blocking ? "stops here" : "continues and lists it as unfinished"})`,
          )) === ACCEPT_WORD;
      } else if (accepted) say([`Accepted with ${ACCEPT_FLAG}.`]);
      open = accepted ? [] : ENROLLED_TAGS.filter(concerned);
      record({ status: accepted ? "accepted" : "unconfirmed", read: true, rules: shown, digest });
      if (!accepted && blocking) {
        pause(
          "the tailnet policy lets Ark nodes open connections to every device, and that was not accepted.",
          pending,
          `Narrow the rule in ${ACCESS_CONTROLS}; setup reads the policy again.`,
          [[ACCEPT_FLAG, "to accept the rule and continue with it in place"]],
        );
      }
      if (!accepted)
        say([
          "Continuing, because the nodes it concerns are already enrolled. It stays listed as unfinished.",
        ]);
    },

    async unread(pending) {
      const previous = state.tailnetPolicy;
      const fresh = pending.includes(ARK_VPS_TAG);
      const accept = scripted && options.acceptBroadTailnetPolicy;
      const reviewed = scripted && options.tailnetPolicyReviewed;
      if (!accept && !reviewed && previous && previous.status !== "unconfirmed") {
        // The operator's own answer about a policy setup cannot read; a fresh host confirms it again.
        if (!previous.read && (previous.status === "accepted" || !fresh)) {
          say([
            previous.status === "accepted"
              ? `You accepted continuing with a catch-all tailnet policy rule on ${previous.at}.`
              : `You confirmed on ${previous.at} that the tailnet policy has no catch-all rule.`,
          ]);
          open = [];
          return;
        }
        // Nothing to enrol: keep what setup read earlier. A later enrolment asks again.
        if (!pending.length) return;
      }
      ui.print("");
      say([
        "Setup cannot read your tailnet policy without a Tailscale API credential, so check it yourself.",
        `In ${ACCESS_CONTROLS}, look for a catch-all rule: one whose source`,
        `covers the Ark tags ("*", "autogroup:tagged", an Ark tag, or a range such as 100.64.0.0/10) and whose`,
        `destination covers every device ("*" or such a range). Tailscale's default rule is one:`,
        `  ${DEFAULT_RULE.text}`,
        ...(previous?.status !== "clear" && previous?.rules
          ? ["When setup last read the policy, it had:", ...previous.rules.map((rule) => `  ${rule}`)]
          : []),
        "",
        ...meaning(ENROLLED_TAGS),
        "",
        ...suggestion([DEFAULT_RULE]),
        "",
      ]);
      let outcome: "accepted" | "clear" | undefined = accept ? "accepted" : reviewed ? "clear" : undefined;
      const blocking = pending.length > 0;
      if (interactive) {
        const answer = await ask(
          `Type yes if the policy is saved and contains no such rule, or ${ACCEPT_WORD} to continue with one (anything else ${blocking ? "stops here" : "continues and lists it as unfinished"})`,
        );
        outcome = answer === "yes" ? "clear" : answer === ACCEPT_WORD ? "accepted" : undefined;
      } else if (outcome)
        say([
          accept
            ? `Continuing with any catch-all rule accepted (${ACCEPT_FLAG}).`
            : `You reviewed the policy (${REVIEWED_FLAG}).`,
        ]);
      open = outcome ? [] : ENROLLED_TAGS;
      // What setup read earlier says more than another acceptance, or no answer at all.
      const keep = outcome === "accepted" ? previous?.status === "accepted" : !outcome && previous?.rules;
      if (!keep) record({ status: outcome ?? "unconfirmed", read: false });
      if (!outcome && blocking) {
        pause(
          "you have not confirmed that the tailnet policy has no catch-all rule.",
          pending,
          `Check the policy in ${ACCESS_CONTROLS} and narrow any such rule.`,
          [
            [REVIEWED_FLAG, "once the policy has no such rule"],
            [ACCEPT_FLAG, "to continue with one in place"],
          ],
        );
      }
      if (!outcome)
        say(["Continuing, because the Ark nodes are already enrolled. It stays listed as unfinished."]);
    },
  };
}

/** The summary's lines about a catch-all: one accepted, and one still to resolve. */
export function policySummary(state: SetupState): { accepted: string[]; unfinished: string[] } {
  const review = state.tailnetPolicy;
  if (!review || review.status === "clear") return { accepted: [], unfinished: [] };
  const rules = (review.rules ?? []).map((rule) => `      ${rule}`);
  const recheck = `re-run host:setup with a Tailscale API credential (or with --non-interactive ${REVIEWED_FLAG}) to clear this`;
  if (review.status === "accepted") {
    return {
      accepted: [
        `Tailnet policy: you accepted a catch-all rule on ${review.at}.`,
        "  It lets the Ark nodes it covers open connections to every device on your tailnet.",
        ...(rules.length ? rules : ["      (setup could not read the policy)"]),
        `  Narrow it in ${ACCESS_CONTROLS}, then ${recheck}.`,
      ],
      unfinished: [],
    };
  }
  return {
    accepted: [],
    unfinished: [
      review.read
        ? "  - Tailnet policy: a catch-all rule lets Ark nodes open connections to every device, and was not accepted:"
        : "  - Tailnet policy: not confirmed to be free of a catch-all rule that lets the internet-facing edge reach every device.",
      ...rules,
      `      Narrow ${review.read ? "it" : "any such rule"} in ${ACCESS_CONTROLS}, then ${recheck}.`,
      `      To keep it, re-run interactively and type ${ACCEPT_WORD}, or with --non-interactive ${ACCEPT_FLAG}.`,
    ],
  };
}
