// Where the guided setup gets its one-off Tailscale auth keys.
//
// Part 1 ships the manual source: the owner creates each key in the admin console and pastes it
// (or supplies it in the environment). Part 2 adds a source that mints the keys through the Tailscale
// API; it implements the same interface, so the setup flow does not change.
import { ARK_EDGE_TAG, ARK_VPS_TAG, sshPolicyExample } from "@ark-stack/shared";

import type { Ui } from "./system.ts";

export type KeyRequest = {
  /** The single tag the key must carry. */
  tag: typeof ARK_VPS_TAG | typeof ARK_EDGE_TAG;
  /** The variable that can supply it non-interactively, named in messages. */
  variable: string;
  /** An optional key may be declined (the step is then skipped). */
  optional: boolean;
};

export type AcquiredKey = {
  /** The key itself, written by the caller to a private file or `.env`. */
  key?: string;
  /** Or a private key file the owner already made (`TS_VPS_AUTHKEY_FILE`); it is left in place. */
  file?: string;
  /** Called once the node has joined with the right tag: an API source revokes the key here. */
  release?: () => Promise<void>;
};

export interface TailscaleKeySource {
  readonly id: string;
  /** The tailnet policy the owner needs before keys can be used (printed once, before enrolment). */
  policyInstructions(): string[];
  /** Returns a key, or `undefined` when an optional key was declined. */
  acquire(request: KeyRequest): Promise<AcquiredKey | undefined>;
}

export function tailnetPolicyInstructions() {
  return [
    "In the Tailscale admin console (Access controls), make sure the tailnet policy file has:",
    "",
    '  "tagOwners": {',
    `    "${ARK_VPS_TAG}": ["autogroup:admin"],`,
    `    "${ARK_EDGE_TAG}": ["autogroup:admin"],`,
    "  },",
    "",
    "and the owner-only Tailscale SSH access to the VPS (merge it with your own grants and ssh rules):",
    "",
    ...sshPolicyExample()
      .trimEnd()
      .split("\n")
      .map((line) => `  ${line}`),
    "",
    `"autogroup:nonroot" lets you log in as any local user except root. If this VPS has only root,`,
    "create a user with sudo first (adduser <name> && usermod -aG sudo <name>) or list it in users.",
    `Add no grant with ${ARK_EDGE_TAG} as the source, and check that no catch-all rule`,
    '(such as "src": ["*"], "dst": ["*"]) covers it.',
  ];
}

const KEY_PATTERN = /^tskey-[A-Za-z0-9-]+$/;

export function manualKeySource({
  env,
  ui,
  interactive,
}: {
  env: Record<string, string | undefined>;
  ui: Ui;
  interactive: boolean;
}): TailscaleKeySource {
  return {
    id: "manual",
    policyInstructions: tailnetPolicyInstructions,
    async acquire(request) {
      if (request.tag === ARK_VPS_TAG && env.TS_VPS_AUTHKEY_FILE?.trim()) {
        return { file: env.TS_VPS_AUTHKEY_FILE.trim() };
      }
      const supplied = env[request.variable]?.trim();
      if (supplied) {
        if (!KEY_PATTERN.test(supplied))
          throw new Error(`${request.variable} must be a Tailscale auth key (tskey-…).`);
        return { key: supplied };
      }
      if (!interactive) {
        if (request.optional) return undefined;
        const alternatives =
          request.tag === ARK_VPS_TAG ? `${request.variable} or TS_VPS_AUTHKEY_FILE` : request.variable;
        throw new Error(`Missing required answer: a one-off ${request.tag} auth key (${alternatives}).`);
      }
      ui.print(`Create a key: Settings > Keys > Generate auth key. Reusable off, Ephemeral off,`);
      ui.print(`Pre-approved on, Tags ${request.tag} only, expiry 1 day.`);
      for (;;) {
        const key = await ui.askSecret(
          `Paste the ${request.tag} key${request.optional ? " (Enter to skip this step for now)" : ""}`,
        );
        if (!key && request.optional) return undefined;
        if (KEY_PATTERN.test(key)) return { key };
        ui.print("  That is not a Tailscale auth key (tskey-…). Try again.");
      }
    },
  };
}
