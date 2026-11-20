// The guided setup's root-only state file: which steps finished, with what inputs, so a re-run
// verifies and skips them and resumes at the first unfinished one. It never holds a secret.
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const STEP_IDS = [
  "prerequisites",
  "tailscale",
  "ssh-gate",
  "install",
  "edge",
  "configuration",
  "public-ssh",
  "provider-firewall",
  "summary",
] as const;
export type StepId = (typeof STEP_IDS)[number];

export type StepRecord = {
  status: "done" | "skipped" | "pending" | "failed";
  at: string;
  /** Inputs the step completed with; a different fingerprint makes the step run again. */
  fingerprint?: string;
  /** Why the step was skipped or is pending. */
  note?: string;
  /** The command or action that finishes a skipped or pending step. */
  finish?: string;
  error?: string;
};

export type StoredAnswers = {
  domain: string;
  adminHost: string;
  acmeEmail: string;
  trustedCertificates: boolean;
  certificatePreference?: boolean;
  mailEnabled: boolean;
  sniPorts: number[];
  rebootTime: string;
  sshUser: string;
};

export type SetupState = {
  version: 1;
  answers: Partial<StoredAnswers>;
  /** The node and account for which the operator confirmed a working Tailscale SSH session. */
  sshConfirmation?: { target: string; at: string };
  sshCutoverPending?: boolean;
  /** The admin origin this setup last wrote, so a changed hostname replaces it. */
  adminOrigin?: string;
  edgeKeyRetry?: boolean;
  steps: Partial<Record<StepId, StepRecord>>;
};

export function emptyState(): SetupState {
  return { version: 1, answers: {}, steps: {} };
}

export class StateStore {
  readonly path: string;

  constructor(readonly directory: string) {
    this.path = join(directory, "state.json");
  }

  load(): SetupState {
    if (!existsSync(this.path)) return emptyState();
    const parsed = JSON.parse(readFileSync(this.path, "utf8")) as SetupState;
    if (parsed.version !== 1) throw new Error(`Unsupported setup state version in ${this.path}.`);
    return { ...emptyState(), ...parsed, steps: parsed.steps ?? {}, answers: parsed.answers ?? {} };
  }

  save(state: SetupState) {
    mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    chmodSync(this.directory, 0o700);
    const temporary = `${this.path}.${process.pid}.tmp`;
    writeFileSync(temporary, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    chmodSync(temporary, 0o600);
    renameSync(temporary, this.path);
  }
}
