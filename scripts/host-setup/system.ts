// Command runner, redacting log and terminal UI for the guided setup (scripts/host-setup.ts).
//
// Every child process runs with its output captured: progress goes to the terminal as one line per
// step and the detail goes, redacted, to the log file. Tests replace the runner and the UI.
import { appendFileSync, chmodSync, mkdirSync, openSync, closeSync } from "node:fs";
import { dirname } from "node:path";
import { createInterface } from "node:readline/promises";

import { isSecretKey, parseEnvFile, redactLogLine } from "@ark-stack/shared";

import { promptHidden } from "../install-edge-auth.ts";

export type RunOptions = {
  env?: Record<string, string | undefined>;
  stdin?: string;
  cwd?: string;
  timeoutMs?: number;
  /** Each output line as it arrives (the runner's caller logs it). */
  onLine?: (line: string) => void;
};
export type RunResult = { status: number; stdout: string; stderr: string };
/** Runs one command with captured output. Never throws for a non-zero exit. */
export type Runner = (argv: string[], options?: RunOptions) => Promise<RunResult>;

async function readLines(stream: ReadableStream<Uint8Array>, onLine?: (line: string) => void) {
  const decoder = new TextDecoder();
  let all = "";
  let pending = "";
  const reader = stream.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const text = decoder.decode(value, { stream: true });
    all += text;
    pending += text;
    const lines = pending.split("\n");
    pending = lines.pop() ?? "";
    for (const line of lines) onLine?.(line);
  }
  const rest = decoder.decode();
  all += rest;
  pending += rest;
  if (pending) onLine?.(pending);
  return all;
}

export const runCommand: Runner = async (argv, options = {}) => {
  let child;
  try {
    child = Bun.spawn(argv, {
      cwd: options.cwd,
      env: (options.env ? withoutApiCredentials(options.env) : withoutSetupSecrets(process.env)) as Record<
        string,
        string
      >,
      stdin: options.stdin === undefined ? "ignore" : new TextEncoder().encode(options.stdin),
      stdout: "pipe",
      stderr: "pipe",
      timeout: options.timeoutMs,
    });
  } catch (error) {
    return { status: 127, stdout: "", stderr: String(error) };
  }
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    readLines(child.stdout, options.onLine),
    readLines(child.stderr, options.onLine),
  ]);
  return { status, stdout, stderr };
};

const API_SECRETS = ["TS_API_KEY", "TS_OAUTH_CLIENT_SECRET", "HCLOUD_TOKEN"];

/** Shell-supplied secrets to register with the setup redactor. */
export const SECRET_VARIABLES = [
  "TS_VPS_AUTHKEY",
  "TS_EDGE_AUTHKEY",
  "TS_BACKUP_AUTHKEY",
  ...API_SECRETS,
  "DNS_API_TOKEN",
];

export function withoutApiCredentials(source: Record<string, string | undefined>) {
  const env = { ...source };
  for (const key of [...API_SECRETS, "TS_OAUTH_CLIENT_ID"]) delete env[key];
  return env;
}

export function withoutSetupSecrets(source: Record<string, string | undefined>) {
  const env = { ...source };
  for (const key of [...SECRET_VARIABLES, "TS_VPS_AUTHKEY_FILE", "TS_OAUTH_CLIENT_ID"]) delete env[key];
  return env;
}

/** Values that must never reach the terminal (except the setup token in the summary) or the log. */
export class Redactor {
  private secrets = new Set<string>();

  add(value: string | undefined) {
    const trimmed = value?.trim();
    if (trimmed && trimmed.length >= 8) this.secrets.add(trimmed);
  }

  /** Learns every secret-looking value of an installed `.env`. */
  addEnv(text: string) {
    for (const [key, value] of Object.entries(parseEnvFile(text))) {
      if (envKeyIsSecret(key)) this.add(value);
    }
  }

  redact(text: string) {
    const known = [...this.secrets].toSorted((a, b) => b.length - a.length);
    return redactLogLine(text, known)
      .replace(/tskey-[A-Za-z0-9-]+/g, "<redacted>")
      .replace(/(Setup token:\s*)\S+/gi, "$1<redacted>");
  }
}

export function envKeyIsSecret(key: string) {
  if (key === "ARK_ROOT_KEY_ID") return false;
  return isSecretKey(key) || /(?:_KEY|_PASS|AUTHKEY)$/.test(key);
}

/** An append-only, root-only log; every line passes through the redactor first. */
export class SetupLog {
  constructor(
    readonly path: string,
    readonly redactor: Redactor,
  ) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    closeSync(openSync(path, "a", 0o600));
    chmodSync(path, 0o600);
  }

  write(line: string) {
    const stamp = new Date().toISOString();
    const text = this.redactor
      .redact(line)
      .split("\n")
      .map((part) => `${stamp} ${part}`)
      .join("\n");
    appendFileSync(this.path, `${text}\n`);
  }
}

export interface Ui {
  readonly interactive: boolean;
  /** One line to the terminal; it is also logged, redacted. */
  print(line?: string): void;
  ask(question: string, fallback?: string, signal?: AbortSignal): Promise<string>;
  askSecret(question: string): Promise<string>;
}

export class TerminalUi implements Ui {
  constructor(
    readonly interactive: boolean,
    private log: SetupLog,
    private redactor: Redactor,
    private out: (text: string) => void = (text) => process.stdout.write(text),
  ) {}

  print(line = "") {
    this.out(`${line}\n`);
    this.log.write(line);
  }

  async ask(question: string, fallback = "", signal?: AbortSignal) {
    if (!this.interactive) throw new Error(`Cannot ask "${question}" in non-interactive mode.`);
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    try {
      const answer = (
        await rl.question(fallback ? `${question} [${fallback}]: ` : `${question}: `, { signal })
      ).trim();
      this.log.write(`? ${question} -> ${answer || fallback}`);
      return answer || fallback;
    } finally {
      rl.close();
    }
  }

  async askSecret(question: string) {
    if (!this.interactive) throw new Error(`Cannot ask "${question}" in non-interactive mode.`);
    const value = await promptHidden(`${question}: `);
    this.redactor.add(value);
    this.log.write(`? ${question} -> ${value ? "<entered>" : "<empty>"}`);
    return value;
  }
}
