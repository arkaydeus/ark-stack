// Guided production install (`mise run host:setup`), started by install.sh after the prerequisites.
//
// It asks a short set of questions up front, then drives the existing installer phases in the order
// of docs/getting-started/production-install.md: enrol the host, confirm Tailscale SSH, harden and
// install, enrol the edge node (and, optionally, the backup node), set the admin origin and ACME,
// close public SSH, apply the provider firewall rules and audit, then print a summary. With a
// Tailscale API credential the policy change and the auth keys are automated (tailscale-api.ts); a
// provider firewall adapter (provider-firewall.ts) applies the rules where one detects the provider. Progress is one line per step; the detail goes to
// a redacted log. A root-only state file records each step, so a re-run verifies and resumes.
import { join, resolve } from "node:path";

import { parseEnvFile } from "@ark-stack/shared";

import { lockHostDeployment } from "./host-deployment-lock.ts";
import {
  USAGE,
  describeAnswers,
  parseFlags,
  resolveAnswers,
  resolveOptions,
  storedAnswers,
  type Answers,
  type Options,
} from "./host-setup/answers.ts";
import { readEnv } from "./host-setup/env-file.ts";
import { providerFirewalls, type ProviderFirewall } from "./host-setup/provider-firewall.ts";
import { StateStore, type SetupState } from "./host-setup/state.ts";
import {
  STEPS,
  SetupPaused,
  detectSessionOrigin,
  summary,
  type Context,
  type HostPaths,
  type SessionOrigin,
} from "./host-setup/steps.ts";
import {
  Redactor,
  SECRET_VARIABLES,
  SetupLog,
  TerminalUi,
  runCommand,
  withoutSetupSecrets,
  type Runner,
  type Ui,
} from "./host-setup/system.ts";
import { automaticKeySource } from "./host-setup/tailscale-api.ts";
import type { TailscaleKeySource } from "./host-setup/tailscale-keys.ts";
import { hostFirewallPath } from "./install-host-hardening.ts";

export type SetupDependencies = {
  root: string;
  argv: string[];
  env: Record<string, string | undefined>;
  run: Runner;
  stateDir: string;
  paths: HostPaths;
  isRoot: boolean;
  platform: string;
  bun: string;
  stdinIsTty: boolean;
  /** Builds the UI once the log exists (tests supply a scripted one). */
  ui?: (interactive: boolean, log: SetupLog, redactor: Redactor) => Ui;
  keys?: (context: {
    env: Record<string, string | undefined>;
    ui: Ui;
    interactive: boolean;
    options: Options;
    redactor: Redactor;
    log: SetupLog;
  }) => TailscaleKeySource;
  /** The Tailscale API base URL (tests point it at a mock server). */
  tailscaleApi?: string;
  firewalls?: ProviderFirewall[];
  sleep?: (ms: number) => Promise<void>;
  sessionOrigin?: () => Promise<SessionOrigin>;
  lock?: () => Promise<void>;
  out?: (text: string) => void;
};

/** 0: finished. 1: a step failed or the input was invalid. 2: paused for an SSH safety prerequisite. */
export async function runSetup(deps: SetupDependencies): Promise<number> {
  const out = deps.out ?? ((text: string) => process.stdout.write(text));
  let flags;
  let options: Options;
  try {
    flags = parseFlags(deps.argv);
    options = resolveOptions(flags, deps.env);
  } catch (error) {
    out(`${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
  if (options.help) {
    out(USAGE);
    return 0;
  }
  const args = deps.argv.length ? ` ${deps.argv.map(shellQuote).join(" ")}` : "";
  const resumeCommand = `cd ${shellQuote(deps.root)} && sudo mise run host:setup${args}`;
  if (deps.platform !== "linux" || !deps.isRoot) {
    out(
      `host:setup changes the host and must run as root on the Ubuntu VPS. Nothing was changed.\nRun: ${resumeCommand}\n`,
    );
    return 1;
  }

  try {
    await deps.lock?.();
  } catch (error) {
    out(`${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }

  const redactor = new Redactor();
  const stateDir = resolve(deps.stateDir);
  const envPath = join(deps.root, ".env");
  redactor.addEnv(readEnv(envPath));
  for (const key of SECRET_VARIABLES) redactor.add(deps.env[key]);
  const log = new SetupLog(join(stateDir, "setup.log"), redactor);
  const interactive = !options.nonInteractive && deps.stdinIsTty;
  const ui = deps.ui?.(interactive, log, redactor) ?? new TerminalUi(interactive, log, redactor, out);
  log.write(`host:setup started (${interactive ? "interactive" : "non-interactive"})`);

  const store = new StateStore(stateDir);
  const state: SetupState = store.load();
  ui.print("Ark Stack guided setup");
  ui.print(`Detail log: ${log.path}`);
  ui.print("");

  let answers: Answers;
  try {
    answers = await resolveAnswers({
      flags,
      env: deps.env,
      previous: state.answers,
      dotenv: parseEnvFile(readEnv(envPath)),
      interactive,
      ui,
    });
  } catch (error) {
    ui.print(error instanceof Error ? error.message : String(error));
    if (!interactive) ui.print("Run mise run host:setup --help for every flag and variable.");
    return 1;
  }
  redactor.add(answers.dnsApiToken);
  ui.print("");
  ui.print("Settings:");
  for (const line of describeAnswers(answers, parseEnvFile(readEnv(envPath)))) ui.print(line);
  if (interactive) {
    const proceed = await ui.ask("Continue with these settings? (yes/no)", "yes");
    if (!/^y(?:es)?$/i.test(proceed.trim())) {
      ui.print("Stopped. Nothing was changed.");
      return 1;
    }
  }
  state.answers = storedAnswers(answers);
  store.save(state);

  const context: Context = {
    root: deps.root,
    stateDir,
    envPath,
    bun: deps.bun,
    run: deps.run,
    ui,
    log,
    redactor,
    state,
    save: () => store.save(state),
    answers,
    options,
    interactive,
    env: deps.env,
    keys: (
      deps.keys ??
      ((input) =>
        automaticKeySource({
          ...input,
          approve: options.nonInteractive && options.approveTailnetPolicy,
          backup: options.backupNode,
          sleep: deps.sleep,
          secret: (value) => redactor.add(value),
          log: (line) => log.write(line),
          apiBase: deps.tailscaleApi,
        }))
    )({ env: deps.env, ui, interactive, options, redactor, log }),
    firewalls: deps.firewalls ?? providerFirewalls,
    paths: deps.paths,
    isRoot: deps.isRoot,
    platform: deps.platform,
    resumeCommand,
    sleep: deps.sleep ?? ((ms) => Bun.sleep(ms)),
    sessionOrigin: deps.sessionOrigin ?? (() => detectSessionOrigin(deps.env)),
  };

  const total = STEPS.length + 1;
  for (const [index, step] of STEPS.entries()) {
    ui.print("");
    ui.print(`[${index + 1}/${total}] ${step.title}`);
    log.write(`--- step ${step.id}`);
    try {
      const result = await step.run(context);
      state.steps[step.id] = {
        status: result.status,
        at: new Date().toISOString(),
        fingerprint: result.fingerprint,
        note: result.note,
        finish: result.finish,
      };
      store.save(state);
      const label = result.status === "done" ? "ok" : result.status;
      ui.print(
        `      ${label}${result.message ? `: ${result.message}` : result.note ? `: ${result.note}` : ""}`,
      );
    } catch (error) {
      const message = redactor.redact(error instanceof Error ? error.message : String(error));
      if (error instanceof SetupPaused) {
        ui.print(`      paused`);
        ui.print("");
        ui.print(message);
        return 2;
      }
      state.steps[step.id] = { status: "failed", at: new Date().toISOString(), error: message };
      store.save(state);
      log.write(error instanceof Error && error.stack ? error.stack : message);
      ui.print(`      failed: ${message}`);
      ui.print("");
      ui.print(`Details: ${log.path}`);
      ui.print("Fix the problem, then run the same command again; finished steps are checked and skipped:");
      ui.print(`  ${resumeCommand}`);
      return 1;
    }
  }
  ui.print("");
  ui.print(`[${total}/${total}] Summary`);
  for (const line of await summary(context)) ui.print(line);
  state.steps.summary = { status: "done", at: new Date().toISOString() };
  store.save(state);
  return 0;
}

function shellQuote(value: string) {
  return /^[A-Za-z0-9_./:=@,+-]+$/.test(value) ? value : `'${value.replaceAll("'", "'\\''")}'`;
}

if (import.meta.main) {
  const root = join(import.meta.dir, "..");
  const code = await runSetup({
    root,
    argv: process.argv.slice(2),
    env: process.env,
    run: runCommand,
    lock: () => lockHostDeployment(root, withoutSetupSecrets(process.env)),
    stateDir: process.env.ARK_SETUP_STATE_DIR || join(root, "tmp", "host-setup"),
    paths: { osRelease: "/etc/os-release", hostFirewall: hostFirewallPath },
    isRoot: process.getuid?.() === 0,
    platform: process.platform,
    bun: process.execPath,
    stdinIsTty: Boolean(process.stdin.isTTY),
  });
  process.exit(code);
}
