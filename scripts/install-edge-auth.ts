import { chmod } from "node:fs/promises";

import { applyEdgeAuthKey, parseEnvFile } from "@ark-stack/shared";

// The installed value must win both on disk and in every Compose child's environment.
export async function configureEdgeAuthKey(
  envPath: string,
  {
    env = process.env,
    interactive = Boolean(process.stdin.isTTY) && env.ARK_INSTALL_NONINTERACTIVE !== "1",
    prompt = promptHidden,
    log = console.log,
  }: {
    env?: Record<string, string | undefined>;
    interactive?: boolean;
    prompt?: (question: string) => Promise<string>;
    log?: (line: string) => void;
  } = {},
) {
  const current = await Bun.file(envPath).text();
  const probe = applyEdgeAuthKey(current);
  if (probe.status === "kept") {
    env.TS_EDGE_AUTHKEY = parseEnvFile(current).TS_EDGE_AUTHKEY!.trim();
    log("TS_EDGE_AUTHKEY is already set in .env; keeping it.");
    return probe.status;
  }
  const supplied =
    env.TS_EDGE_AUTHKEY?.trim() ||
    (interactive
      ? await prompt(
          "Tailscale auth key for the edge node (tag:ark-edge); Enter to skip (or if it has already joined): ",
        )
      : "");
  const result = applyEdgeAuthKey(current, supplied);
  if (result.status === "set") {
    await Bun.write(envPath, result.env);
    await chmod(envPath, 0o600);
    log("TS_EDGE_AUTHKEY written to .env.");
  }
  env.TS_EDGE_AUTHKEY = parseEnvFile(result.env).TS_EDGE_AUTHKEY?.trim() ?? "";
  return result.status;
}

type HiddenInput = {
  setRawMode: (enabled: boolean) => unknown;
  resume: () => unknown;
  pause: () => unknown;
  setEncoding: (encoding: "utf8") => unknown;
  on: (event: "data", listener: (chunk: string) => void) => unknown;
  off: (event: "data", listener: (chunk: string) => void) => unknown;
};

export function promptHidden(
  question: string,
  stdin: HiddenInput = process.stdin,
  stdout: { write: (value: string) => unknown } = process.stdout,
) {
  return readHidden(question, stdin, stdout).then((value) => value.trim());
}

export function readHidden(
  question: string,
  stdin: HiddenInput = process.stdin,
  stdout: { write: (value: string) => unknown } = process.stdout,
) {
  return new Promise<string>((resolve) => {
    let value = "";
    stdin.setRawMode(true);
    stdout.write(question);
    stdin.resume();
    stdin.setEncoding("utf8");
    const finish = () => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.off("data", onData);
      stdout.write("\n");
      resolve(value);
    };
    const onData = (chunk: string) => {
      for (const character of chunk) {
        if (character === "\r" || character === "\n") return finish();
        if (character === "\u0003") {
          stdin.setRawMode(false);
          process.exit(130);
        }
        if (character === "\u007f" || character === "\b") value = value.replace(/.$/su, "");
        else value += character;
      }
    };
    stdin.on("data", onData);
  });
}
