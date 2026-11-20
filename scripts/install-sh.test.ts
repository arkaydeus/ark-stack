// install.sh (the curl | sudo bash bootstrap) with every system command stubbed on an isolated PATH
// and its host files under a temporary ARK_BOOTSTRAP_ROOTFS. Nothing here changes the test machine.
// scripts/test-install-bootstrap.ts runs the real apt path in disposable Ubuntu containers.
import { describe, expect, test } from "bun:test";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const repoRoot = join(import.meta.dir, "..");
const script = readFileSync(join(repoRoot, "install.sh"), "utf8");
const BOOTSTRAP_TIMEOUT_MS = 60_000;

// Real tools the script needs besides the stubbed ones.
const REAL_TOOLS = [
  "bash",
  "sed",
  "tr",
  "head",
  "dirname",
  "ls",
  "cat",
  "chmod",
  "install",
  "mkdir",
  "grep",
  "touch",
  "rm",
  "cp",
];

/** Stubs log their arguments to $STUB_CALLS. apt-get install "provides" commands by copying stubs in. */
const STUBS: Record<string, string> = {
  id: 'echo "${STUB_UID:-0}"',
  uname: 'case "$1" in -s) echo "${STUB_KERNEL:-Linux}" ;; -m) echo "${STUB_MACHINE:-x86_64}" ;; esac',
  "dpkg-query":
    'for p in $(cat "$STUB_STATE/installed" 2>/dev/null); do [ "$p" = "${@: -1}" ] && { echo "install ok installed"; exit 0; }; done; exit 1',
  "apt-get": `if [ "$1" = install ]; then
  for p in "$@"; do
    case "$p" in -*|install) continue ;; esac
    echo "$p" >> "$STUB_STATE/installed"
    case "$p" in
      git|curl|mise|tailscale|extrepo) cp "$STUB_TEMPLATES/$p" "$STUB_BIN/$p" ;;
      iproute2) cp "$STUB_TEMPLATES/ip" "$STUB_BIN/ip"; cp "$STUB_TEMPLATES/ss" "$STUB_BIN/ss" ;;
      docker-ce) cp "$STUB_TEMPLATES/docker" "$STUB_BIN/docker" ;;
      docker-compose-plugin) touch "$STUB_STATE/compose" ;;
    esac
  done
fi`,
  docker:
    'case "$1 $2" in "compose version") [ -f "$STUB_STATE/compose" ] && echo v2.40.0 ;; "info --format") [ ! -f "$STUB_STATE/docker-stopped" ] ;; esac',
  snap: '[ "$1 $2" = "list docker" ] && [ "${STUB_SNAP_DOCKER:-0}" = 1 ] && exit 0; exit 1',
  git: `case "$1" in
  clone) mkdir -p "\${@: -1}/.git" ;;
  -C) shift 2; case "$1" in
      status) printf '%s' "\${STUB_GIT_STATUS:-}" ;;
      rev-parse) [ "$2" = HEAD ] && echo "\${STUB_GIT_HEAD:-aaa}" || echo "\${STUB_GIT_FETCH_HEAD:-aaa}" ;;
      symbolic-ref) [ -n "\${STUB_GIT_BRANCH:-main}" ] && echo "\${STUB_GIT_BRANCH:-main}" || exit 1 ;;
      merge-base) exit "\${STUB_GIT_NOT_ANCESTOR:-0}" ;;
    esac ;;
esac`,
  curl: 'while [ $# -gt 0 ]; do [ "$1" = -o ] && echo KEY > "$2"; shift; done',
  mise: 'case "$1" in --version) echo "mise 2026.11.0" ;; which) echo "$STUB_TEMPLATES/bun" ;; esac',
  bun: '[[ "$TS_API_KEY" = tskey-api-bootstrap-probe && "$TS_OAUTH_CLIENT_ID" = client-probe && "$HCLOUD_TOKEN" = hcloud-bootstrap-probe ]] || exit 9',
  systemctl: 'rm -f "$STUB_STATE/docker-stopped"',
  flock: 'exit "${STUB_LOCK_EXIT:-0}"',
  ip: "exit 0",
  ss: "exit 0",
  extrepo: "exit 0",
  tailscale: "exit 0",
  sudo: "exit 0",
};

type Run = {
  status: number;
  stdout: string;
  stderr: string;
  calls: string[];
  rootfs: string;
  installDir: string;
};

function sandbox(present: string[]) {
  const dir = mkdtempSync(join(tmpdir(), "ark-install-sh-"));
  const bin = join(dir, "bin");
  const templates = join(dir, "templates");
  const state = join(dir, "state");
  const rootfs = join(dir, "rootfs");
  for (const path of [bin, templates, state, join(rootfs, "etc")]) mkdirSync(path, { recursive: true });
  for (const [name, body] of Object.entries(STUBS)) {
    const file = join(templates, name);
    const rejectApiEnv =
      name === "bun"
        ? ""
        : `
if [[ -n "$TS_API_KEY$TS_OAUTH_CLIENT_SECRET$TS_OAUTH_CLIENT_ID$HCLOUD_TOKEN" ]]; then
  echo "API credential reached ${name}" >&2
  exit 9
fi
`;
    writeFileSync(file, `#!/bin/bash\necho "${name} $*" >> "$STUB_CALLS"\n${rejectApiEnv}${body}\n`);
    chmodSync(file, 0o755);
  }
  for (const name of [...present, "id", "uname", "dpkg-query", "apt-get", "systemctl", "flock"]) {
    writeFileSync(join(bin, name), readFileSync(join(templates, name)));
    chmodSync(join(bin, name), 0o755);
  }
  for (const tool of REAL_TOOLS) {
    const real = Bun.which(tool, { PATH: "/usr/bin:/bin" });
    if (real && !existsSync(join(bin, tool))) symlinkSync(real, join(bin, tool));
  }
  osRelease(rootfs, "ubuntu", "24.04", "noble");
  return { dir, bin, templates, state, rootfs };
}

function osRelease(rootfs: string, id: string, version: string, codename: string) {
  writeFileSync(
    join(rootfs, "etc", "os-release"),
    `ID=${id}\nVERSION_ID="${version}"\nVERSION_CODENAME=${codename}\nPRETTY_NAME="${id} ${version}"\n`,
  );
}

function run(
  box: ReturnType<typeof sandbox>,
  {
    env = {},
    args = [],
    file,
    stdin,
  }: { env?: Record<string, string>; args?: string[]; file?: string; stdin?: string } = {},
): Run {
  const target = file ?? join(box.dir, "install.sh");
  if (!file) writeFileSync(target, script);
  const installDir = join(box.dir, "opt", "ark-stack");
  const calls = join(box.state, "calls");
  const result = Bun.spawnSync(
    [join(box.bin, "bash"), ...(stdin === undefined ? [target] : ["-s", "--"]), ...args],
    {
      cwd: box.dir,
      env: {
        PATH: box.bin,
        HOME: box.dir,
        STUB_CALLS: calls,
        STUB_STATE: box.state,
        STUB_BIN: box.bin,
        STUB_TEMPLATES: box.templates,
        ARK_BOOTSTRAP_ROOTFS: box.rootfs,
        ARK_INSTALL_DIR: installDir,
        ...env,
      },
      stdin: stdin === undefined ? "ignore" : new TextEncoder().encode(stdin),
    },
  );
  return {
    status: result.exitCode,
    stdout: result.stdout.toString(),
    stderr: result.stderr.toString(),
    calls: existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n").filter(Boolean) : [],
    rootfs: box.rootfs,
    installDir,
  };
}

const CHANGES = /^(apt-get|git clone|git -C \S+ (merge|checkout|fetch)|curl|mise|systemctl|extrepo)/;
const changed = (calls: string[]) => calls.filter((call) => CHANGES.test(call));

describe("install.sh", () => {
  test("API credentials reach only the guided setup on a fresh host", () => {
    const box = sandbox([]);
    const result = run(box, {
      env: {
        TS_API_KEY: "tskey-api-bootstrap-probe",
        TS_OAUTH_CLIENT_ID: "client-probe",
        HCLOUD_TOKEN: "hcloud-bootstrap-probe",
      },
      args: ["--non-interactive", "--domain", "example.com"],
      stdin: script,
    });
    expect(result.status).toBe(0);
    expect(result.stderr).not.toContain("API credential reached");
    expect(result.calls.slice(-2)).toEqual([
      "mise which bun",
      "bun --no-env-file scripts/host-setup.ts --non-interactive --domain example.com",
    ]);
  });
  test("is valid bash and runs everything from one function called on the last line", () => {
    expect(Bun.spawnSync(["bash", "-n", join(repoRoot, "install.sh")]).exitCode).toBe(0);
    const lines = script.trimEnd().split("\n");
    expect(lines.at(-1)).toBe('{ ark_bootstrap "$@"; }');
    // Outside the function there are only comments and blank lines.
    const start = lines.indexOf("ark_bootstrap() {");
    const end = lines.lastIndexOf("}");
    const outside = [...lines.slice(0, start), ...lines.slice(end + 1, -1)];
    expect(outside.every((line) => line === "" || line.startsWith("#"))).toBe(true);
  });

  test(
    "a truncated download runs nothing",
    () => {
      const box = sandbox([]);
      const callLine = script.lastIndexOf('{ ark_bootstrap "$@"; }');
      const cuts = new Set<number>();
      for (let cut = 0; cut < callLine; cut += 211) cuts.add(cut);
      // The final newline is optional in Bash. Every cut before the closing brace must be inert.
      for (let cut = callLine - 40; cut < script.trimEnd().length; cut++) cuts.add(cut);
      for (const cut of cuts) {
        const result = run(box, { stdin: script.slice(0, cut), args: ["--non-interactive"] });
        expect({ cut, calls: result.calls }).toEqual({ cut, calls: [] });
      }
      const complete = run(box, { stdin: script, args: ["--non-interactive", "--domain", "example.com"] });
      expect(complete.status).toBe(0);
      expect(complete.calls.at(-1)).toBe("mise run host:setup --non-interactive --domain example.com");
    },
    BOOTSTRAP_TIMEOUT_MS,
  );

  test("without root it changes nothing, explains and prints the sudo command", () => {
    const box = sandbox(["sudo", "docker", "mise"]);
    const result = run(box, { env: { STUB_UID: "1000", ARK_REF: "v1.2.0" } });
    expect(result.status).not.toBe(0);
    expect(changed(result.calls)).toEqual([]);
    expect(result.stdout).toContain("nothing has been changed");
    expect(result.stdout).toContain(
      "curl -fsSL https://raw.githubusercontent.com/arkaydeus/ark-stack/main/install.sh | sudo ARK_REF=v1.2.0 ARK_INSTALL_DIR=",
    );
    expect(result.stdout).toContain("[ok]   operating system: ubuntu 24.04");
    expect(result.stdout).toContain("[ok]   architecture: x86_64");
    expect(result.stdout).toContain("[ok]   sudo is installed");
  });

  test("without root, from a checkout, it prints sudo ./install.sh with the arguments", () => {
    const box = sandbox([]);
    const result = run(box, {
      env: { STUB_UID: "1000" },
      file: join(repoRoot, "install.sh"),
      args: ["--domain", "example.com"],
    });
    expect(result.status).not.toBe(0);
    expect(result.stdout).toContain(`sudo ${join(repoRoot, "install.sh")} --domain example.com`);
    expect(result.stdout).toContain("[fail] sudo is not installed");
    expect(changed(result.calls)).toEqual([]);
  });

  test("without root it reports an unsupported OS and architecture", () => {
    const box = sandbox(["sudo"]);
    osRelease(box.rootfs, "debian", "12", "bookworm");
    const result = run(box, { env: { STUB_UID: "1000", STUB_MACHINE: "riscv64" } });
    expect(result.stdout).toContain("[fail] operating system: debian 12 (supported: Ubuntu 22.04 (jammy)");
    expect(result.stdout).toContain("[fail] platform: Linux riscv64");
  });

  test("refuses an unsupported OS as root and changes nothing", () => {
    for (const [id, version, codename] of [
      ["debian", "12", "bookworm"],
      ["ubuntu", "20.04", "focal"],
    ] as const) {
      const box = sandbox([]);
      osRelease(box.rootfs, id, version, codename);
      const result = run(box);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("Unsupported operating system");
      expect(result.stderr).toContain("Nothing was changed");
      expect(changed(result.calls)).toEqual([]);
    }
  });

  test("refuses snap Docker and changes nothing", () => {
    const box = sandbox(["snap", "docker"]);
    const result = run(box, { env: { STUB_SNAP_DOCKER: "1" } });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Docker is installed as a snap");
    expect(changed(result.calls)).toEqual([]);
  });

  test("refuses a distribution docker.io without Compose v2 and changes nothing", () => {
    const box = sandbox(["docker"]);
    writeFileSync(join(box.state, "installed"), "docker.io\n");
    const result = run(box);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("without the Compose v2 plugin");
    expect(result.stderr).toContain("docker-compose-v2");
    expect(changed(result.calls)).toEqual([]);
  });

  test.each(["containerd", "runc"])("refuses standalone %s without a Docker CLI", (pkg) => {
    const box = sandbox([]);
    writeFileSync(join(box.state, "installed"), pkg + "\n");
    const result = run(box);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("The installed " + pkg + " package conflicts");
    expect(changed(result.calls)).toEqual([]);
    expect(existsSync(join(box.rootfs, "etc/apt"))).toBe(false);
  });

  test("refuses to mutate apt or the checkout under a competing deployment lock", () => {
    const result = run(sandbox([]), { env: { STUB_LOCK_EXIT: "1" } });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("signed maintenance run is in progress");
    expect(changed(result.calls)).toEqual([]);
  });

  test(
    "starts a stopped preinstalled Docker daemon and checks it again",
    () => {
      const box = sandbox(["docker", "mise", "tailscale", "git", "curl", "ip", "ss"]);
      writeFileSync(join(box.state, "installed"), "git\ncurl\nca-certificates\njq\nopenssl\n");
      writeFileSync(join(box.state, "compose"), "");
      writeFileSync(join(box.state, "docker-stopped"), "");
      mkdirSync(join(box.rootfs, "run", "systemd", "system"), { recursive: true });
      const result = run(box);
      expect(result.status).toBe(0);
      expect(
        result.calls.filter((call) => call.startsWith("docker info") || call.startsWith("systemctl")),
      ).toEqual([
        "docker info --format {{.ServerVersion}}",
        "systemctl enable --now docker.service",
        "docker info --format {{.ServerVersion}}",
      ]);
      const resumed = run(box);
      expect(resumed.status).toBe(0);
      expect(resumed.calls.filter((call) => call.startsWith("systemctl"))).toHaveLength(1);
    },
    BOOTSTRAP_TIMEOUT_MS,
  );

  test(
    "on a fresh host it installs every prerequisite, clones and hands off to host:setup",
    () => {
      const box = sandbox([]);
      const result = run(box, { args: ["--non-interactive", "--domain", "example.com"] });
      // Without systemd (macOS, containers) the script only warns that docker.service was not started.
      expect(
        result.stderr.replace("warning: systemd is not running, so docker.service was not started.\n", ""),
      ).toBe("");
      expect(result.status).toBe(0);
      const apt = result.calls.filter((call) => call.startsWith("apt-get install"));
      expect(apt[0]).toBe(
        "apt-get install -y -q --no-remove --no-install-recommends git curl ca-certificates jq openssl iproute2",
      );
      expect(apt).toContain(
        "apt-get install -y -q --no-remove --no-install-recommends docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin",
      );
      expect(apt).toContain("apt-get install -y -q --no-remove --no-install-recommends extrepo");
      expect(apt).toContain("apt-get install -y -q --no-remove --no-install-recommends mise");
      expect(apt).toContain("apt-get install -y -q --no-remove --no-install-recommends tailscale");
      const docker = readFileSync(join(box.rootfs, "etc/apt/sources.list.d/docker.sources"), "utf8");
      expect(docker).toContain("URIs: https://download.docker.com/linux/ubuntu\nSuites: noble\n");
      expect(docker).toContain("Architectures: amd64\nSigned-By: /etc/apt/keyrings/docker.asc");
      expect(readFileSync(join(box.rootfs, "etc/apt/sources.list.d/tailscale.list"), "utf8")).toBe(
        "deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/ubuntu noble main\n",
      );
      expect(result.calls).toContain(
        "curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o " +
          join(box.rootfs, "etc/apt/keyrings/docker.asc"),
      );
      expect(result.calls).toContain("extrepo enable mise");
      expect(result.calls).toContain(
        `git clone --quiet --branch main -- https://github.com/arkaydeus/ark-stack.git ${result.installDir}`,
      );
      const mise = result.calls.filter((call) => call.startsWith("mise ") && call !== "mise --version");
      expect(mise).toEqual([
        `mise trust ${result.installDir}/mise.toml`,
        "mise install",
        "mise exec -- bun install --frozen-lockfile",
        "mise run host:setup --non-interactive --domain example.com",
      ]);
    },
    BOOTSTRAP_TIMEOUT_MS,
  );

  test(
    "with everything present it installs nothing and fast-forwards nothing when current",
    () => {
      const box = sandbox(["docker", "mise", "tailscale", "git", "curl", "snap", "ip", "ss"]);
      writeFileSync(join(box.state, "installed"), "git\ncurl\nca-certificates\njq\nopenssl\ndocker-ce\n");
      writeFileSync(join(box.state, "compose"), "");
      mkdirSync(join(box.dir, "opt", "ark-stack", ".git"), { recursive: true });
      const result = run(box);
      expect(result.status).toBe(0);
      expect(result.calls.filter((call) => call.startsWith("apt-get"))).toEqual([]);
      expect(
        result.calls.some((call) => call.startsWith("git clone") || / merge | checkout /.test(call)),
      ).toBe(false);
      expect(result.stdout).toContain("Already at main.");
      expect(result.calls.at(-1)).toBe("mise run host:setup");
    },
    BOOTSTRAP_TIMEOUT_MS,
  );

  test(
    "updates a clean checkout with a fast-forward only, and refuses a dirty or diverged one",
    () => {
      const setup = () => {
        const box = sandbox(["docker", "mise", "tailscale", "git", "curl"]);
        writeFileSync(join(box.state, "installed"), "git\ncurl\nca-certificates\njq\nopenssl\n");
        writeFileSync(join(box.state, "compose"), "");
        mkdirSync(join(box.dir, "opt", "ark-stack", ".git"), { recursive: true });
        return box;
      };
      const forward = run(setup(), { env: { STUB_GIT_HEAD: "aaa", STUB_GIT_FETCH_HEAD: "bbb" } });
      expect(forward.status).toBe(0);
      expect(forward.calls).toContain(`git -C ${forward.installDir} merge --quiet --ff-only bbb`);

      const dirty = run(setup(), { env: { STUB_GIT_STATUS: " M scripts/install.ts\n" } });
      expect(dirty.status).toBe(1);
      expect(dirty.stderr).toContain("has local changes");
      expect(dirty.calls.some((call) => call.startsWith("mise trust"))).toBe(false);

      const untracked = run(setup(), { env: { STUB_GIT_STATUS: "?? mise.local.toml\n" } });
      expect(untracked.status).toBe(1);
      expect(untracked.calls.some((call) => / fetch |^mise trust/.test(call))).toBe(false);

      const diverged = run(setup(), {
        env: { STUB_GIT_HEAD: "aaa", STUB_GIT_FETCH_HEAD: "bbb", STUB_GIT_NOT_ANCESTOR: "1" },
      });
      expect(diverged.status).toBe(1);
      expect(diverged.stderr).toContain("is not a fast-forward");
      expect(diverged.calls.some((call) => / merge | checkout /.test(call))).toBe(false);
    },
    BOOTSTRAP_TIMEOUT_MS,
  );

  test(
    "adds only the Compose plugin to Docker's own docker-ce",
    () => {
      const box = sandbox(["docker", "mise", "tailscale", "git", "curl"]);
      writeFileSync(join(box.state, "installed"), "git\ncurl\nca-certificates\njq\nopenssl\ndocker-ce\n");
      const result = run(box);
      expect(result.status).toBe(0);
      expect(result.calls).toContain(
        "apt-get install -y -q --no-remove --no-install-recommends docker-compose-plugin docker-buildx-plugin",
      );
      expect(result.calls.some((call) => call.includes(" docker-ce docker-ce-cli"))).toBe(false);
    },
    BOOTSTRAP_TIMEOUT_MS,
  );

  test(
    "refuses an install directory that is not a checkout, and a bad ARK_REF",
    () => {
      const box = sandbox([]);
      mkdirSync(join(box.dir, "opt", "ark-stack"), { recursive: true });
      writeFileSync(join(box.dir, "opt", "ark-stack", "notes.txt"), "mine");
      const result = run(box);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("is not a git checkout");
      expect(changed(result.calls)).toEqual([]);
      const ref = run(sandbox([]), { env: { ARK_REF: "--upload-pack=evil" } });
      expect(ref.status).toBe(1);
      expect(changed(ref.calls)).toEqual([]);
      const local = sandbox([]);
      mkdirSync(join(local.dir, "scripts"));
      writeFileSync(join(local.dir, "scripts/host-setup.ts"), "");
      writeFileSync(join(local.dir, "mise.toml"), "");
      writeFileSync(join(local.dir, "install.sh"), script);
      const checkout = run(local, {
        file: join(local.dir, "install.sh"),
        env: { ARK_REF: "--upload-pack=evil" },
      });
      expect(checkout.status).toBe(0);
      expect(checkout.stdout).toContain("Using the checkout");
    },
    BOOTSTRAP_TIMEOUT_MS,
  );
});
