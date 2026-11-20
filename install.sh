#!/usr/bin/env bash
# Ark Stack bootstrap: one command on a fresh Ubuntu VPS.
#
#   curl -fsSL https://raw.githubusercontent.com/arkaydeus/ark-stack/main/install.sh | sudo bash
#   sudo ./install.sh            (from a checkout)
#
# It installs the prerequisites that are missing (git, curl, ca-certificates, jq, OpenSSL, Docker
# Engine with the Compose v2 plugin, mise and the Tailscale package), clones or fast-forwards the
# repository in /opt/ark-stack, runs `mise trust` and `mise install`, then hands off to the guided
# setup (`mise run host:setup`, scripts/host-setup.ts). Arguments are passed to the guided setup:
#
#   curl -fsSL …/install.sh | sudo bash -s -- --non-interactive --domain example.com …
#
# Settings: ARK_REF (branch or tag, default main), ARK_INSTALL_DIR (default /opt/ark-stack) and
# ARK_REPO_URL (default the public GitHub repository). Without root it changes nothing: it prints what
# it would do and the exact sudo command. It never removes packages, Docker resources or users, and
# it refuses a conflicting Docker install (snap, or a distribution docker.io without Compose v2).
#
# The whole script is one function called on the last line, so a truncated download never runs.

ark_bootstrap() {
  set -euo pipefail

  local repo_url="${ARK_REPO_URL:-https://github.com/arkaydeus/ark-stack.git}"
  local one_liner="curl -fsSL https://raw.githubusercontent.com/arkaydeus/ark-stack/main/install.sh | sudo bash"
  local ref="${ARK_REF:-main}"
  local install_dir="${ARK_INSTALL_DIR:-/opt/ark-stack}"
  # Test-only prefix for the host files this script reads and writes (os-release and apt sources).
  local rootfs="${ARK_BOOTSTRAP_ROOTFS:-}"
  local supported="22.04 (jammy), 24.04 (noble) and 26.04 (resolute)"
  local -a setup_args=("$@")

  say() { printf '%s\n' "$*"; }
  step() { printf '==> %s\n' "$*"; }
  warn() { printf 'warning: %s\n' "$*" >&2; }
  die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
  }
  have() { command -v "$1" >/dev/null 2>&1; }
  quote_args() {
    local out="" arg
    for arg in "$@"; do out+=" $(printf '%q' "$arg")"; done
    printf '%s' "$out"
  }

  local arg
  for arg in "$@"; do
    case "$arg" in
      -h | --help)
        say "Usage: $one_liner [-s -- SETUP-OPTIONS]"
        say "   or: sudo ./install.sh [SETUP-OPTIONS]"
        say ""
        say "Installs the prerequisites, fetches Ark Stack into \$ARK_INSTALL_DIR (default /opt/ark-stack)"
        say "at \$ARK_REF (default main), then runs the guided setup (mise run host:setup)."
        say "Run 'mise run host:setup --help' in a checkout for the setup options."
        exit 0
        ;;
    esac
  done

  # ---- Where the code comes from -------------------------------------------------------------
  # Run as a file from inside a checkout: use that checkout. Piped (curl | bash): /opt/ark-stack.
  local source_path="${BASH_SOURCE[0]:-}" checkout=""
  if [[ -n "$source_path" && -f "$source_path" ]]; then
    local source_dir
    source_dir="$(cd "$(dirname "$source_path")" && pwd -P)"
    if [[ -f "$source_dir/scripts/host-setup.ts" && -f "$source_dir/mise.toml" ]]; then
      checkout="$source_dir"
    fi
  fi

  # ---- Checks that need no root and change nothing ---------------------------------------------
  local os_file="$rootfs/etc/os-release" os_id="" os_version="" codename="" os_name="unknown"
  if [[ -r "$os_file" ]]; then
    os_id="$(sed -n 's/^ID=//p' "$os_file" | tr -d '"' | head -n1)"
    os_version="$(sed -n 's/^VERSION_ID=//p' "$os_file" | tr -d '"' | head -n1)"
    codename="$(sed -n 's/^VERSION_CODENAME=//p' "$os_file" | tr -d '"' | head -n1)"
    os_name="$(sed -n 's/^PRETTY_NAME=//p' "$os_file" | tr -d '"' | head -n1)"
  fi
  local os_ok=0
  if [[ "$os_id" == "ubuntu" ]]; then
    case "$os_version:$codename" in
      22.04:jammy | 24.04:noble | 26.04:resolute) os_ok=1 ;;
    esac
  fi
  local kernel machine arch_ok=0 deb_arch=""
  kernel="$(uname -s)"
  machine="$(uname -m)"
  case "$machine" in
    x86_64 | amd64)
      arch_ok=1
      deb_arch=amd64
      ;;
    aarch64 | arm64)
      arch_ok=1
      deb_arch=arm64
      ;;
  esac

  local uid
  uid="$(id -u)"
  if [[ "$uid" != "0" ]]; then
    say "Ark Stack installer: nothing has been changed. It needs root."
    say ""
    say "Run as root, it will:"
    say "  1. install whatever is missing of git, curl, ca-certificates, jq and OpenSSL (apt),"
    say "     Docker Engine with the Compose v2 plugin (Docker's signed apt repository),"
    say "     mise (its signed apt repository) and Tailscale (its signed apt repository);"
    if [[ -n "$checkout" ]]; then
      say "  2. use this checkout ($checkout) and run mise trust and mise install;"
    else
      say "  2. clone $repo_url at $ref into $install_dir (or fast-forward a clean checkout there),"
      say "     then run mise trust and mise install;"
    fi
    say "  3. start the guided setup: a few questions, Tailscale enrolment, a Tailscale SSH check,"
    say "     hardening and install, the edge node, admin origin and ACME settings, closing public SSH,"
    say "     the provider firewall rules and audit, and a summary."
    say ""
    say "Run:"
    local env_prefix=""
    [[ -n "${ARK_REF:-}" ]] && env_prefix+=" ARK_REF=$(printf '%q' "$ARK_REF")"
    [[ -n "${ARK_INSTALL_DIR:-}" ]] && env_prefix+=" ARK_INSTALL_DIR=$(printf '%q' "$ARK_INSTALL_DIR")"
    [[ -n "${ARK_REPO_URL:-}" ]] && env_prefix+=" ARK_REPO_URL=$(printf '%q' "$ARK_REPO_URL")"
    if [[ -n "$checkout" ]]; then
      # ARK_REF, ARK_INSTALL_DIR and ARK_REPO_URL do not apply to a checkout.
      say "  sudo $(printf '%q' "$checkout/install.sh")$(quote_args "$@")"
    elif [[ $# -gt 0 ]]; then
      say "  curl -fsSL https://raw.githubusercontent.com/arkaydeus/ark-stack/main/install.sh | sudo$env_prefix bash -s --$(quote_args "$@")"
    else
      say "  curl -fsSL https://raw.githubusercontent.com/arkaydeus/ark-stack/main/install.sh | sudo$env_prefix bash"
    fi
    say ""
    say "Preconditions:"
    if [[ "$os_ok" == 1 ]]; then
      say "  [ok]   operating system: $os_name"
    else
      say "  [fail] operating system: $os_name (supported: Ubuntu $supported)"
    fi
    if [[ "$kernel" == "Linux" && "$arch_ok" == 1 ]]; then
      say "  [ok]   architecture: $machine"
    else
      say "  [fail] platform: $kernel $machine (supported: Linux x86_64 or aarch64)"
    fi
    if have sudo; then
      say "  [ok]   sudo is installed"
    else
      say "  [fail] sudo is not installed: run the command as root instead (without sudo)"
    fi
    exit 1
  fi

  [[ "$kernel" == "Linux" ]] || die "Ark Stack installs only on Linux (this is $kernel). Nothing was changed."
  [[ "$arch_ok" == 1 ]] || die "Unsupported architecture $machine; use x86_64 or aarch64. Nothing was changed."
  if [[ "$os_ok" != 1 ]]; then
    die "Unsupported operating system: $os_name. Ark Stack supports Ubuntu $supported, the releases its
hardening (unattended security upgrades from <codename>-security, nftables, systemd) and the Docker,
mise and Tailscale apt repositories cover. Nothing was changed."
  fi

  # ---- Conflicts: refuse before changing anything --------------------------------------------
  if have snap && snap list docker >/dev/null 2>&1; then
    die "Docker is installed as a snap. The snap's confinement and paths break the Ark Docker daemon
settings and published ports. Nothing was changed. Remove it yourself after checking that nothing else
uses it ('sudo snap remove docker'), then run this installer again; it will install Docker Engine from
Docker's apt repository."
  fi
  local docker_state="absent"
  if have docker; then
    if docker compose version >/dev/null 2>&1; then
      docker_state="ready"
    elif dpkg-query -W -f='${Status}' docker-ce 2>/dev/null | grep -q "install ok installed"; then
      # Docker's own package without its Compose plugin: add the plugin from the same repository.
      docker_state="needs-compose"
    else
      die "Docker is installed but without the Compose v2 plugin ('docker compose version' fails),
for example the distribution docker.io package. Nothing was changed. Either install Compose v2 for this
Docker ('sudo apt-get install docker-compose-v2' on Ubuntu), or remove the distribution packages
yourself after checking nothing else needs them and let this installer add Docker Engine from Docker's
repository. See https://docs.docker.com/engine/install/ubuntu/."
    fi
  fi

  # ---- Code location: validate before any change ---------------------------------------------
  [[ "$ref" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || die "ARK_REF must be a branch or tag name, not '$ref'."
  local root
  if [[ -n "$checkout" ]]; then
    root="$checkout"
  else
    [[ "$install_dir" == /* ]] || die "ARK_INSTALL_DIR must be an absolute path."
    root="$install_dir"
    if [[ -e "$root" && ! -d "$root/.git" ]]; then
      if [[ -n "$(ls -A "$root" 2>/dev/null)" ]]; then
        die "$root exists and is not a git checkout. Nothing was changed. Choose another ARK_INSTALL_DIR or move it aside."
      fi
    fi
  fi

  export DEBIAN_FRONTEND=noninteractive
  local apt_updated=0
  apt_update() {
    if [[ "$apt_updated" == 0 ]]; then
      apt-get update -q </dev/null
      apt_updated=1
    fi
  }
  apt_install() {
    apt_update
    apt-get install -y -q --no-install-recommends "$@" </dev/null
  }
  installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }

  # ---- Base packages ------------------------------------------------------------------------------
  step "Checking base packages"
  local -a missing=()
  local package
  for package in git curl ca-certificates jq openssl; do
    installed "$package" || missing+=("$package")
  done
  if ((${#missing[@]})); then
    step "Installing ${missing[*]}"
    apt_install "${missing[@]}"
  else
    say "    git, curl, ca-certificates, jq and openssl are present."
  fi

  local keyrings="$rootfs/etc/apt/keyrings" sources="$rootfs/etc/apt/sources.list.d"

  # ---- Docker Engine and Compose v2 -------------------------------------------------------------
  if [[ "$docker_state" == "ready" ]]; then
    say "    Docker with Compose v2 is present ($(docker compose version --short 2>/dev/null || echo unknown))."
  else
    if [[ ! -f "$sources/docker.sources" ]]; then
      step "Adding Docker's signed apt repository"
      install -m 0755 -d "$keyrings" "$sources"
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o "$keyrings/docker.asc"
      chmod a+r "$keyrings/docker.asc"
      cat >"$sources/docker.sources" <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $codename
Components: stable
Architectures: $deb_arch
Signed-By: /etc/apt/keyrings/docker.asc
EOF
      apt_updated=0
    fi
    if [[ "$docker_state" == "needs-compose" ]]; then
      step "Installing the Docker Compose v2 plugin"
      apt_install docker-compose-plugin docker-buildx-plugin
    else
      step "Installing Docker Engine and the Compose v2 plugin"
      apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    fi
    if [[ -d /run/systemd/system ]]; then
      systemctl enable --now docker.service </dev/null
    else
      warn "systemd is not running, so docker.service was not started."
    fi
    docker compose version >/dev/null 2>&1 || die "docker compose version still fails after installing Docker."
  fi

  # ---- mise ---------------------------------------------------------------------------------------
  if have mise; then
    say "    mise is present ($(mise --version 2>/dev/null | head -n1))."
  else
    step "Adding the mise apt repository (extrepo) and installing mise"
    installed extrepo || apt_install extrepo
    extrepo enable mise </dev/null
    apt_updated=0
    apt_install mise
  fi

  # ---- Tailscale (the host node is enrolled later by the guided setup) ------------------------------
  if have tailscale; then
    say "    Tailscale is present."
  else
    if [[ ! -f "$sources/tailscale.list" ]]; then
      step "Adding Tailscale's signed apt repository"
      install -m 0755 -d "$rootfs/usr/share/keyrings" "$sources"
      curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/$codename.noarmor.gpg" \
        -o "$rootfs/usr/share/keyrings/tailscale-archive-keyring.gpg"
      chmod a+r "$rootfs/usr/share/keyrings/tailscale-archive-keyring.gpg"
      printf 'deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/ubuntu %s main\n' \
        "$codename" >"$sources/tailscale.list"
      apt_updated=0
    fi
    step "Installing Tailscale"
    apt_install tailscale
  fi

  # ---- The code -----------------------------------------------------------------------------------
  if [[ -n "$checkout" ]]; then
    step "Using the checkout at $root"
  elif [[ ! -d "$root/.git" ]]; then
    step "Cloning $repo_url ($ref) into $root"
    install -m 0755 -d "$(dirname "$root")"
    git clone --quiet --branch "$ref" -- "$repo_url" "$root"
  else
    step "Updating the checkout at $root to $ref (fast-forward only)"
    if [[ -n "$(git -C "$root" status --porcelain --untracked-files=no)" ]]; then
      die "$root has local changes. Nothing in it was changed. Commit or discard them, then run this again."
    fi
    git -C "$root" fetch --quiet --tags origin "$ref"
    local head target branch
    head="$(git -C "$root" rev-parse HEAD)"
    target="$(git -C "$root" rev-parse FETCH_HEAD)"
    branch="$(git -C "$root" symbolic-ref --quiet --short HEAD || true)"
    if [[ "$head" == "$target" ]]; then
      say "    Already at $ref."
    elif ! git -C "$root" merge-base --is-ancestor "$head" "$target"; then
      die "$ref is not a fast-forward of the checkout in $root. Nothing in it was changed. Check out the
ref you want there yourself, then run this again."
    elif [[ -n "$branch" && "$branch" == "$ref" ]]; then
      git -C "$root" merge --quiet --ff-only "$target"
    elif [[ -z "$branch" ]]; then
      git -C "$root" -c advice.detachedHead=false checkout --quiet --detach "$target"
    else
      die "$root is on branch $branch, not $ref. Nothing in it was changed. Switch it yourself, or set ARK_REF=$branch."
    fi
  fi

  step "Installing the pinned toolchain (mise trust, mise install, bun install)"
  cd "$root"
  export MISE_YES=1
  mise trust "$root/mise.toml" </dev/null
  mise install </dev/null
  mise exec -- bun install --frozen-lockfile </dev/null

  step "Starting the guided setup (mise run host:setup)"
  # The script itself arrived on stdin when piped, so prompts read the terminal instead.
  if [[ -t 0 ]]; then
    exec mise run host:setup ${setup_args[@]+"${setup_args[@]}"}
  elif { : </dev/tty; } 2>/dev/null; then
    exec mise run host:setup ${setup_args[@]+"${setup_args[@]}"} </dev/tty
  else
    exec mise run host:setup ${setup_args[@]+"${setup_args[@]}"} </dev/null
  fi
}

ark_bootstrap "$@"
