#!/bin/sh
# HAProxy launch guard (docs/design/front-door.md §3.2, §3.8.6, FD-25). It is the `edge-l4` container's
# entrypoint and runs before every start, including restarts after the watchdog stopped HAProxy. The
# official HAProxy binary is unchanged; this process starts it in master-worker mode and supervises it.
#
# HAProxy is started with `-f $ARK_EDGE_L4_LAUNCH_DIR/haproxy.cfg`, a symlink in this container's own
# tmpfs that points at either `current/haproxy.cfg` or `current/haproxy.closed.cfg`. `current` is the
# generation symlink the domain worker swaps, so a master-CLI `reload` always reads the newest
# generation in the mode this guard chose:
#
# - A configuration without protected routes needs no lease. Supervision stays latched after any
#   generation with an HTTP or L4 tailnet route.
# - Otherwise the edge watchdog must answer `open` (every protected server authorised by a valid lease)
#   for the full variant; else (or when the watchdog cannot be reached) the closed variant, which
#   omits L4 tailnet targets. Caddy independently checks its HTTP lease and selects its closed
#   configuration when needed.
# - Once a protected route has existed, the watchdog must keep reporting verified HAProxy enforcement every
#   250 ms. After two consecutive misses, every HAProxy process is killed (listeners and established
#   sessions), the container exits, and the next start is decided again.
# - Started closed, the guard re-asks the watchdog and switches to the full variant (link + reload)
#   once the lease allows it; told `closed` while full, it points the link back at the closed variant
#   so no later reload re-admits a withdrawn backend.
#
# Reload lock (FD-25): HAProxy's master re-executes as soon as it parses a `reload`, answering only the
# connection that sent it. Any other master-CLI connection it had accepted is closed unanswered, and a
# second `reload` on it never runs. Concurrent reloads by this guard and the domain worker's
# `edge.l4_apply` therefore made one of them report "the master CLI did not answer the reload".
# Every reloader holds an exclusive flock(2) on `reload.lock` beside the master socket (the shared
# `ark_haproxy_run` tmpfs) for the whole request: this guard with BusyBox `flock`, the worker through
# `HaproxyMaster.reload` (shared/src/haproxy-control.ts). The kernel drops the lock when a holder exits.
# `ark-edge-l4-launch-guard reload` runs only this guard's locked reload, once, and prints the answer.
set -eu

root="${ARK_EDGE_L4_DIR:-/usr/local/etc/haproxy}"
full="$root/current/haproxy.cfg"
closed="$root/current/haproxy.closed.cfg"
launch_dir="${ARK_EDGE_L4_LAUNCH_DIR:-/run/ark-l4}"
link="$launch_dir/haproxy.cfg"
master="${ARK_HAPROXY_MASTER_SOCKET:-/var/run/haproxy/master.sock}"
gid="${ARK_EDGE_L4_GID:-4400}"
watchdog="${ARK_EDGE_WATCHDOG_URL:-http://edge-watchdog:2021}"
# Relative paths in a generation (allowlists, certificates, CRLs) resolve from `current`, read again at
# every reload; the validator sets the same variable to the candidate it checks.
export ARK_EDGE_L4_GENERATION="$root/current"

guarded() { grep -Eq '^# ark-(tailnet|http)-route ' "$full" 2>/dev/null; }
# `wget -T` bounds reads, not name resolution: once the watchdog container is gone, resolving its
# name can take the resolver's 5 s timeout (Docker behind systemd-resolved). Bound the whole request.
ask() { timeout 1 wget -q -T 1 -O - "$watchdog/v1/launch?proxy=haproxy$1" 2>/dev/null || true; }
point() {
  ln -s "$1" "$link.next"
  mv -f "$link.next" "$link"
}
reload_lock="${ARK_HAPROXY_RELOAD_LOCK:-${master%/*}/reload.lock}"
# Prints the master's answer to `reload`, sent under the reload lock. With an argument, the launch link
# is first pointed at it inside the same lock. Waits at most 60 s for the lock (another reloader holds
# it for at most its own bounded request and confirmation); prints nothing when it cannot be taken.
locked_reload() {
  [ -e "$reload_lock" ] || (umask 007 && : >>"$reload_lock") 2>/dev/null || true
  (
    tries=0
    until flock -n 9; do
      tries=$((tries + 1))
      if [ "$tries" -ge 600 ]; then
        echo "ark edge-l4 launch guard: the reload lock $reload_lock is busy" >&2
        exit 1
      fi
      sleep 0.1
    done
    if [ -n "${1:-}" ]; then point "$1"; fi
    echo reload | socat -t 30 - "UNIX-CONNECT:$master" 2>&1
  ) 9<"$reload_lock"
}
if [ "${1:-}" = reload ]; then
  locked_reload
  exit
fi

if [ ! -r "$full" ]; then
  echo "ark edge-l4 launch guard: $full is missing; refusing to start" >&2
  exit 1
fi
mode=full
# Latch before starting: removing the final route must not abandon leaving workers.
latched=0
if guarded; then latched=1; fi
if ! guarded; then
  reason="the configuration has no protected route"
else
  decision=""
  attempt=0
  while [ "$attempt" -lt 5 ]; do
    decision="$(ask "")"
    [ -n "$decision" ] && break
    attempt=$((attempt + 1))
    sleep 1
  done
  if [ "$decision" = "open" ]; then
    reason="the watchdog confirmed a valid lease"
  elif [ -r "$closed" ]; then
    mode=closed
    reason="protected routes not authorised (watchdog: ${decision:-unreachable})"
  else
    echo "ark edge-l4 launch guard: no valid lease and no closed config; refusing to start" >&2
    exit 1
  fi
fi
rm -f "$link" "$link.next"
if [ "$mode" = full ]; then point "$full"; else point "$closed"; fi
echo "ark edge-l4 launch guard: starting from the $mode configuration: $reason" >&2
haproxy -W -db -S "$master,gid,$gid,mode,660" -f "$link" &
haproxy_pid=$!

kill_all() {
  # No graceful stop: established sessions to withdrawn backends must close as well as listeners.
  kill -KILL "$haproxy_pid" 2>/dev/null || true
  pkill -KILL -x haproxy 2>/dev/null || true
}

# Keep heartbeat enforcement independent of launch requests and potentially slow reloads.
# An immutable generation records that protected workers might exist, including generations
# installed and replaced between two polls. Generations are retained while workers leave.
protected_generation() { grep -Eq '^# ark-(tailnet|http)-route ' "$root"/generations/*/haproxy.cfg 2>/dev/null; }
supervise() {
  # Allow the first enforcement pass to inspect the newly started HAProxy.
  sleep 2
  misses=0
  while kill -0 "$haproxy_pid" 2>/dev/null; do
    if guarded || protected_generation; then latched=1; fi
    if [ "$latched" = 1 ]; then
      heartbeat="$(timeout 0.5 wget -q -T 1 -O - "$watchdog/v1/supervise?proxy=haproxy" 2>/dev/null || true)"
      if [ "$heartbeat" = "ok" ]; then
        misses=0
      else
        # One miss is tolerated: the master CLI stalls while a reload re-executes HAProxy, which can
        # delay a single enforcement pass. Two consecutive misses take at most 1.5 s (including poll phase and HTTP timeouts).
        misses=$((misses + 1))
      fi
      if [ "$misses" -ge 2 ]; then
        echo "ark edge-l4 launch guard: watchdog enforcement unavailable; terminating HAProxy" >&2
        kill_all
        return
      fi
      # Never spend the remaining shutdown budget on launch polling after a missed heartbeat.
      if [ "$heartbeat" != "ok" ]; then sleep 0.25; continue; fi
    fi
    sleep 0.25
  done
}
# A separate process may block on the CLI without delaying heartbeat enforcement.
reopen() {
  while kill -0 "$haproxy_pid" 2>/dev/null; do
    if guarded; then
      decision="$(ask "&cached=1")"
      if [ "$mode" = closed ] && [ "$decision" = "open" ]; then
        answer="$(locked_reload "$full" || true)"
        if printf '%s\n' "$answer" | grep -q '^Success=1$'; then
          mode=full
          echo "ark edge-l4 launch guard: lease valid; switched to the full configuration" >&2
        else
          point "$closed"
          echo "ark edge-l4 launch guard: full reload unconfirmed; retaining closed mode and retrying" >&2
        fi
      elif [ "$mode" = full ] && [ "$decision" = "closed" ]; then
        point "$closed"
        mode=closed
        echo "ark edge-l4 launch guard: lease no longer allows every protected route; later reloads use the closed configuration" >&2
      fi
    fi
    sleep 1
  done
}
supervise &
supervisor_pid=$!
reopen &
reopen_pid=$!
shutdown() {
  kill "$reopen_pid" 2>/dev/null || true
  kill "$supervisor_pid" 2>/dev/null || true
  kill -USR1 "$haproxy_pid" 2>/dev/null || true
}
trap shutdown TERM INT
set +e
wait "$haproxy_pid"
status=$?
# `wait` returns early when a trapped signal arrives; wait for HAProxy itself to finish.
while kill -0 "$haproxy_pid" 2>/dev/null; do wait "$haproxy_pid"; status=$?; done
kill "$reopen_pid" 2>/dev/null || true
kill "$supervisor_pid" 2>/dev/null || true
wait "$supervisor_pid" 2>/dev/null
exit "$status"
