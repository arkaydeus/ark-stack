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
# - A configuration without any tailnet server needs no lease: the full variant, unsupervised.
# - Otherwise the edge watchdog must answer `open` (every tailnet server authorised by a valid lease)
#   for the full variant; else (or when the watchdog cannot be reached) the closed variant, which
#   renders no tailnet backend. HTTP routes through Caddy keep working; tailnet routes fail closed.
# - While a tailnet route exists, the watchdog must keep reporting verified HAProxy enforcement every
#   second. After two consecutive misses, every HAProxy process is killed (listeners and established
#   sessions), the container exits, and the next start is decided again.
# - Started closed, the guard re-asks the watchdog and switches to the full variant (link + reload)
#   once the lease allows it; told `closed` while full, it points the link back at the closed variant
#   so no later reload re-admits a withdrawn backend.
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

guarded() { grep -q '^# ark-tailnet-route ' "$full" 2>/dev/null; }
ask() { wget -q -T 3 -O - "$watchdog/v1/launch?proxy=haproxy$1" 2>/dev/null || true; }
point() {
  ln -s "$1" "$link.next"
  mv -f "$link.next" "$link"
}

if [ ! -r "$full" ]; then
  echo "ark edge-l4 launch guard: $full is missing; refusing to start" >&2
  exit 1
fi
mode=full
if ! guarded; then
  reason="the configuration has no tailnet route"
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
    reason="no valid lease (watchdog: ${decision:-unreachable}); tailnet routes are not served"
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

supervise() {
  # Allow the first enforcement pass to inspect the newly started HAProxy.
  sleep 2
  misses=0
  while kill -0 "$haproxy_pid" 2>/dev/null; do
    if guarded; then
      heartbeat="$(wget -q -T 1 -O - "$watchdog/v1/supervise?proxy=haproxy" 2>/dev/null || true)"
      if [ "$heartbeat" = "ok" ]; then
        misses=0
      else
        # One miss is tolerated: the master CLI stalls while a reload re-executes HAProxy, which can
        # delay a single enforcement pass. Two consecutive misses (about 2-4 s) stop HAProxy.
        misses=$((misses + 1))
      fi
      if [ "$misses" -ge 2 ]; then
        echo "ark edge-l4 launch guard: watchdog enforcement unavailable; terminating HAProxy" >&2
        kill_all
        return
      fi
      decision="$(ask "&cached=1")"
      if [ "$mode" = closed ] && [ "$decision" = "open" ]; then
        point "$full"
        mode=full
        answer="$(echo reload | socat -t 30 - "UNIX-CONNECT:$master" 2>&1 | head -n 1 || true)"
        echo "ark edge-l4 launch guard: lease valid; switched to the full configuration ($answer)" >&2
      elif [ "$mode" = full ] && [ "$decision" = "closed" ]; then
        point "$closed"
        mode=closed
        echo "ark edge-l4 launch guard: lease no longer allows every tailnet route; later reloads use the closed configuration" >&2
      fi
    fi
    sleep 1
  done
}
supervise &
supervisor_pid=$!
shutdown() {
  kill "$supervisor_pid" 2>/dev/null || true
  kill -USR1 "$haproxy_pid" 2>/dev/null || true
}
trap shutdown TERM INT
set +e
wait "$haproxy_pid"
status=$?
# `wait` returns early when a trapped signal arrives; wait for HAProxy itself to finish.
while kill -0 "$haproxy_pid" 2>/dev/null; do wait "$haproxy_pid"; status=$?; done
kill "$supervisor_pid" 2>/dev/null || true
wait "$supervisor_pid" 2>/dev/null
exit "$status"
