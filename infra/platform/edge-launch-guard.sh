#!/bin/sh
# Caddy launch guard (docs/design/front-door.md §3.2, FD-06). It is the `edge` container's entrypoint
# and runs before every start, including restarts after the watchdog stopped Caddy. The official Caddy
# binary is unchanged. This process also supervises the watchdog while Caddy serves.
#
# - A Caddyfile without any tailnet route (the bootstrap config, a host without routes) needs no
#   lease and starts as it is.
# - Otherwise the edge watchdog answers `open` only when every tailnet handler in Caddyfile
#   matches its allowed route identity and pinned backend under a valid lease: start from Caddyfile.
# - Otherwise, or when the watchdog cannot be reached, start from Caddyfile.closed, which renders
#   no tailnet route. ACME, redirects and the admin site keep working; tailnet routes fail closed.
set -eu

dir="${ARK_EDGE_CONFIG_DIR:-/etc/caddy/ark}"
full="$dir/Caddyfile"
closed="$dir/Caddyfile.closed"
watchdog="${ARK_EDGE_WATCHDOG_URL:-http://edge-watchdog:2021}"
admin="${ARK_EDGE_LOCAL_ADMIN_URL:-http://edge-admin:2019}"
guarded=0

if ! grep -Eiq '^# ark-tailnet-route |ark_tailnet_route|reverse_proxy[^#]*(100[.]|\[fd7a:)' "$full" 2>/dev/null; then
  config="$full"
  reason="the config has no tailnet route"
else
  guarded=1
  # An unreachable watchdog (still starting after a host restart) gets a few seconds; `closed` is final.
  decision=""
  attempt=0
  while [ "$attempt" -lt 5 ]; do
    decision="$(wget -q -T 3 -O - "$watchdog/v1/launch" 2>/dev/null || true)"
    [ -n "$decision" ] && break
    attempt=$((attempt + 1))
    sleep 1
  done
  if [ "$decision" = "open" ]; then
    config="$full"
    reason="the watchdog confirmed a valid lease"
  elif [ -f "$closed" ]; then
    config="$closed"
    reason="no valid lease (watchdog: ${decision:-unreachable}); tailnet routes are not served"
  else
    echo "ark launch guard: no valid lease and no closed config; refusing to start" >&2
    exit 1
  fi
fi
echo "ark launch guard: starting from $config: $reason" >&2
caddy run --config "$config" --adapter caddyfile &
caddy_pid=$!
supervise() {
  # Allow the first enforcement pass to inspect the newly started Caddy.
  sleep 2
  while kill -0 "$caddy_pid" 2>/dev/null; do
    # Watch even when launched without routes: edge.apply can add them later.
    if grep -q '^# ark-tailnet-route ' "$full" 2>/dev/null; then guarded=1; fi
    if [ "$guarded" -eq 0 ]; then
      # Inspect the running config as well: a file may have been replaced before a failed reload.
      # Never infer an empty active config from an empty or unreadable on-disk file.
      active="$(wget -q -T 1 -O - "$admin/config/" 2>/dev/null || true)"
      if [ -z "$active" ] || printf '%s' "$active" | grep -Eq 'ark_tailnet_route|"dial"[[:space:]]*:[[:space:]]*"(tcp/)?(100\.|\[fd7a:)'; then guarded=1; fi
    fi
    if [ "$guarded" -eq 1 ]; then
      heartbeat="$(wget -q -T 1 -O - "$watchdog/v1/supervise" 2>/dev/null || true)"
      if [ "$heartbeat" != "ok" ]; then
        echo "ark launch guard: watchdog enforcement unavailable; terminating Caddy" >&2
        # No graceful wait: existing upgraded sessions must close as well as listeners.
        kill -KILL "$caddy_pid" 2>/dev/null || true
        return
      fi
    fi
    sleep 1
  done
}
supervise &
supervisor_pid=$!
shutdown() {
  kill "$supervisor_pid" 2>/dev/null || true
  kill -TERM "$caddy_pid" 2>/dev/null || true
}
trap shutdown TERM INT
set +e
wait "$caddy_pid"
status=$?
kill "$supervisor_pid" 2>/dev/null || true
wait "$supervisor_pid" 2>/dev/null
exit "$status"
