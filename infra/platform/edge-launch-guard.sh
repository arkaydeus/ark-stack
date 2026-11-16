#!/bin/sh
# Caddy launch guard (docs/design/front-door.md §3.2, FD-06). It is the `edge` container's entrypoint
# and runs before every start, including restarts after the watchdog stopped Caddy. The official Caddy
# binary is unchanged; this only chooses which rendered config it starts from.
#
# - The edge watchdog answers `open` only when every tailnet backend in Caddyfile is allowed by a
#   valid lease: start from Caddyfile.
# - Otherwise, or when the watchdog cannot be reached, start from Caddyfile.closed, which renders
#   no tailnet route. ACME, redirects and the admin site keep working; tailnet routes fail closed.
# - A Caddyfile without any tailnet route (the bootstrap config, a host without routes) needs no
#   lease and starts as it is.
set -eu

dir="${ARK_EDGE_CONFIG_DIR:-/etc/caddy/ark}"
full="$dir/Caddyfile"
closed="$dir/Caddyfile.closed"
watchdog="${ARK_EDGE_WATCHDOG_URL:-http://edge-watchdog:2021}"

decision="$(wget -q -T 3 -O - "$watchdog/v1/launch" 2>/dev/null || true)"
if [ "$decision" = "open" ]; then
  config="$full"
  reason="the watchdog confirmed a valid lease"
elif ! grep -q '^# ark-tailnet-route ' "$full" 2>/dev/null; then
  config="$full"
  reason="the config has no tailnet route"
elif [ -f "$closed" ]; then
  config="$closed"
  reason="no valid lease (watchdog: ${decision:-unreachable}); tailnet routes are not served"
else
  echo "ark launch guard: no valid lease and no closed config; refusing to start" >&2
  exit 1
fi
echo "ark launch guard: starting from $config: $reason" >&2
exec caddy run --config "$config" --adapter caddyfile
