#!/bin/sh
# Invoked under flock by host:setup and by its transient systemd recovery timer.
set -eu
directory=$1
mode=$2
ufw_directory=$3
shift 3
if [ "$mode" = timed ] && [ -e "$directory/verified" ]; then exit 0; fi
if [ -e "$directory/restored" ]; then exit 0; fi

failed=0
if [ -e "$directory/ufw-changed" ]; then
  for file in user.rules user6.rules; do
    if [ -e "$directory/$file" ]; then
      cp -p -- "$directory/$file" "$ufw_directory/$file" || failed=1
    fi
  done
  ufw reload || failed=1
fi
for record do
  unit=${record%%:*}
  state=${record#*:}
  active=${state#*:}
  state=${state%%:*}
  case "$state" in
    enabled) systemctl enable "$unit" || failed=1 ;;
    enabled-runtime) systemctl enable --runtime "$unit" || failed=1 ;;
  esac
  if [ "$active" = true ]; then
    systemctl start "$unit" && systemctl is-active --quiet "$unit" || failed=1
  fi
  case "$state" in
    enabled|enabled-runtime)
      [ "$(systemctl is-enabled "$unit")" = "$state" ] || failed=1 ;;
  esac
done
[ "$failed" = 0 ]
touch "$directory/restored"
