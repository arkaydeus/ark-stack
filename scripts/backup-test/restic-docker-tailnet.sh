#!/bin/sh
# Test-only ARK_RESTIC_BIN for scripts/test-backups-tailnet.ts (FD-30). Runs the pinned restic image
# with the exact environment the exporter gives its restic subprocess, on the network a deployed
# backup worker would use for that target:
#   - home (REST) targets: the internal backup-tailnet network, which has no route to the tailnet; the
#     only way out is backup-ts's SOCKS5 proxy, and only if HTTP_PROXY/HTTPS_PROXY says so;
#   - S3 targets: MinIO's network namespace, which never sees backup-ts.
# It logs the proxy-related environment restic received (ARK_TEST_RESTIC_ENV_LOG), mounts the test's
# work volume (ARK_TEST_RESTIC_VOLUME, a copy of ARK_TEST_RESTIC_WORK; see work-volume.ts) read-only
# at /work and rewrites paths under the work directory to it, and on SIGTERM kills the container: a
# killed `docker run` client alone would leave restic running, and the watchdog must stop the transfer.
set -eu
image="restic/restic:0.19.1@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510"
name="${ARK_TEST_RESTIC_NAME_PREFIX:-ark-fd30-restic}-$$-$(date +%s)"
if [ -n "${RESTIC_REST_USERNAME:-}" ]; then
  kind=rest
  network="$ARK_TEST_RESTIC_REST_NETWORK"
else
  kind=s3
  network="$ARK_TEST_RESTIC_S3_NETWORK"
fi
if [ -n "${ARK_TEST_RESTIC_ENV_LOG:-}" ]; then
  {
    printf 'kind=%s container=%s' "$kind" "$name"
    for variable in HTTP_PROXY http_proxy HTTPS_PROXY https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy; do
      eval "value=\${$variable-<unset>}"
      printf ' %s=%s' "$variable" "$value"
    done
    printf ' args=%s\n' "$*"
  } >>"$ARK_TEST_RESTIC_ENV_LOG"
fi
work="$ARK_TEST_RESTIC_WORK"
for arg do
  shift
  case "$arg" in "$work"*) arg="/work${arg#"$work"}" ;; esac
  set -- "$@" "$arg"
done
cwd="${ARK_RESTIC_CWD:-}"
case "$cwd" in "$work"*) cwd="/work${cwd#"$work"}" ;; esac
limit=""
if [ -n "${ARK_TEST_RESTIC_LIMIT_UPLOAD:-}" ]; then limit="--limit-upload $ARK_TEST_RESTIC_LIMIT_UPLOAD"; fi
# shellcheck disable=SC2086
docker run --rm --name "$name" --label ark.test=fd30-backups --network "$network" \
  --volume "${ARK_TEST_RESTIC_VOLUME:-$work}:/work:ro" \
  ${cwd:+--workdir "$cwd"} \
  -e RESTIC_PASSWORD -e RESTIC_REST_USERNAME -e RESTIC_REST_PASSWORD -e HTTP_PROXY -e HTTPS_PROXY \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION \
  "$image" "$@" $limit &
child=$!
trap 'docker kill "$name" >/dev/null 2>&1 || true; wait "$child" || true; exit 143' TERM INT
wait "$child"
