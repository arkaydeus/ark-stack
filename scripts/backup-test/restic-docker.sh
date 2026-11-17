#!/bin/sh
# Test-only ARK_RESTIC_BIN for scripts/test-backups.ts (FD-21): runs the pinned restic image with the
# exact environment the exporter gives its restic subprocess (credentials and repository password
# only). ARK_TEST_RESTIC_DOCKER_ARGS adds the network (MinIO's namespace) and the read-only staging
# volume mounts at the backup worker's paths.
set -eu
# shellcheck disable=SC2086
exec docker run --rm -i $ARK_TEST_RESTIC_DOCKER_ARGS ${ARK_RESTIC_CWD:+--workdir "$ARK_RESTIC_CWD"} \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION -e RESTIC_PASSWORD \
  restic/restic:0.19.1@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510 "$@"
