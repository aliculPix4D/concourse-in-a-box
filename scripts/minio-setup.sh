#! /bin/sh

set -e

# We expect the caller to set these environment variables:
: "${MINIO_ADDR?Need to set this environment variable}"
: "${MINIO_ROOT_USER?Need to set this environment variable}"
: "${MINIO_ROOT_PASSWORD?Need to set this environment variable}"

# FIXME This should be replaced by a more robust healthcheck, see
# https://docs.docker.com/compose/compose-file/compose-file-v3/#healthcheck
# https://docs.docker.com/engine/reference/builder/#healthcheck
echo
echo "***** Sleeping a few seconds to allow Minio to startup"
sleep 5

echo
echo "***** Logging in to Minio"
mc alias set concourse-minio "$MINIO_ADDR" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"

echo
echo "***** Creating the bucket: /concourse"
mc mb --ignore-existing concourse-minio/concourse
