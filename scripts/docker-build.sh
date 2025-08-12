#!/bin/sh
set -eu

# Compute image and tags
IMAGE="us-central1-docker.pkg.dev/${PROJECT_ID}/cloud-run-source-deploy/isectech-app"
TAGS="-t ${IMAGE}"

if [ -n "${COMMIT_SHA:-}" ]; then
  TAGS="${TAGS} -t ${IMAGE}:${COMMIT_SHA}"
  COMMIT_VALUE="${COMMIT_SHA}"
else
  echo "COMMIT_SHA not set; building with 'latest' tag only"
  COMMIT_VALUE="dev"
fi

BUILD_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

echo "Building image: ${IMAGE}"
echo "Tags: ${TAGS}"

docker build --no-cache ${TAGS} \
  -f Dockerfile.frontend.production \
  --build-arg BUILD_DATE="${BUILD_DATE}" \
  --build-arg BUILD_VERSION="${COMMIT_VALUE}" \
  --build-arg BUILD_COMMIT="${COMMIT_VALUE}" \
  .


