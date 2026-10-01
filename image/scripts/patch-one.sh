#!/bin/bash
# Comprehensively patches a single image (all OS packages, all platforms) and
# pushes it as <tag>-patched. Used by webhook-server, one invocation per Harbor
# event.
#
# Like sweep.sh, this does NOT use copa's report-driven mode (`-r`): a single
# arch-less Harbor report can't satisfy copa's per-platform report matching for
# a multi-arch image (it would patch nothing with "No scan report for
# platform"). A comprehensive patch needs no report and covers every platform.
# Usage: patch-one.sh <repo> <tag>
set -euo pipefail

REPO="${1:?usage: patch-one.sh <repo> <tag>}"
TAG="${2:?usage: patch-one.sh <repo> <tag>}"
REF="${REPO}:${TAG}"
PATCHED_TAG="${TAG}-patched"

# Restrict to specific platforms (copa --platform, comma-separated); empty =
# all platforms present. Non-native platforms need QEMU emulation.
PLATFORM_ARGS=()
if [ -n "${PATCH_PLATFORMS:-}" ]; then
  PLATFORM_ARGS=(--platform "$PATCH_PLATFORMS")
fi

echo "patch-one: comprehensively patching ${REF} -> ${REPO}:${PATCHED_TAG}"
copa patch \
  -i "$REF" \
  -t "$PATCHED_TAG" \
  --scanner native \
  --timeout "${PATCH_TIMEOUT:-15m}" \
  --push ${PLATFORM_ARGS[@]+"${PLATFORM_ARGS[@]}"}

echo "patch-one: done, pushed ${REPO}:${PATCHED_TAG}"
