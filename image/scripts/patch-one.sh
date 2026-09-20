#!/bin/bash
# Fetches Harbor's own (already-computed) vulnerability report for a single
# image and patches+pushes it with copa. Used both by sweep.sh (per
# pattern/latest-strategy image, where sweep-helper can't pre-resolve a
# target ref) and by webhook-server (per Harbor event).
# Usage: patch-one.sh <repo> <tag>
set -euo pipefail

REPO="${1:?usage: patch-one.sh <repo> <tag>}"
TAG="${2:?usage: patch-one.sh <repo> <tag>}"
REF="${REPO}:${TAG}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

REPORT="${WORKDIR}/report.json"
echo "patch-one: fetching Harbor's vulnerability report for ${REF}"
harbor-report -ref "$REF" -out "$REPORT"

PATCHED_TAG="${TAG}-patched"
echo "patch-one: patching ${REF} -> ${REPO}:${PATCHED_TAG}"
copa patch \
  -i "$REF" \
  -r "$REPORT" \
  --scanner native \
  -t "$PATCHED_TAG" \
  --timeout "${PATCH_TIMEOUT:-15m}" \
  --push

echo "patch-one: done, pushed ${REPO}:${PATCHED_TAG}"
