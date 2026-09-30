#!/bin/bash
# CronJob entrypoint: comprehensively patch every image declared in bulk.yaml
# (updating all OS packages across all platforms), skipping images whose
# already-patched target has no fixable OS-package CVEs left.
#
# Why not copa's own bulk/report-driven mode: passing `-r <dir>` to `copa
# patch --config` makes copa match reports to platforms by the report's
# Metadata.Config.Arch — which Harbor's report (and thus harbor-report) has no
# per-platform notion of — so for a multi-arch image copa finds "No scan
# report for platform" for every platform and patches nothing. Instead we do
# our own skip-detection here and run a comprehensive per-image `copa patch`
# (no `-r`), which updates all OS packages on every platform and doesn't need a
# report at all. Harbor's scan (via harbor-report) is used only to decide
# whether patching is still needed.
#
# Known limitation: only OS-package CVEs are considered/fixable (see
# harbor-report) — language/app-package CVEs are reported by Harbor but can't
# be fixed by the OS package manager and are ignored here. An image whose
# remaining OS CVEs have no fix available in its distro release will be
# re-patched every run (same tag overwritten, no accumulation); fix that by
# rebuilding from an updated base image.
set -euo pipefail

BULK_CONFIG="${BULK_CONFIG:-/etc/copa/bulk.yaml}"
REPORTS_DIR="${REPORTS_DIR:-/data/reports}"
TIMEOUT="${PATCH_TIMEOUT:-20m}"

mkdir -p "$REPORTS_DIR"

echo "sweep: planning from ${BULK_CONFIG}"
# sweep-helper emits one tab-separated "<source-ref>\t<target-ref>" line per
# image:tag. Read the whole plan first so the patch loop isn't tied to the
# helper's pipe lifetime.
PLAN="$(sweep-helper -config "$BULK_CONFIG")"

if [ -z "$PLAN" ]; then
  echo "sweep: nothing to do (no list-strategy images with a target registry)"
  exit 0
fi

while IFS=$'\t' read -r SOURCE TARGET; do
  [ -n "${SOURCE:-}" ] && [ -n "${TARGET:-}" ] || continue

  report="${REPORTS_DIR}/$(echo "$TARGET" | tr -c 'A-Za-z0-9' '_').json"

  # Skip-detection: if the already-patched target exists and Harbor reports it
  # has no fixable OS-package CVEs left, there's nothing to do. harbor-report
  # exits non-zero when the target doesn't exist yet (first run) or its scan
  # can't be obtained — in which case we fall through and patch.
  if harbor-report -ref "$TARGET" -out "$report"; then
    fixable="$(grep -c '"vulnerabilityID"' "$report" 2>/dev/null || true)"
    fixable="${fixable:-0}"
    if [ "$fixable" -eq 0 ]; then
      echo "sweep: skip ${SOURCE} — patched target ${TARGET} has 0 fixable OS CVEs"
      continue
    fi
    echo "sweep: ${TARGET} still has ${fixable} fixable OS CVE(s); (re-)patching ${SOURCE}"
  else
    echo "sweep: no usable report for ${TARGET} (likely not patched yet); patching ${SOURCE}"
  fi

  # Comprehensive patch: updates every OS package on every platform and pushes
  # to TARGET (a full reference, so it may be a different repo), overwriting
  # the tag. No `-r` — so no report-driven per-platform matching and no
  # "-patched-N" version churn.
  echo "sweep: patching ${SOURCE} -> ${TARGET}"
  if ! copa patch -i "$SOURCE" -t "$TARGET" --push --scanner native --timeout "$TIMEOUT"; then
    echo "sweep: WARNING: patch failed for ${SOURCE}; continuing with the rest of the fleet" >&2
    continue
  fi
done <<< "$PLAN"

echo "sweep: done"
