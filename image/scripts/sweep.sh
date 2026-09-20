#!/bin/bash
# CronJob entrypoint: patch the whole fleet declared in bulk.yaml, then fetch
# Harbor's own (already-computed) vulnerability report for whatever got
# pushed, so the next scheduled run's skip-detection has fresh reports to
# check against. This does NOT run a separate scanner — it reuses Harbor's
# built-in Trivy scan results via harbor-report.
#
# Known limitation: skip-detection (and this script's auto-rescan) only
# covers images using `tags.strategy: list` in bulk.yaml. Images discovered
# via `pattern`/`latest` strategies are patched every run (sweep-helper logs
# a warning per such image to stderr) since resolving their live source tags
# ahead of time would require duplicating copa's own registry-discovery
# logic rather than just its target-naming rules.
set -euo pipefail

BULK_CONFIG="${BULK_CONFIG:-/etc/copa/bulk.yaml}"
REPORTS_DIR="${REPORTS_DIR:-/data/reports}"
TIMEOUT="${PATCH_TIMEOUT:-20m}"

mkdir -p "$REPORTS_DIR"

echo "sweep: patching fleet from ${BULK_CONFIG}"
# Only pass -r once the reports directory actually has something in it.
# Passing -r to bulk mode switches every non-skipped job from a
# comprehensive update to report-driven patching (confirmed live: with an
# empty reports dir, copa "preserved" every platform as having "no scan
# report" instead of doing a comprehensive update) — so on a genuinely
# first run (nothing to skip-detect against yet), we want -r omitted
# entirely to get copa's real first-time comprehensive-update behavior.
REPORT_ARGS=()
if [ -n "$(find "$REPORTS_DIR" -maxdepth 1 -name '*.json' -print -quit 2>/dev/null)" ]; then
  REPORT_ARGS=(-r "$REPORTS_DIR")
fi
copa patch --config "$BULK_CONFIG" --push "${REPORT_ARGS[@]}" --scanner native --timeout "$TIMEOUT"

echo "sweep: resolving patched targets to fetch fresh Harbor reports for"
sweep-helper -config "$BULK_CONFIG" | while IFS= read -r ref; do
  out_name="$(echo "$ref" | tr -c 'A-Za-z0-9' '_')"
  echo "sweep: fetching Harbor report for ${ref}"
  if ! harbor-report -ref "$ref" -out "${REPORTS_DIR}/${out_name}.json"; then
    echo "sweep: WARNING: fetching Harbor report for ${ref} failed; next run will fail-open and re-patch it" >&2
  fi
done

echo "sweep: done"
