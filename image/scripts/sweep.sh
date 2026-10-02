#!/bin/bash
# CronJob entrypoint: comprehensively patch every image declared in bulk.yaml
# (updating all OS packages across the requested platforms), skipping images
# whose already-patched target has no fixable OS-package CVEs left — or whose
# remaining OS CVEs have no installable fix (see the count memo below).
#
# Why not copa's own bulk/report-driven mode: passing `-r <dir>` to `copa
# patch --config` makes copa match reports to platforms by the report's
# Metadata.Config.Arch — which Harbor's report (and thus harbor-report) has no
# per-platform notion of — so for a multi-arch image copa finds "No scan
# report for platform" for every platform and patches nothing. Instead we do
# our own skip-detection here and run a comprehensive per-image `copa patch`
# (no `-r`), which updates all OS packages without needing a report.
#
# IMPORTANT caveat about Harbor's "Fixable": it means a fixed version exists in
# the vulnerability database, NOT that the fix is installable in this image's
# distro release. A comprehensive patch installs the latest packages available
# in the release's repos; CVEs whose fix isn't in that release stay "Fixable"
# in Harbor forever. The count memo below stops us re-patching such images on
# every run; the real fix is to rebuild from an updated base image.
set -euo pipefail

BULK_CONFIG="${BULK_CONFIG:-/etc/copa/bulk.yaml}"
REPORTS_DIR="${REPORTS_DIR:-/data/reports}"
TIMEOUT="${PATCH_TIMEOUT:-20m}"

mkdir -p "$REPORTS_DIR"

# Restrict patching to specific platforms (copa --platform, comma-separated);
# empty = all platforms present in the image. Non-native platforms need QEMU
# emulation (buildkit.emulation) or they fail to build.
PLATFORM_ARGS=()
if [ -n "${PATCH_PLATFORMS:-}" ]; then
  PLATFORM_ARGS=(--platform "$PATCH_PLATFORMS")
fi

echo "sweep: planning from ${BULK_CONFIG}"
# When exactly one platform is requested, sweep-helper pins each source to that
# platform's digest so copa produces a single-arch result (a multi-arch output
# would still carry the other, unpatched arches and keep Harbor's count high).
PLAN="$(sweep-helper -config "$BULK_CONFIG" -platforms "${PATCH_PLATFORMS:-}")"

if [ -z "$PLAN" ]; then
  echo "sweep: nothing to do (no list-strategy images with a target registry)"
  exit 0
fi

while IFS=$'\t' read -r SOURCE TARGET; do
  [ -n "${SOURCE:-}" ] && [ -n "${TARGET:-}" ] || continue

  key="$(echo "$TARGET" | tr -c 'A-Za-z0-9' '_')"
  report="${REPORTS_DIR}/${key}.json"
  state="${REPORTS_DIR}/${key}.fixable"

  fixable=""
  # Skip-detection: ask Harbor how many fixable OS-package CVEs the
  # already-patched target still has. harbor-report exits non-zero when the
  # target doesn't exist yet (first run) or its scan can't be obtained — then
  # we fall through and patch.
  if harbor-report -ref "$TARGET" -out "$report"; then
    fixable="$(grep -c '"vulnerabilityID"' "$report" 2>/dev/null || true)"
    fixable="${fixable:-0}"
    if [ "$fixable" -eq 0 ]; then
      echo "sweep: skip ${SOURCE} — patched target ${TARGET} has 0 fixable OS CVEs"
      continue
    fi
    # Count memo: if the fixable count is exactly what it was when we last
    # patched this target, the previous patch already applied everything
    # available and nothing new has appeared — re-patching would just reproduce
    # the same image. Skip until the count changes (a new fix/CVE) or the
    # source changes.
    if [ -f "$state" ] && [ "$(cat "$state" 2>/dev/null)" = "$fixable" ]; then
      echo "sweep: skip ${SOURCE} — ${TARGET} still has ${fixable} fixable OS CVE(s), unchanged since its last patch (no installable fix in this release). Rebuild from a newer base, or 'rm ${state}' to force a re-patch."
      continue
    fi
    echo "sweep: ${TARGET} has ${fixable} fixable OS CVE(s) (new or changed); (re-)patching ${SOURCE}"
  else
    echo "sweep: no usable report for ${TARGET} (likely not patched yet); patching ${SOURCE}"
  fi

  # Comprehensive patch: updates every OS package on the requested platforms
  # and pushes to TARGET (a full reference, so it may be a different repo),
  # overwriting the tag. No `-r` — no report-driven per-platform matching and
  # no "-patched-N" version churn.
  # A digest-pinned source (contains '@') is already single-arch — copa emits a
  # single-arch result, so don't pass --platform. Otherwise apply the scope (if
  # any) so copa patches the requested platforms and preserves the rest.
  platform_args=()
  case "$SOURCE" in
    *@*) : ;;                                   # single-arch digest: no --platform
    *)   platform_args=(${PLATFORM_ARGS[@]+"${PLATFORM_ARGS[@]}"}) ;;
  esac

  echo "sweep: patching ${SOURCE} -> ${TARGET}"
  if ! copa patch -i "$SOURCE" -t "$TARGET" --push --scanner native \
        --timeout "$TIMEOUT" ${platform_args[@]+"${platform_args[@]}"}; then
    echo "sweep: WARNING: patch failed for ${SOURCE}; continuing with the rest of the fleet" >&2
    rm -f "$state"
    continue
  fi

  # Record the fixable count we just acted on (if we had one), so a residual
  # that no available OS fix can clear won't re-patch every run.
  if [ -n "$fixable" ]; then
    echo "$fixable" > "$state"
  else
    rm -f "$state"
  fi
done <<< "$PLAN"

echo "sweep: done"
