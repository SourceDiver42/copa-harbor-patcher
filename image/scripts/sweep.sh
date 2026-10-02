#!/bin/bash
# CronJob entrypoint: comprehensively patch every image declared in bulk.yaml
# (updating all OS packages across the requested platforms), re-patching only
# when an image's set of fixable OS-package CVEs has actually changed since we
# last patched it.
#
# Why not copa's own bulk/report-driven mode: passing `-r <dir>` to `copa
# patch --config` makes copa match reports to platforms by the report's
# Metadata.Config.Arch — which Harbor's report (and thus harbor-report) has no
# per-platform notion of — so for a multi-arch image copa finds "No scan
# report for platform" for every platform and patches nothing. Instead we do
# our own skip-detection here and run a comprehensive per-image `copa patch`
# (no `-r`), which updates all OS packages without needing a report.
#
# Skip-detection (the ".cves" memo): each run we ask Harbor for the current set
# of fixable OS-package CVE IDs on the already-patched target and compare it to
# the set we recorded when we last patched it:
#   - empty set              -> skip (clean)
#   - identical to last patch -> skip (nothing new; any residual has no
#                                installable fix in this release)
#   - differs (new/changed)  -> re-patch, then record the new set
# This picks up newly-disclosed CVEs (and drops once a residual stabilizes),
# instead of re-patching forever. NOTE on Harbor's "Fixable": it means a fix
# exists in the vuln DB, not that it's installable in this image's distro
# release — residuals with no in-release fix need a base-image rebuild.
#
# Only the small CVE-ID set is persisted (per target, in REPORTS_DIR), not the
# full report JSON; and state for targets no longer in bulk.yaml is rotated out
# each run, so the reports volume stays small and bounded.
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

keyfor() { echo "$1" | tr -c 'A-Za-z0-9' '_'; }

# Extract the sorted, unique set of fixable OS CVE IDs from a harbor-report
# JSON file (one "vulnerabilityID" per osupdate entry). The trailing `|| true`
# is essential: with `set -o pipefail`, a clean image (grep matches nothing)
# would otherwise make this exit non-zero and kill the whole sweep.
cve_set() {
  grep '"vulnerabilityID"' "$1" 2>/dev/null \
    | sed -E 's/.*"vulnerabilityID"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/' \
    | sort -u || true
}

echo "sweep: planning from ${BULK_CONFIG}"
# When exactly one platform is requested, sweep-helper pins each source to that
# platform's digest so copa produces a single-arch result (a multi-arch output
# would still carry the other, unpatched arches and keep Harbor's count high).
PLAN="$(sweep-helper -config "$BULK_CONFIG" -platforms "${PATCH_PLATFORMS:-}")"

if [ -z "$PLAN" ]; then
  echo "sweep: nothing to do (no list-strategy images with a target registry)"
  exit 0
fi

# Rotation: drop state files for targets no longer in the plan (images removed
# from bulk.yaml, renamed, etc.) so the reports volume doesn't accumulate
# orphans. Also clears any legacy per-target report JSONs / .fixable memos from
# earlier versions.
VALID_KEYS=" "
while IFS=$'\t' read -r _src tgt; do
  [ -n "${tgt:-}" ] || continue
  VALID_KEYS="${VALID_KEYS}$(keyfor "$tgt") "
done <<< "$PLAN"
shopt -s nullglob
for f in "$REPORTS_DIR"/*; do
  base="$(basename "$f")"
  k="${base%.*}"
  # Keep only the current ".cves" state for targets still in the plan; drop
  # everything else — stale targets, plus legacy per-target report JSONs and
  # .fixable memos from earlier versions.
  keep=0
  case "$base" in
    *.cves)
      case "$VALID_KEYS" in *" $k "*) keep=1 ;; esac
      ;;
  esac
  if [ "$keep" -ne 1 ]; then
    echo "sweep: rotating out stale state ${base}"
    rm -f "$f"
  fi
done
shopt -u nullglob

while IFS=$'\t' read -r SOURCE TARGET; do
  [ -n "${SOURCE:-}" ] && [ -n "${TARGET:-}" ] || continue

  key="$(keyfor "$TARGET")"
  baseline="${REPORTS_DIR}/${key}.cves"
  tmpreport="$(mktemp)"

  cur_cves=""
  acted=1   # 1 = we don't have a current CVE set to record (e.g. first patch)
  # Skip-detection: fetch the already-patched target's fixable OS CVE set.
  # harbor-report exits non-zero when the target doesn't exist yet (first run)
  # or its scan can't be obtained — then we fall through and patch.
  if harbor-report -ref "$TARGET" -out "$tmpreport"; then
    cur_cves="$(cve_set "$tmpreport")"
    cur_count="$(printf '%s' "$cur_cves" | grep -c . || true)"; cur_count="${cur_count:-0}"
    acted=0

    if [ "$cur_count" -eq 0 ]; then
      echo "sweep: skip ${SOURCE} — patched target ${TARGET} has 0 fixable OS CVEs"
      rm -f "$tmpreport" "$baseline"
      continue
    fi
    if [ -f "$baseline" ] && [ "$cur_cves" = "$(cat "$baseline")" ]; then
      echo "sweep: skip ${SOURCE} — ${TARGET} still has ${cur_count} fixable OS CVE(s), an identical set to its last patch (nothing new; any residual has no installable fix). 'rm ${baseline}' to force."
      rm -f "$tmpreport"
      continue
    fi
    if [ -f "$baseline" ]; then
      new_count="$(comm -23 <(printf '%s\n' "$cur_cves") <(sort -u "$baseline") | grep -c . || true)"
      echo "sweep: ${TARGET} fixable OS CVE set changed (${cur_count} total, ${new_count:-0} new vs last patch); re-patching ${SOURCE}"
    else
      echo "sweep: ${TARGET} has ${cur_count} fixable OS CVE(s), no prior baseline; patching ${SOURCE}"
    fi
  else
    echo "sweep: no usable report for ${TARGET} (likely not patched yet); patching ${SOURCE}"
  fi
  rm -f "$tmpreport"

  # A digest-pinned source (contains '@') is already single-arch — copa emits a
  # single-arch result, so don't pass --platform. Otherwise apply the scope (if
  # any) so copa patches the requested platforms and preserves the rest.
  platform_args=()
  case "$SOURCE" in
    *@*) : ;;
    *)   platform_args=(${PLATFORM_ARGS[@]+"${PLATFORM_ARGS[@]}"}) ;;
  esac

  echo "sweep: patching ${SOURCE} -> ${TARGET}"
  if ! copa patch -i "$SOURCE" -t "$TARGET" --push --scanner native \
        --timeout "$TIMEOUT" ${platform_args[@]+"${platform_args[@]}"}; then
    echo "sweep: WARNING: patch failed for ${SOURCE}; continuing with the rest of the fleet" >&2
    rm -f "$baseline"
    continue
  fi

  # Record the fixable CVE set we just acted on as the new baseline, so an
  # identical set next run is skipped and only a new/changed set re-triggers.
  if [ "$acted" -eq 0 ]; then
    printf '%s\n' "$cur_cves" > "$baseline"
  else
    rm -f "$baseline"
  fi
done <<< "$PLAN"

echo "sweep: done"
