#!/bin/bash
# Manually triggers the CronJob once and verifies, via Trivy run from inside
# the cluster, that the patched image in Harbor has fewer CVEs than the
# source. Assumes 01-05 have already run successfully.
set -euo pipefail
cd "$(dirname "$0")"

RUN_NAME="manual-run-$(date +%s 2>/dev/null || echo verify)"
kubectl delete job -l job-name="$RUN_NAME" --ignore-not-found=true 2>&1 || true
kubectl create job --from=cronjob/copa-harbor-copa-harbor-patcher "$RUN_NAME"

echo "==> Waiting for the Job to complete"
POD="$(kubectl get pods -l job-name="$RUN_NAME" -o jsonpath='{.items[0].metadata.name}' --field-selector=status.phase!=Failed 2>/dev/null || true)"
for _ in $(seq 1 30); do
  POD="$(kubectl get pods -l job-name="$RUN_NAME" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [ -n "$POD" ] && break
  sleep 2
done
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded "pod/${POD}" --timeout=180s
kubectl logs "$POD" -c copa

echo "==> Scanning source vs. patched image from inside the cluster"
kubectl delete pod trivycheck --ignore-not-found=true --force --grace-period=0 >/dev/null 2>&1 || true
kubectl run trivycheck --restart=Never --image=aquasec/trivy:0.73.0 --command -- sh -c "sleep 3600" >/dev/null
kubectl wait --for=condition=Ready pod/trivycheck --timeout=60s >/dev/null

# Adjust these two refs to match your bulk.yaml's source/target.
SOURCE_REF="${SOURCE_REF:?set SOURCE_REF to the source image, e.g. harbor.test:30003/library/python-seed:3.7-alpine}"
PATCHED_REF="${PATCHED_REF:?set PATCHED_REF to the patched image, e.g. harbor.test:30003/library/python-seed:3.7-alpine-patched}"

kubectl exec trivycheck -- trivy image --skip-version-check --scanners vuln -f json -o /tmp/before.json --insecure "$SOURCE_REF"
kubectl exec trivycheck -- trivy image --skip-version-check --scanners vuln -f json -o /tmp/after.json --insecure "$PATCHED_REF"
kubectl cp trivycheck:/tmp/before.json ./before.json >/dev/null
kubectl cp trivycheck:/tmp/after.json ./after.json >/dev/null
kubectl delete pod trivycheck --force --grace-period=0 >/dev/null 2>&1 || true

python3 - <<'PYEOF'
import json
for label, f in [("BEFORE", "before.json"), ("AFTER", "after.json")]:
    d = json.load(open(f))
    total = 0
    sev = {}
    for res in d.get("Results", []):
        vulns = res.get("Vulnerabilities", []) or []
        total += len(vulns)
        for v in vulns:
            sev[v["Severity"]] = sev.get(v["Severity"], 0) + 1
    print(label, "Total:", total, sev)
PYEOF
