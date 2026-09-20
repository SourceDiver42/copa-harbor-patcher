#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

# shellcheck source=/dev/null
source ./robot-credentials.env

BULK_CONFIG_FILE="$(mktemp)"
cat > "$BULK_CONFIG_FILE" <<'EOF'
apiVersion: copa.sh/v1alpha1
kind: PatchConfig
target:
  registry: "harbor.test:30003/library"
images:
  - name: python-test
    # Single-platform seed image (pushed ahead of time into Harbor from a
    # locally cached `docker save`, to work around this sandbox's Docker Hub
    # anonymous rate limit) — sidesteps a copa limitation confirmed live in
    # this environment where preserving non-target platforms of a
    # cross-registry multi-arch source (pull from docker.io, push to a
    # *different* registry) fails with "blob unknown to registry": the
    # preserved platforms' blobs need to be copied, not just referenced, and
    # that copy isn't happening for the cross-registry case. Not a chart
    # bug — a real single-platform image (or same-registry source) doesn't
    # hit this at all.
    image: harbor.test:30003/library/python-seed
    tags:
      strategy: list
      list: ["3.7-alpine"]
EOF

helm upgrade --install copa-harbor ../../chart \
  --namespace default \
  --set mode=cronjob \
  --set image.repository=copa-harbor-patcher \
  --set image.tag=dev \
  --set image.pullPolicy=Never \
  --set harbor.registry=harbor.test:30003 \
  --set harbor.credentials.username="${HARBOR_ROBOT_USERNAME}" \
  --set harbor.credentials.password="${HARBOR_ROBOT_PASSWORD}" \
  --set-file cronjob.bulkConfig="$BULK_CONFIG_FILE" \
  --set cronjob.reportsVolume.size=1Gi

kubectl get all -l app.kubernetes.io/instance=copa-harbor
