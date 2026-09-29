#!/bin/bash
# Replicates a real upstream image (ghcr.io/gchq/cyberchef) into the test
# Harbor's `library` project, so the sweep has something real to patch.
#
# Runs skopeo *inside the cluster* (as a Job) rather than from the host, so it
# reuses the CoreDNS patch from 03 to resolve harbor.test and doesn't need the
# host's Docker configured to trust Harbor's self-signed cert. Copies a single
# platform (linux/arm64 — the kind node arch on Apple Silicon; change to amd64
# elsewhere) so copa patches a single-platform image and avoids copa's
# cross-registry multi-arch preserve limitation (see README). Source and
# target are both Harbor here, so that limitation doesn't apply anyway.
set -euo pipefail
cd "$(dirname "$0")"

# shellcheck source=/dev/null
source ./robot-credentials.env

SOURCE="${SOURCE:-ghcr.io/gchq/cyberchef:latest}"
DEST="${DEST:-harbor.test:30003/library/cyberchef:latest}"
ARCH="${ARCH:-arm64}"

kubectl delete job replicate-cyberchef --ignore-not-found >/dev/null 2>&1

cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: replicate-cyberchef
spec:
  backoffLimit: 1
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: skopeo
          image: quay.io/skopeo/stable:latest
          command: ["skopeo","copy",
            "--dest-creds","${HARBOR_ROBOT_USERNAME}:${HARBOR_ROBOT_PASSWORD}",
            "--dest-tls-verify=false",
            "--override-arch","${ARCH}","--override-os","linux",
            "docker://${SOURCE}",
            "docker://${DEST}"]
EOF

echo "==> Waiting for replication to complete"
kubectl wait --for=condition=complete job/replicate-cyberchef --timeout=300s
POD="$(kubectl get pods -l job-name=replicate-cyberchef -o jsonpath='{.items[0].metadata.name}')"
kubectl logs "$POD" | tail -5
echo "==> Replicated ${SOURCE} -> ${DEST} (${ARCH})"
