#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

# shellcheck source=/dev/null
source ./robot-credentials.env

# Wire Harbor's self-signed CA into the workload pods. buildkit (copa's
# pull/push), copa itself, and harbor-report's detectOS all use the system
# trust store for registry TLS — HARBOR_INSECURE_SKIP_VERIFY only covers
# harbor-report's Harbor *API* HTTP client, not any of those — so without this
# the sweep fails to pull/push against the self-signed test Harbor. 03 wrote
# harbor-ca.crt; mount it into /etc/ssl/certs on both containers via the
# chart's extraVolumes/extraVolumeMounts (its documented CA-trust hook).
kubectl create configmap harbor-ca --from-file=harbor-ca.crt=./harbor-ca.crt \
  --dry-run=client -o yaml | kubectl apply -f -

BULK_CONFIG_FILE="$(mktemp)"
cat > "$BULK_CONFIG_FILE" <<'EOF'
apiVersion: copa.sh/v1alpha1
kind: PatchConfig
target:
  registry: "harbor.test:30003/library"
images:
  - name: cyberchef
    # A real upstream image replicated into Harbor by 04b (single-platform,
    # same registry for source and target, so copa's cross-registry
    # multi-arch preserve limitation doesn't apply).
    image: harbor.test:30003/library/cyberchef
    tags:
      strategy: list
      list: ["latest"]
EOF

VALUES_FILE="$(mktemp)"
cat > "$VALUES_FILE" <<'EOF'
extraVolumes:
  - name: harbor-ca
    configMap:
      name: harbor-ca
extraVolumeMounts:
  - name: harbor-ca
    mountPath: /etc/ssl/certs/harbor-ca.pem
    subPath: harbor-ca.crt
    readOnly: true
EOF

helm upgrade --install copa-harbor ../../chart \
  --namespace default \
  --set mode=cronjob \
  --set image.repository=copa-harbor-patcher \
  --set image.tag=dev \
  --set image.pullPolicy=Never \
  --set harborserver.registry=harbor.test:30003 \
  --set harborserver.insecureSkipVerify=true \
  --set harborserver.credentials.username="${HARBOR_ROBOT_USERNAME}" \
  --set harborserver.credentials.password="${HARBOR_ROBOT_PASSWORD}" \
  --set-file cronjob.bulkConfig="$BULK_CONFIG_FILE" \
  --set cronjob.reportsVolume.size=1Gi \
  -f "$VALUES_FILE"

# buildkit needs a PodSecurity privileged exemption on its namespace.
kubectl label ns default pod-security.kubernetes.io/enforce=privileged --overwrite

kubectl get all -l app.kubernetes.io/instance=copa-harbor
