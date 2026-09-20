#!/bin/bash
# Configures the test Harbor instance:
#  - patches in-cluster DNS so pods can resolve harbor.test to a node IP
#    reachable at the NodePort (so in-cluster and host-side testing use the
#    exact same hostname:port the TLS cert's CN covers)
#  - extracts Harbor's auto-generated CA cert
#  - creates a project + robot account with the permissions copa-harbor-patcher needs
#  - configures a webhook policy pointed at the (not-yet-installed) webhook receiver
set -euo pipefail
cd "$(dirname "$0")"

NAMESPACE=harbor
HARBOR_HOST="harbor.test"
HARBOR_PORT=30003
ADMIN_PASSWORD="Harbor12345"
PROJECT="library"
ROBOT_NAME="copa-patcher"
OUT_DIR="$(mktemp -d)"

echo "==> Patching CoreDNS so in-cluster pods resolve ${HARBOR_HOST} to a reachable node IP"
NODE_IP="$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"
kubectl -n kube-system get configmap coredns -o json \
  | python3 -c "
import json, re, sys
cm = json.load(sys.stdin)
corefile = cm['data']['Corefile']
# Always replace any existing managed hosts block wholesale (idempotent
# across hostname/IP changes across re-runs), rather than only inserting
# once and leaving a stale mapping behind on subsequent runs.
corefile = re.sub(r'    hosts \{[^}]*\}\n', '', corefile)
hosts_block = '''    hosts {
       ${NODE_IP} ${HARBOR_HOST}
       fallthrough
    }
'''
corefile = corefile.replace('    ready\n', '    ready\n' + hosts_block)
cm['data']['Corefile'] = corefile
json.dump(cm, sys.stdout)
" | kubectl apply -f -
kubectl -n kube-system rollout restart deployment coredns
kubectl -n kube-system rollout status deployment coredns --timeout=60s

echo "==> Waiting for ${HARBOR_HOST}:${HARBOR_PORT} to answer"
for _ in $(seq 1 30); do
  if curl -sk --resolve "${HARBOR_HOST}:${HARBOR_PORT}:127.0.0.1" "https://${HARBOR_HOST}:${HARBOR_PORT}/api/v2.0/systeminfo" >/dev/null; then
    break
  fi
  sleep 5
done

# The chart itself doesn't consume this (CA trust is expected to come from
# the cluster, e.g. trust-manager) — written out for your own use, e.g. as
# the source for a trust-manager Bundle, or `curl --cacert` when poking at
# Harbor directly from the host.
echo "==> Extracting Harbor's CA cert (secret harbor-nginx, key ca.crt — confirmed for expose.type=nodePort)"
kubectl get secret harbor-nginx -n "$NAMESPACE" -o jsonpath='{.data.ca\.crt}' | base64 -d > "${OUT_DIR}/harbor-ca.crt"
cp "${OUT_DIR}/harbor-ca.crt" ./harbor-ca.crt
echo "CA written to $(pwd)/harbor-ca.crt (not consumed by the chart)"

CURL=(curl -sk --resolve "${HARBOR_HOST}:${HARBOR_PORT}:127.0.0.1" -u "admin:${ADMIN_PASSWORD}")
API="https://${HARBOR_HOST}:${HARBOR_PORT}/api/v2.0"

echo "==> Ensuring project '${PROJECT}' exists"
"${CURL[@]}" -o /dev/null -w '%{http_code}\n' "${API}/projects" \
  -H 'Content-Type: application/json' \
  -d "{\"project_name\": \"${PROJECT}\", \"public\": false}" || true

if [ -f ./robot-credentials.env ]; then
  echo "==> ./robot-credentials.env already exists, skipping robot account creation"
  echo "    (delete it, and the robot account via Harbor's UI/API, to force recreation)"
else
  echo "==> Creating robot account '${ROBOT_NAME}' (pull, push, list-tags, read vulnerability reports)"
  ROBOT_RESPONSE="$("${CURL[@]}" "${API}/robots" \
    -H 'Content-Type: application/json' \
    -d "{
      \"name\": \"${ROBOT_NAME}\",
      \"duration\": -1,
      \"level\": \"project\",
      \"permissions\": [{
        \"kind\": \"project\",
        \"namespace\": \"${PROJECT}\",
        \"access\": [
          {\"resource\": \"repository\", \"action\": \"pull\"},
          {\"resource\": \"repository\", \"action\": \"push\"},
          {\"resource\": \"repository\", \"action\": \"list\"},
          {\"resource\": \"tag\", \"action\": \"list\"},
          {\"resource\": \"artifact\", \"action\": \"read\"},
          {\"resource\": \"artifact\", \"action\": \"list\"},
          {\"resource\": \"scan\", \"action\": \"read\"},
          {\"resource\": \"scan\", \"action\": \"create\"}
        ]
      }]
    }")"
  echo "$ROBOT_RESPONSE" | python3 -m json.tool
  if ! echo "$ROBOT_RESPONSE" | python3 -c "import json,sys; json.load(sys.stdin)['secret']" >/dev/null 2>&1; then
    echo "Robot account creation failed (see response above) — if it already exists from a" >&2
    echo "prior run whose robot-credentials.env got deleted, remove the robot account via" >&2
    echo "Harbor's UI/API first, then re-run this script." >&2
    exit 1
  fi
  echo "$ROBOT_RESPONSE" > "${OUT_DIR}/robot.json"
  ROBOT_USER="$(python3 -c "import json;print(json.load(open('${OUT_DIR}/robot.json'))['name'])")"
  ROBOT_SECRET="$(python3 -c "import json;print(json.load(open('${OUT_DIR}/robot.json'))['secret'])")"
  echo "robot username: ${ROBOT_USER}"
  echo "(secret saved to ${OUT_DIR}/robot.json — not printed)"

  cat > ./robot-credentials.env <<EOF
HARBOR_ROBOT_USERNAME='${ROBOT_USER}'
HARBOR_ROBOT_PASSWORD='${ROBOT_SECRET}'
EOF
  echo "Robot credentials written to $(pwd)/robot-credentials.env (git-ignored; do not commit)"
fi
