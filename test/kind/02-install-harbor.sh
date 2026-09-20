#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

helm repo add harbor https://helm.goharbor.io 2>/dev/null || true
helm repo update harbor

kubectl create namespace harbor --dry-run=client -o yaml | kubectl apply -f -

helm upgrade --install harbor harbor/harbor \
  --namespace harbor \
  -f harbor-values.yaml \
  --wait --timeout 10m

kubectl get pods -n harbor
