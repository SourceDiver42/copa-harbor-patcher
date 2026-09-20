#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

kind create cluster --config kind-config.yaml
kubectl cluster-info --context kind-copa-harbor-test
