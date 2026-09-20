#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../../image"

docker build -t copa-harbor-patcher:dev .
kind load docker-image copa-harbor-patcher:dev --name copa-harbor-test
