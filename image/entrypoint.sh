#!/bin/bash
set -euo pipefail

case "${1:-}" in
  sweep)
    exec /usr/local/bin/sweep.sh
    ;;
  webhook)
    exec /usr/local/bin/webhook-server
    ;;
  patch-one)
    shift
    exec /usr/local/bin/patch-one.sh "$@"
    ;;
  *)
    echo "usage: entrypoint.sh {sweep|webhook|patch-one <repo> <tag>}" >&2
    exit 64
    ;;
esac
