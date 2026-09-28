#!/bin/bash
set -euo pipefail

case "${1:-}" in
  sweep|webhook|patch-one)
    # Generate the registry docker config.json from the credential env vars
    # before handing off. In webhook mode this runs once at container start;
    # the config persists in the shared emptyDir for the patch-one.sh calls
    # webhook-server spawns later.
    /usr/local/bin/render-docker-config.sh
    ;;
esac

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
