#!/bin/bash
# Renders ${DOCKER_CONFIG}/config.json from the registry credentials passed in
# via env, so the chart's credentials secret only ever needs plaintext
# username/password/url keys — the docker config.json copa/buildkit use for
# registry auth is "inferred" here at container startup rather than being
# baked into (or required in) the secret.
#
# Registry host precedence: HARBOR_REGISTRY_HOST_OVERRIDE (from an existing
# secret's url key, when present) wins over HARBOR_REGISTRY_HOST (the literal
# harbor.registry). Idempotent: safe to run once per container start.
set -euo pipefail

DOCKER_CONFIG="${DOCKER_CONFIG:-/etc/copa/docker}"
HOST="${HARBOR_REGISTRY_HOST_OVERRIDE:-${HARBOR_REGISTRY_HOST:-}}"
USER_NAME="${HARBOR_USERNAME:-}"
PASSWORD="${HARBOR_PASSWORD:-}"

if [ -z "$HOST" ] || [ -z "$USER_NAME" ] || [ -z "$PASSWORD" ]; then
  echo "render-docker-config: missing registry host/username/password; skipping config.json generation" >&2
  # Not fatal: an operator may inject their own DOCKER_CONFIG via extraVolumes.
  exit 0
fi

# JSON-escape the two characters that would otherwise break a double-quoted
# JSON string. Robot passwords/usernames are the only untrusted-shape values
# here; control characters aren't expected in registry credentials.
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "$s"
}

auth="$(printf '%s:%s' "$USER_NAME" "$PASSWORD" | base64 | tr -d '\n')"

mkdir -p "$DOCKER_CONFIG"
umask 0077
cat > "${DOCKER_CONFIG}/config.json" <<EOF
{"auths":{"$(json_escape "$HOST")":{"username":"$(json_escape "$USER_NAME")","password":"$(json_escape "$PASSWORD")","auth":"${auth}"}}}
EOF

echo "render-docker-config: wrote ${DOCKER_CONFIG}/config.json for ${HOST}"
