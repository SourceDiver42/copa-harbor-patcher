#!/bin/bash
# Minimal SMTP sender used by the CronJob sweep to email its patch summary.
# curl-based (the runtime image has curl + bash, not python); text body only.
#
# Connection details come from the environment (injected from the smtp secret
# by the chart's smtpEnv helper):
#   SMTP_URL      smtp://host:port (STARTTLS) or smtps://host:port (implicit TLS)
#   SMTP_USER     optional SMTP username (no auth if empty)
#   SMTP_PASS     optional SMTP password
#   MAIL_FROM     envelope/From address
#   MAIL_TO       recipient(s), comma-separated
#   SMTP_CA_FILE  optional CA bundle to trust (curl --cacert)
#   SMTP_INSECURE 1/true/yes -> skip TLS verification (testing only)
#
# Usage: send-report.sh <subject> <bodyfile>
set -euo pipefail

subject="${1:?usage: send-report.sh <subject> <bodyfile>}"
bodyfile="${2:?usage: send-report.sh <subject> <bodyfile>}"

: "${SMTP_URL:?SMTP_URL is required}"
: "${MAIL_FROM:?MAIL_FROM is required}"
: "${MAIL_TO:?MAIL_TO is required}"

msg="$(mktemp)"
trap 'rm -f "$msg"' EXIT
{
  printf 'From: %s\r\n' "$MAIL_FROM"
  printf 'To: %s\r\n' "$MAIL_TO"
  printf 'Subject: %s\r\n' "$subject"
  printf 'Date: %s\r\n' "$(date -R 2>/dev/null || date)"
  printf 'MIME-Version: 1.0\r\n'
  printf 'Content-Type: text/plain; charset=utf-8\r\n'
  printf '\r\n'
  sed 's/$/\r/' "$bodyfile"
} > "$msg"

args=(--fail --silent --show-error --url "$SMTP_URL"
      --mail-from "$MAIL_FROM" --upload-file "$msg")

# one --mail-rcpt per (trimmed, non-empty) recipient
IFS=',' read -ra _rcpts <<< "$MAIL_TO"
for r in "${_rcpts[@]}"; do
  r="$(printf '%s' "$r" | tr -d '[:space:]')"
  [ -n "$r" ] && args+=(--mail-rcpt "$r")
done

# smtps:// is implicit TLS; everything else requires STARTTLS.
case "$SMTP_URL" in
  smtps://*) : ;;
  *) args+=(--ssl-reqd) ;;
esac
[ -n "${SMTP_USER:-}" ] && args+=(--user "${SMTP_USER}:${SMTP_PASS:-}")
[ -n "${SMTP_CA_FILE:-}" ] && args+=(--cacert "$SMTP_CA_FILE")
case "$(printf '%s' "${SMTP_INSECURE:-}" | tr 'A-Z' 'a-z')" in
  1|true|yes) echo "WARNING: SMTP_INSECURE set; TLS verification disabled" >&2; args+=(--insecure) ;;
esac

curl "${args[@]}"
