#!/bin/sh
# Checks a running stack from outside: alive, ready, and the audit trail readable by the operator.
# Usage: deploy/verify.sh https://sentinelapi.example.org   (reads SENTINEL_OPERATOR_TOKEN from the environment)
set -eu

base="${1:?usage: deploy/verify.sh <base URL>}"
curl --fail --silent --show-error "$base/health" > /dev/null && echo "verify: /health ok"
curl --fail --silent --show-error "$base/ready" && echo
if [ -n "${SENTINEL_OPERATOR_TOKEN:-}" ]; then
  curl --fail --silent --show-error -H "Authorization: Bearer $SENTINEL_OPERATOR_TOKEN" \
    "$base/security/events?limit=1" | head -c 300 && echo
fi
