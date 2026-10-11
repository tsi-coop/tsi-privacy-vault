#!/usr/bin/env bash
# Shared helpers for the example test scripts. Source this file, do not run it.
#
# Requires: curl, jq, base64.
#
# Environment:
#   BASE_URL     Vault base URL. Default http://localhost:8081
#   API_KEY      Client API key        (client scripts)
#   API_SECRET   Client API secret     (client scripts)
#   ADMIN_TOKEN  Admin JWT             (admin calls, set by setup script)

BASE_URL="${BASE_URL:-http://localhost:8081}"
PASS_COUNT=0
FAIL_COUNT=0
HTTP_STATUS=""
BODY=""

require_cmds() {
  local cmd
  for cmd in curl jq base64; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "Missing required command: $cmd" >&2
      exit 1
    fi
  done
}

require_client_env() {
  : "${API_KEY:?Set API_KEY to a client API key. Run setup/setup-test-fixtures.sh to create one.}"
  : "${API_SECRET:?Set API_SECRET to the matching secret.}"
}

# Loads fixtures written by setup/setup-test-fixtures.sh when the variables are not already set.
load_fixtures() {
  local file="${FIXTURES_FILE:-$(dirname "${BASH_SOURCE[0]}")/setup/.fixtures.env}"
  if [ -z "${API_KEY:-}" ] && [ -f "$file" ]; then
    # shellcheck disable=SC1090
    . "$file"
  fi
}

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

# http_post URL JSON [extra curl args...]  -> sets HTTP_STATUS and BODY
http_post() {
  local url="$1" data="$2" out
  shift 2
  # The body goes through stdin so large payloads do not hit the argument size limit.
  if ! out=$(printf '%s' "$data" | curl -sS -m 60 -w '\n%{http_code}' -H 'Content-Type: application/json' "$@" --data-binary @- "$url" 2>/dev/null); then
    HTTP_STATUS="000"
    BODY=""
    return 0
  fi
  HTTP_STATUS="${out##*$'\n'}"
  BODY="${out%$'\n'*}"
  # Older builds answered admin errors with HTTP 200 and the real code only in the body.
  local inner
  inner="$(printf '%s' "$BODY" | jq -r 'if type=="object" and (.status|type)=="number" and .status>=400 then .status else empty end' 2>/dev/null)"
  if [ -n "$inner" ] && [ "$HTTP_STATUS" -lt 400 ] 2>/dev/null; then HTTP_STATUS="$inner"; fi
}

# vault_call JSON  -> data plane call with the client credentials
vault_call() {
  http_post "$BASE_URL/api/client/vault" "$1" \
    -H "X-API-Key: $API_KEY" -H "X-API-Secret: $API_SECRET"
}

# vault_call_as KEY SECRET JSON
vault_call_as() {
  http_post "$BASE_URL/api/client/vault" "$3" -H "X-API-Key: $1" -H "X-API-Secret: $2"
}

# admin_call ENDPOINT JSON  (endpoint: entity, apikey, permission, utility)
admin_call() {
  http_post "$BASE_URL/api/admin/$1" "$2" -H "Authorization: Bearer ${ADMIN_TOKEN:?ADMIN_TOKEN not set}"
}

jqr() { printf '%s' "$BODY" | jq -r "$1" 2>/dev/null; }

pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf '  PASS  %s\n' "$1"; }
fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf '  FAIL  %s\n' "$1"
  printf '        status=%s body=%s\n' "$HTTP_STATUS" "$(printf '%s' "$BODY" | head -c 300)"
}

# expect_status CODE DESCRIPTION
expect_status() {
  if [ "$HTTP_STATUS" = "$1" ]; then pass "$2"; else fail "$2 (expected HTTP $1)"; fi
}

# expect_jq FILTER EXPECTED DESCRIPTION
expect_jq() {
  local got
  got="$(jqr "$1")"
  if [ "$got" = "$2" ]; then pass "$3"; else fail "$3 (expected '$2', got '$got')"; fi
}

section() { printf '\n== %s\n' "$1"; }

summary() {
  printf '\n%s passed, %s failed\n' "$PASS_COUNT" "$FAIL_COUNT"
  [ "$FAIL_COUNT" -eq 0 ]
}
