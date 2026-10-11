#!/usr/bin/env bash
# Checks utilities (secrets, keys and certificates) end to end:
#   - a client key discovers only the utilities it was granted
#   - a client key resolves a utility by label and gets the enrolled value
#   - the admin console list shows the utility without its value
#   - rotating a utility changes the value the client resolves
#   - a read-only grant, a missing grant and an unknown label are handled
#
# Requires: curl, jq, base64. Run setup/setup-test-fixtures.sh first. Rotation
# uses the admin token the setup script saved. It expires, so rerun setup on 401.
#
# Usage:
#   ./test-utilities.sh

set -uo pipefail
. "$(dirname "$0")/../common.sh"
require_cmds
load_fixtures
require_client_env
: "${UTILITY_LABEL:?Set UTILITY_LABEL (written by the setup script)}"
: "${UTILITY_CERT_LABEL:?Set UTILITY_CERT_LABEL}"
: "${RO_API_KEY:?Set RO_API_KEY}" "${RO_API_SECRET:?Set RO_API_SECRET}"

resolve_as() { # key secret label
  vault_call_as "$1" "$2" "$(jq -nc --arg u "$3" '{_func:"resolve_utility",utility_id:$u}')"
}

section "Discovery"
vault_call '{"_func":"get_authorized_utilities"}'
expect_status 200 "list authorized utilities"
expect_jq "[.utilities[].label | select(. == \"$UTILITY_LABEL\")] | length" 1 "KEYS utility is listed"
expect_jq "[.utilities[].label | select(. == \"$UTILITY_CERT_LABEL\")] | length" 1 "CERT utility is listed"
expect_jq "[.utilities[] | select(.label == \"$UTILITY_LABEL\") | .flavor][0]" KEYS "flavor is KEYS"
expect_jq "[.utilities[] | select(.label == \"$UTILITY_LABEL\") | .can_read][0]" true "read flag is set"

vault_call_as "$RO_API_KEY" "$RO_API_SECRET" '{"_func":"get_authorized_utilities"}'
expect_status 200 "read-only key lists utilities"
expect_jq "[.utilities[].label | select(. == \"$UTILITY_CERT_LABEL\")] | length" 0 "read-only key does not see the CERT utility"
expect_jq "[.utilities[] | select(.label == \"$UTILITY_LABEL\") | .can_write][0]" false "read-only key has no write flag"

section "Resolve"
resolve_as "$API_KEY" "$API_SECRET" "$UTILITY_LABEL"
expect_status 200 "resolve KEYS utility"
expect_jq '.success' true "success flag is true"
expect_jq '.id' "$UTILITY_LABEL" "id echoes the label"
[ -n "$(jqr '.value // empty')" ] && pass "value is returned" || fail "value is returned"

resolve_as "$API_KEY" "$API_SECRET" "$UTILITY_CERT_LABEL"
expect_status 200 "resolve CERT utility"
case "$(jqr '.value')" in
  *"BEGIN CERTIFICATE"*) pass "certificate PEM is returned intact" ;;
  *) fail "certificate PEM is returned intact" ;;
esac

resolve_as "$RO_API_KEY" "$RO_API_SECRET" "$UTILITY_LABEL"
expect_status 200 "read-only key resolves the utility it can read"

section "Access"
resolve_as "$RO_API_KEY" "$RO_API_SECRET" "$UTILITY_CERT_LABEL"
expect_status 403 "key with no grant cannot resolve"
resolve_as "$API_KEY" "$API_SECRET" "EX_NO_SUCH_UTILITY"
expect_status 403 "unknown label is not resolved"
resolve_as "$API_KEY" "wrong-secret" "$UTILITY_LABEL"
expect_status 401 "wrong secret rejected"

section "Admin list and rotate"
if [ -z "${ADMIN_TOKEN:-}" ]; then
  echo "  ADMIN_TOKEN not set, skipping admin checks"
else
  admin_call utility '{"_func":"utility_list"}'
  expect_status 200 "admin lists utilities"
  UTILITY_ID="$(printf '%s' "$BODY" | jq -r --arg l "$UTILITY_LABEL" '.[] | select(.label==$l) | .id' 2>/dev/null)"
  if [ -z "$UTILITY_ID" ]; then
    fail "admin list contains $UTILITY_LABEL"
  else
    pass "admin list contains $UTILITY_LABEL"
    if printf '%s' "$BODY" | jq -e '.[0] | has("payload") or has("value")' >/dev/null 2>&1; then
      fail "admin list does not expose payloads"
    else
      pass "admin list does not expose payloads"
    fi

    NEW_VALUE="rotated-$(date -u +%s)-$RANDOM"
    admin_call utility "$(jq -nc --arg i "$UTILITY_ID" --arg p "$NEW_VALUE" '{_func:"rotate",utility_id:$i,payload:$p}')"
    expect_status 200 "rotate utility"
    resolve_as "$API_KEY" "$API_SECRET" "$UTILITY_LABEL"
    expect_status 200 "resolve after rotate"
    expect_jq '.value' "$NEW_VALUE" "resolved value is the rotated value"
  fi
fi

summary
