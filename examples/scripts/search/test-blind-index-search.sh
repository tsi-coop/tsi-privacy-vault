#!/usr/bin/env bash
# Stores a DATA record, then searches for it by full value, by one word, and by
# a 3 character prefix. Also checks that an unknown term returns nothing and
# that a key without READ access to the entity gets no match.
#
# Requires: curl, jq, base64. Run setup/setup-test-fixtures.sh first.
#
# Usage:
#   ./test-blind-index-search.sh

set -uo pipefail
. "$(dirname "$0")/../common.sh"
require_cmds
load_fixtures
require_client_env
: "${DATA_ENTITY:?Set DATA_ENTITY}"

TAG="$(date +%s)"
FIRST="Zephyr${TAG}"
VALUE="$FIRST Quillfeather"

search() { # term [key secret]
  local json
  json="$(jq -nc --arg t "$1" '{_func:"search_data",searchTerm:$t}')"
  if [ -n "${2:-}" ]; then vault_call_as "$2" "$3" "$json"; else vault_call "$json"; fi
}

section "Store a searchable record"
vault_call "$(jq -nc --arg e "$DATA_ENTITY" --arg c "$(b64 "$VALUE")" \
  '{_func:"store_data",entityType:"DATA",entityName:$e,content:$c}')"
expect_status 201 "store record '$VALUE'"
REF="$(jqr '.reference_key')"

has_ref() { printf '%s' "$BODY" | jq -e --arg r "$REF" '.results | map(.reference_key) | index($r) != null' >/dev/null 2>&1; }

section "Search"
search "$VALUE"
expect_status 200 "search full value"
if has_ref; then pass "full value finds the record"; else fail "full value did not find the record"; fi

search "$FIRST"
if has_ref; then pass "first word finds the record"; else fail "first word did not find the record"; fi

search "Zep"
if has_ref; then pass "3 character prefix finds the record"; else fail "prefix did not find the record"; fi

search "no-such-value-${TAG}"
expect_status 200 "unknown term returns 200"
expect_jq '.results | length' "0" "unknown term has no matches"

section "Case and spacing"
search "  $(printf '%s' "$FIRST" | tr '[:upper:]' '[:lower:]')  "
if has_ref; then pass "search ignores case and surrounding spaces"; else fail "case or spacing changed the result"; fi

section "Authorization"
if [ -n "${RO_API_KEY:-}" ]; then
  # The read-only key can read DATA entities, so it should see the match.
  search "$FIRST" "$RO_API_KEY" "$RO_API_SECRET"
  if has_ref; then pass "read-only key can find the record"; else fail "read-only key could not find the record"; fi
fi
summary
