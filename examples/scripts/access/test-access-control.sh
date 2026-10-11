#!/usr/bin/env bash
# Checks the data plane authorization rules:
#   - a request with a wrong secret is rejected
#   - a read-only key cannot store
#   - a key with no permission on an entity cannot store or fetch from it
#   - an unknown entity is rejected
#
# Requires: curl, jq, base64. Run setup/setup-test-fixtures.sh first. The
# fixtures include a read-only key that can read the DATA entity only.
#
# Usage:
#   ./test-access-control.sh

set -uo pipefail
. "$(dirname "$0")/../common.sh"
require_cmds
load_fixtures
require_client_env
: "${DATA_ENTITY:?Set DATA_ENTITY}" "${ID_ENTITY:?Set ID_ENTITY}"
: "${RO_API_KEY:?Set RO_API_KEY (written by the setup script)}" "${RO_API_SECRET:?Set RO_API_SECRET}"

store_as() { # key secret entity
  vault_call_as "$1" "$2" "$(jq -nc --arg e "$3" --arg c "$(b64 'access control check')" \
    '{_func:"store_data",entityType:"DATA",entityName:$e,content:$c}')"
}

section "Credentials"
store_as "$API_KEY" "wrong-secret" "$DATA_ENTITY"
expect_status 401 "wrong secret rejected"
store_as "no-such-key" "no-such-secret" "$DATA_ENTITY"
expect_status 401 "unknown key rejected"

section "Read-only key"
store_as "$RO_API_KEY" "$RO_API_SECRET" "$DATA_ENTITY"
expect_status 403 "read-only key cannot store"

# A record the read-write key stores, so the read-only key has something to fetch.
store_as "$API_KEY" "$API_SECRET" "$DATA_ENTITY"
expect_status 201 "read-write key can store"
REF="$(jqr '.reference_key')"
vault_call_as "$RO_API_KEY" "$RO_API_SECRET" "$(jq -nc --arg r "$REF" '{_func:"fetch_data","reference-key":$r}')"
expect_status 200 "read-only key can fetch a DATA record"

section "No permission on the entity"
store_as "$RO_API_KEY" "$RO_API_SECRET" "$ID_ENTITY"
expect_status 403 "key without a grant cannot store to the ID entity"

# Store an ID record with the read-write key, then try to read it as the read-only key.
vault_call "$(jq -nc --arg e "$ID_ENTITY" --arg c "$(b64 '210987654321')" \
  '{_func:"store_data",entityType:"ID",entityName:$e,content:$c}')"
expect_status 201 "read-write key stores an ID record"
ID_REF="$(jqr '.reference_key')"
vault_call_as "$RO_API_KEY" "$RO_API_SECRET" "$(jq -nc --arg r "$ID_REF" '{_func:"fetch_data","reference-key":$r}')"
if [ "$HTTP_STATUS" != "200" ]; then pass "key without a grant cannot fetch the ID record (HTTP $HTTP_STATUS)"; else fail "key without a grant fetched the ID record"; fi

section "Unknown entity"
store_as "$API_KEY" "$API_SECRET" "NO_SUCH_ENTITY"
if [ "$HTTP_STATUS" = "403" ] || [ "$HTTP_STATUS" = "404" ]; then pass "unknown entity rejected (HTTP $HTTP_STATUS)"; else fail "unknown entity was not rejected"; fi

summary
