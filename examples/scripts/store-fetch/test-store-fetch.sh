#!/usr/bin/env bash
# Stores one record of each flavor (ID, DATA, FILE), fetches each one back by its
# reference key, and checks the returned value matches what was stored.
#
# Requires: curl, jq, base64. Run setup/setup-test-fixtures.sh first, or set
# API_KEY, API_SECRET, ID_ENTITY, DATA_ENTITY and FILE_ENTITY yourself.
#
# Usage:
#   ./test-store-fetch.sh

set -uo pipefail
. "$(dirname "$0")/../common.sh"
require_cmds
load_fixtures
require_client_env
: "${ID_ENTITY:?Set ID_ENTITY}" "${DATA_ENTITY:?Set DATA_ENTITY}" "${FILE_ENTITY:?Set FILE_ENTITY}"

store() { # flavor entity base64content [fileName] [principal_id]
  vault_call "$(jq -nc --arg t "$1" --arg e "$2" --arg c "$3" --arg f "${4:-}" --arg p "${5:-}" \
    '{_func:"store_data",entityType:$t,entityName:$e,content:$c}
     + (if $f=="" then {} else {fileName:$f} end)
     + (if $p=="" then {} else {principal_id:$p} end)')"
}
fetch() {
  vault_call "$(jq -nc --arg r "$1" '{_func:"fetch_data","reference-key":$r}')"
}

section "ID flavor"
VALUE="$(date +%s | tail -c 11)01"   # 12 digits
CONTENT="$(b64 "$VALUE")"
store ID "$ID_ENTITY" "$CONTENT"
expect_status 201 "store ID value"
REF="$(jqr '.reference_key')"
fetch "$REF"
expect_status 200 "fetch ID value"
expect_jq '.value' "$CONTENT" "fetched value equals stored content"
expect_jq '.flavor' "ID" "flavor is ID"

section "DATA flavor"
CONTENT="$(b64 "Example note written at $(date -u +%FT%TZ)")"
store DATA "$DATA_ENTITY" "$CONTENT"
expect_status 201 "store DATA value"
REF="$(jqr '.reference_key')"
fetch "$REF"
expect_status 200 "fetch DATA value"
expect_jq '.value' "$CONTENT" "fetched value equals stored content"

section "FILE flavor"
CONTENT="$(b64 $'%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n')"
store FILE "$FILE_ENTITY" "$CONTENT" "example-contract.pdf"
expect_status 201 "store PDF file"
REF="$(jqr '.reference_key')"
fetch "$REF"
expect_status 200 "fetch PDF file"
expect_jq '.value' "$CONTENT" "fetched content equals stored content"
expect_jq '.fileName' "example-contract.pdf" "file name is preserved"

section "Linking a record to a principal"
# principal_id is optional and opaque. It lets one request erase all of a person's records later.
PRINCIPAL="example-principal-$(date +%s)"
CONTENT="$(b64 "Note linked to $PRINCIPAL")"
store DATA "$DATA_ENTITY" "$CONTENT" "" "$PRINCIPAL"
expect_status 201 "store DATA value with principal_id"
REF="$(jqr '.reference_key')"
fetch "$REF"
expect_status 200 "fetch record stored with principal_id"
expect_jq '.value' "$CONTENT" "fetched value equals stored content"
store DATA "$DATA_ENTITY" "$CONTENT" "" "not a valid id!"
expect_status 400 "principal_id with unsafe characters is rejected"

section "Unknown reference"
fetch "00000000-0000-0000-0000-000000000000"
if [ "$HTTP_STATUS" != "200" ]; then pass "unknown reference is not returned (HTTP $HTTP_STATUS)"; else fail "unknown reference returned data"; fi

summary
