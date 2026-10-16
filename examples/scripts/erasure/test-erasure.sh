#!/usr/bin/env bash
# End-to-end check of erasure by principal through the HTTP APIs: store with a principal_id,
# policy hold, legal hold, shred (admin and client API), the scheduled job, the register and the certificate.
#
# Creates its own entities and keys (prefix ERASE_<stamp>), so it does not need the fixtures.
# Needs an admin with the SYSTEM_ADMIN role and a second admin with another role, to check
# that only SYSTEM_ADMIN can destroy data. Use a local or staging instance only.
#
# Requires: curl, jq, base64.
#
# Usage:
#   ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD=<password> \
#   VIEWER_EMAIL=viewer@example.com VIEWER_PASSWORD=<password> ./test-erasure.sh
#
# VIEWER_* is optional. Without it the role check is skipped.

set -uo pipefail
. "$(dirname "$0")/../common.sh"
require_cmds

: "${ADMIN_EMAIL:?Set ADMIN_EMAIL}" "${ADMIN_PASSWORD:?Set ADMIN_PASSWORD}"
STAMP="$(date +%s)"
P1="P-${STAMP}-1"; P2="P-${STAMP}-2"
E_FREE="ERASE_${STAMP}_FREE"      # erasable at once
E_DATED="ERASE_${STAMP}_DATED"    # policy hold: 365 days from creation

login() { # email password -> sets TOKEN (not a subshell, so HTTP_STATUS is kept)
  http_post "$BASE_URL/api/admin/login" \
    "$(jq -nc --arg e "$1" --arg p "$2" '{_func:"admin_login",email:$e,password:$p}')"
  TOKEN="$(jqr '.token')"
}
as_viewer() { http_post "$BASE_URL/api/admin/erasure" "$1" -H "Authorization: Bearer $VIEWER_TOKEN"; }
erasure() { admin_call erasure "$1"; }
store() { # entity principal value
  vault_call "$(jq -nc --arg e "$1" --arg p "$2" --arg c "$(b64 "$3")" \
    '{_func:"store_data",entityType:"DATA",entityName:$e,content:$c} + (if $p=="" then {} else {principal_id:$p} end)')"
}
fetch() { vault_call "$(jq -nc --arg r "$1" '{_func:"fetch_data","reference-key":$r}')"; }
search() { vault_call "$(jq -nc --arg t "$1" '{_func:"search_data",searchTerm:$t}')"; }

section "Admin login and fixtures"
login "$ADMIN_EMAIL" "$ADMIN_PASSWORD"; ADMIN_TOKEN="$TOKEN"
[ "$HTTP_STATUS" = "200" ] && [ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ] && pass "admin login" || { fail "admin login"; exit 1; }
VIEWER_TOKEN=""
if [ -n "${VIEWER_EMAIL:-}" ]; then login "$VIEWER_EMAIL" "${VIEWER_PASSWORD:-}"; VIEWER_TOKEN="$TOKEN"; fi

mk_entity() { # code extra-json
  admin_call entity "$(jq -nc --arg c "$1" --argjson x "$2" \
    '{_func:"create_entity",active:true,entity_code:$c,entity_name:$c,flavor:"DATA",validation_regex:""} + $x')"
  expect_status 200 "create entity $1"
}
mk_entity "$E_FREE"  '{}'
mk_entity "$E_DATED" '{"retain_days":365}'

admin_call entity "$(jq -nc --arg c "$E_FREE" '{_func:"create_entity",active:true,entity_code:($c+"_BAD"),entity_name:"bad",flavor:"DATA",retain_days:-1}')"
expect_status 400 "negative retain_days is rejected"

admin_call apikey "$(jq -nc --arg l "erasure-test-$STAMP" '{_func:"create_key",label:$l,active:true}')"
RW_KEY="$(jqr '.data.api_key_id')"; RW_SECRET="$(jqr '.data.raw_api_secret')"
API_KEY="$RW_KEY"; API_SECRET="$RW_SECRET"
[ -n "$RW_KEY" ] && [ "$RW_KEY" != "null" ] && pass "created client key" || { fail "create client key"; exit 1; }
grant() { admin_call permission "$(jq -nc --arg k "$1" --arg e "$2" --argjson w "$3" \
  '{_func:"create_permission",api_key:$k,resource_type:"ENTITY",resource_id:$e,can_read:true,can_write:$w,granted_by:"erasure-test"}')"; }
for e in "$E_FREE" "$E_DATED"; do grant "$RW_KEY" "$e" true; done

section "Store with principal_id"
V_FREE="free-value-$STAMP"; V_DATED="dated-value-$STAMP"; V_P2="p2-value-$STAMP"; V_LOOSE="loose-value-$STAMP"
store "$E_FREE" "$P1" "$V_FREE";   expect_status 201 "store erasable record for P1"; R_FREE="$(jqr '.reference_key')"
store "$E_DATED" "$P1" "$V_DATED"; expect_status 201 "store dated-retention record for P1"; R_DATED="$(jqr '.reference_key')"
store "$E_FREE" "$P2" "$V_P2";     expect_status 201 "store record for P2"; R_P2="$(jqr '.reference_key')"
store "$E_FREE" "" "$V_LOOSE";     expect_status 201 "store record without principal_id"; R_LOOSE="$(jqr '.reference_key')"
for r in "$R_FREE" "$R_DATED" "$R_P2" "$R_LOOSE"; do
  fetch "$r"; [ "$HTTP_STATUS" = "200" ] || fail "fetch $r before shred"
done
pass "all four records readable before shred"
search "$V_FREE"; expect_jq '.results | length' 1 "erasable value is searchable before shred"

store "$E_FREE" "bad principal!" "x"; expect_status 400 "principal_id with unsafe characters is rejected"

section "Authorization and confirmation"
if [ -n "$VIEWER_TOKEN" ] && [ "$VIEWER_TOKEN" != "null" ]; then
  as_viewer "$(jq -nc --arg p "$P1" '{_func:"shred_principal",principal_id:$p,confirm:$p}')"
  expect_status 403 "non SYSTEM_ADMIN cannot shred"
  as_viewer '{"_func":"get_erasure_register"}'
  expect_status 200 "non SYSTEM_ADMIN can read the register"
else
  echo "  skipped: VIEWER_EMAIL not set"
fi
erasure "$(jq -nc --arg p "$P1" '{_func:"shred_principal",principal_id:$p,confirm:"nope"}')"
expect_status 400 "shred needs confirm equal to principal_id"
fetch "$R_FREE"; expect_status 200 "nothing was destroyed by the refused requests"

section "Shred principal P1 (one record under policy hold)"
erasure "$(jq -nc --arg p "$P1" '{_func:"shred_principal",principal_id:$p,confirm:$p}')"
expect_status 200 "shred P1"
expect_jq '.state' PARTIAL "state is PARTIAL"
expect_jq '.records_destroyed' 1 "one record destroyed"
expect_jq '.records_retained' 1 "one record retained"
fetch "$R_FREE";  expect_status 410 "erased record reads as 410 erased, not a decryption error"
fetch "$R_DATED"; expect_status 200 "record under policy hold stays readable"
fetch "$R_P2";    expect_status 200 "other principal untouched"
fetch "$R_LOOSE"; expect_status 200 "record without principal untouched"
search "$V_FREE"; expect_jq '.results | length' 0 "erased value no longer matches the blind index"
store "$E_FREE" "$P1" "again"; expect_status 409 "new store for an erased principal is rejected"

section "Legal hold"
erasure "$(jq -nc --arg p "$P2" '{_func:"place_legal_hold",principal_id:$p,reason:"Case review",case_ref:"CASE-1"}')"
expect_status 201 "place hold on P2"
HOLD="$(jqr '.hold_id')"
erasure "$(jq -nc --arg p "$P2" '{_func:"shred_principal",principal_id:$p,confirm:$p}')"
expect_status 409 "shred is refused while a hold is open"
fetch "$R_P2"; expect_status 200 "held principal untouched"
erasure "$(jq -nc --argjson h "$HOLD" '{_func:"release_legal_hold",hold_id:$h}')"
expect_status 200 "release hold"

section "Scheduled job"
erasure '{"_func":"run_erasure_job"}'
expect_status 200 "run erasure job"
fetch "$R_DATED"; expect_status 200 "record still inside its 365 day policy hold stays readable"
erasure '{"_func":"get_erasure_register","state":"PARTIAL"}'
expect_jq "[.register[] | select(.principal_id==\"$P1\")] | length" 1 "P1 remains PARTIAL for the dated record"

section "Certificate and register"
erasure "$(jq -nc --arg p "$P1" '{_func:"get_erasure_certificate",principal_id:$p}')"
expect_status 200 "certificate"
expect_jq '.destroyed | length' 1 "certificate lists one destroyed record"
expect_jq '.retained | length' 1 "certificate lists one retained record"
expect_jq '.retained[0].reference_key' "$R_DATED" "retained record is the dated one"

section "Erasure requested through the client API"
admin_call apikey "$(jq -nc --arg l "erasure-test-ro-$STAMP" '{_func:"create_key",label:$l,active:true}')"
RO_KEY="$(jqr '.data.api_key_id')"; RO_SECRET="$(jqr '.data.raw_api_secret')"
grant "$RO_KEY" "$E_FREE" false   # can read, cannot write
P3="P-${STAMP}-3"; P4="P-${STAMP}-4"
store "$E_FREE" "$P3" "client-erase-$STAMP"; expect_status 201 "store record for P3"; R_P3="$(jqr '.reference_key')"
store "$E_FREE" "$P4" "held-$STAMP";         expect_status 201 "store record for P4"; R_P4="$(jqr '.reference_key')"

vault_call_as "$RO_KEY" "$RO_SECRET" "$(jq -nc --arg p "$P3" '{_func:"shred_principal",principal_id:$p,confirm:$p}')"
expect_status 403 "key without write access cannot erase the principal"
vault_call "$(jq -nc --arg p "$P3" '{_func:"shred_principal",principal_id:$p,confirm:"nope"}')"
expect_status 400 "client shred needs confirm equal to principal_id"
vault_call "$(jq -nc '{_func:"shred_principal",principal_id:"no-such-principal",confirm:"no-such-principal"}')"
expect_status 404 "client shred of an unknown principal is a 404"
fetch "$R_P3"; expect_status 200 "nothing destroyed by the refused requests"

erasure "$(jq -nc --arg p "$P4" '{_func:"place_legal_hold",principal_id:$p,reason:"Case review",case_ref:"CASE-2"}')"
HOLD4="$(jqr '.hold_id')"
vault_call "$(jq -nc --arg p "$P4" '{_func:"shred_principal",principal_id:$p,confirm:$p}')"
expect_status 409 "client shred is refused while a legal hold is open"
erasure "$(jq -nc --argjson h "$HOLD4" '{_func:"release_legal_hold",hold_id:$h}')"

vault_call "$(jq -nc --arg p "$P3" '{_func:"shred_principal",principal_id:$p,confirm:$p}')"
expect_status 200 "client shred of P3"
expect_jq '.state' SHREDDED "P3 is SHREDDED"
fetch "$R_P3"; expect_status 410 "erased record reads as 410"
vault_call_as "$RO_KEY" "$RO_SECRET" "$(jq -nc --arg p "$P3" '{_func:"get_erasure_certificate",principal_id:$p}')"
expect_status 200 "key with read access can fetch the certificate"
expect_jq '.destroyed | length' 1 "client certificate lists the destroyed record"
erasure '{"_func":"get_erasure_register"}'
expect_jq "[.register[] | select(.principal_id==\"$P3\" and .requested_by==\"VAULT:$RW_KEY\")] | length" 1 "console register records the client API key as the requester"

section "Shred remaining"
erasure "$(jq -nc --arg p "$P2" '{_func:"shred_principal",principal_id:$p,confirm:$p}')"
expect_jq '.state' SHREDDED "P2 is SHREDDED"
fetch "$R_P2"; expect_status 410 "P2 record erased"
erasure "$(jq -nc --arg r "$R_DATED" '{_func:"shred_record",reference_key:$r,confirm:$r}')"
expect_status 409 "single record under policy hold is refused"
erasure "$(jq -nc --arg r "$R_LOOSE" '{_func:"shred_record",reference_key:$r,confirm:$r}')"
expect_status 200 "single record without principal shredded"
fetch "$R_LOOSE"; expect_status 410 "single shredded record reads as erased"

summary
