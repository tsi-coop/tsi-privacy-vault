#!/usr/bin/env bash
# Creates throwaway test fixtures through the admin API:
#   - three entities: one ID (12 digit number), one DATA, one FILE (PDF and PNG only)
#   - one read/write client key with access to those entities
#   - one read-only client key with access to the DATA entity
#   - two utilities (a KEYS secret and a CERT), readable by the read/write key; the read-only
#     key can read the KEYS utility only
#   - one seeded ID record and tests/load-test.local.properties, ready for the JMeter plan
# Credentials are written to .fixtures.env next to this script, or to FIXTURES_FILE. The other
# example scripts read that file automatically.
#
# Use a local or staging instance only. Never production, never real personal data.
#
# Requires: curl, jq, base64.
#
# Usage:
#   ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD=<password> ./setup-test-fixtures.sh
#
# Environment:
#   BASE_URL        Default http://localhost:8081
#   ADMIN_EMAIL     Admin account email
#   ADMIN_PASSWORD  Admin account password
#   PREFIX          Entity code and utility label prefix. Default EX
#   LOAD_PROPS_FILE JMeter properties output. Default tests/load-test.local.properties
#
# Running it again is safe:
#   - Entities that already exist are reused.
#   - If .fixtures.env holds working credentials they are reused. Set FORCE=1 to
#     create new keys instead.
#   - If .fixtures.env holds a malformed key (for example from an earlier failed
#     run), its permission rows are removed and new keys are created.
#
# If ADMIN_PASSWORD is not set, the script asks for it without echoing, so the
# password does not end up in your shell history.

set -uo pipefail
. "$(dirname "$0")/../common.sh"
require_cmds

: "${ADMIN_EMAIL:?Set ADMIN_EMAIL}"
if [ -z "${ADMIN_PASSWORD:-}" ]; then
  if [ -t 0 ]; then
    read -rsp "Admin password for $ADMIN_EMAIL: " ADMIN_PASSWORD
    echo
  else
    echo "Set ADMIN_PASSWORD, or run in a terminal to be prompted." >&2
    exit 1
  fi
fi
PREFIX="${PREFIX:-EX}"
OUT="${FIXTURES_FILE:-$(dirname "$0")/.fixtures.env}"

# Credentials from an earlier run, if any.
OLD_KEY=""; OLD_SECRET=""; OLD_RO_KEY=""; OLD_RO_SECRET=""
if [ -f "$OUT" ]; then
  eval "$(. "$OUT" >/dev/null 2>&1
    printf 'OLD_KEY=%q OLD_SECRET=%q OLD_RO_KEY=%q OLD_RO_SECRET=%q' \
      "${API_KEY:-}" "${API_SECRET:-}" "${RO_API_KEY:-}" "${RO_API_SECRET:-}")"
fi

section "Admin login"
http_post "$BASE_URL/api/admin/login" \
  "$(jq -nc --arg e "$ADMIN_EMAIL" --arg p "$ADMIN_PASSWORD" '{_func:"admin_login",email:$e,password:$p}')"
ADMIN_TOKEN="$(jqr '.token')"
if [ "$HTTP_STATUS" != "200" ] || [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
  fail "admin login"
  exit 1
fi
pass "admin login"

create_entity() { # code name flavor regex mime
  admin_call entity "$(jq -nc --arg c "$1" --arg n "$2" --arg f "$3" --arg r "$4" --arg m "$5" \
    '{_func:"create_entity",active:true,entity_code:$c,entity_name:$n,flavor:$f,validation_regex:$r,mime_types:$m}')"
  if [ "$HTTP_STATUS" = "200" ]; then
    pass "created entity $1"
  elif [ "$HTTP_STATUS" = "409" ] || printf '%s' "$BODY" | grep -qi 'duplicate key'; then
    pass "entity $1 already exists"
  else
    fail "create entity $1"
    exit 1
  fi
}

section "Entities"
ID_ENTITY="${PREFIX}_ID_NUMBER"
DATA_ENTITY="${PREFIX}_NOTE"
FILE_ENTITY="${PREFIX}_DOCUMENT"
UTILITY_LABEL="${PREFIX}_SERVICE_KEY"
UTILITY_CERT_LABEL="${PREFIX}_TLS_CERT"
create_entity "$ID_ENTITY"   "Example ID number"  "ID"   '^[0-9]{12}$' ''
create_entity "$DATA_ENTITY" "Example note"       "DATA" ''            ''
create_entity "$FILE_ENTITY" "Example document"   "FILE" ''            'application/pdf,image/png'

# create_client LABEL -> sets CLIENT_KEY and CLIENT_SECRET. Runs in this shell, so a
# failure stops the script. create_key answers 201, so accept 200 or 201.
create_client() {
  admin_call apikey "$(jq -nc --arg l "$1" '{_func:"create_key",label:$l,active:true}')"
  CLIENT_KEY="$(jqr '.data.api_key_id')"
  CLIENT_SECRET="$(jqr '.data.raw_api_secret')"
  if { [ "$HTTP_STATUS" != "200" ] && [ "$HTTP_STATUS" != "201" ]; } \
     || [ -z "$CLIENT_KEY" ] || [ "$CLIENT_KEY" = "null" ] \
     || [ -z "$CLIENT_SECRET" ] || [ "$CLIENT_SECRET" = "null" ]; then
    fail "create key $1"
    exit 1
  fi
}

grant() { # key entity read write
  admin_call permission "$(jq -nc --arg k "$1" --arg e "$2" --argjson r "$3" --argjson w "$4" \
    '{_func:"create_permission",api_key:$k,resource_type:"ENTITY",resource_id:$e,can_read:$r,can_write:$w,granted_by:"examples"}')"
  # create_permission answers 201 Created
  if { [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]; } && [ "$(jqr '._success')" = "true" ]; then
    pass "granted $2 (read=$3 write=$4) to ${1:0:8}..."
  else
    fail "grant $2"
    exit 1
  fi
}

# purge_permissions KEY: removes every permission row for a key
purge_permissions() {
  local ids id
  admin_call permission "$(jq -nc --arg k "$1" '{_func:"get_permissions_by_key",api_key:$k}')"
  ids="$(jqr '.permissions[]?.permission_id')"
  for id in $ids; do
    admin_call permission "$(jq -nc --argjson i "$id" '{_func:"delete_permission",permission_id:$i}')"
  done
  [ -n "$ids" ] && printf '  removed %s permission row(s) for key %s\n' "$(printf '%s\n' "$ids" | wc -l | tr -d ' ')" "${1:0:12}"
  return 0
}

# deactivate_example_keys: client names are unique, and a secret cannot be read back, so keys
# from earlier runs are switched off before new ones are created.
deactivate_example_keys() {
  local rows k label
  admin_call apikey '{"_func":"get_all_keys"}'
  rows="$(printf '%s' "$BODY" | jq -c '.keys[]? | select(.active==true and (.label|startswith("examples ")))' 2>/dev/null)"
  while IFS= read -r k; do
    [ -z "$k" ] && continue
    label="$(printf '%s' "$k" | jq -r '.label')"
    admin_call apikey "$(printf '%s' "$k" | jq -c '{_func:"update_key",api_key_id:.api_key_id,label:.label,active:false}')"
    printf '  deactivated earlier key "%s"\n' "$label"
  done <<<"$rows"
}

REUSE=0
if [ -n "$OLD_KEY" ]; then
  section "Existing fixtures"
  if ! [[ "$OLD_KEY" =~ ^[A-F0-9]{32}$ ]]; then
    echo "  saved key is malformed ('${OLD_KEY:0:12}'), discarding it"
    purge_permissions "$OLD_KEY"
  elif [ "${FORCE:-0}" = "1" ]; then
    echo "  FORCE=1, creating new keys"
  else
    vault_call_as "$OLD_KEY" "$OLD_SECRET" '{"_func":"get_authorized_entities"}'
    if [ "$HTTP_STATUS" = "200" ]; then
      vault_call_as "$OLD_RO_KEY" "$OLD_RO_SECRET" '{"_func":"get_authorized_entities"}'
    fi
    if [ "$HTTP_STATUS" = "200" ]; then
      REUSE=1
      pass "saved credentials still work, reusing them"
    else
      echo "  saved credentials no longer work, creating new keys"
    fi
  fi
fi

if [ "$REUSE" = "1" ]; then
  RW_KEY="$OLD_KEY"; RW_SECRET="$OLD_SECRET"
  RO_KEY="$OLD_RO_KEY"; RO_SECRET="$OLD_RO_SECRET"
else
  section "Client keys"
  deactivate_example_keys
  STAMP="$(date -u +%Y%m%d-%H%M%S)"
  create_client "examples read-write $STAMP"
  RW_KEY="$CLIENT_KEY"; RW_SECRET="$CLIENT_SECRET"
  pass "created read-write key ${RW_KEY:0:8}..."
  grant "$RW_KEY" "$ID_ENTITY"   true true
  grant "$RW_KEY" "$DATA_ENTITY" true true
  grant "$RW_KEY" "$FILE_ENTITY" true true

  create_client "examples read-only $STAMP"
  RO_KEY="$CLIENT_KEY"; RO_SECRET="$CLIENT_SECRET"
  pass "created read-only key ${RO_KEY:0:8}..."
  grant "$RO_KEY" "$DATA_ENTITY" true false
fi


# enroll_utility LABEL CATEGORY PAYLOAD. Labels are unique, so an existing one is reused.
enroll_utility() {
  admin_call utility "$(jq -nc --arg l "$1" --arg c "$2" --arg p "$3" \
    '{_func:"enroll",label:$l,category:$c,payload:$p}')"
  if [ "$HTTP_STATUS" = "200" ] && [ -n "$(jqr '.utility_id // empty')" ]; then
    pass "enrolled utility $1 ($2)"
  elif printf '%s' "$BODY" | grep -qi 'duplicate key\|already exists'; then
    pass "utility $1 already exists"
  else
    fail "enroll utility $1"
    exit 1
  fi
}

# grant_utility KEY LABEL read write. The resource id of a utility permission is its label.
grant_utility() {
  admin_call permission "$(jq -nc --arg k "$1" --arg e "$2" --argjson r "$3" --argjson w "$4" \
    '{_func:"create_permission",api_key:$k,resource_type:"UTILITY",resource_id:$e,can_read:$r,can_write:$w,granted_by:"examples"}')"
  if { [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]; } && [ "$(jqr '._success')" = "true" ]; then
    pass "granted utility $2 (read=$3 write=$4) to ${1:0:8}..."
  else
    fail "grant utility $2"
    exit 1
  fi
}

# Utilities and their grants are idempotent, so they run whether or not the keys were reused.
section "Utilities"
enroll_utility "$UTILITY_LABEL"      KEYS "example-service-key-$(date -u +%s)"
enroll_utility "$UTILITY_CERT_LABEL" CERT "-----BEGIN CERTIFICATE-----
EXAMPLEONLYNOTAREALCERTIFICATE
-----END CERTIFICATE-----"
grant_utility "$RW_KEY" "$UTILITY_LABEL"      true true
grant_utility "$RW_KEY" "$UTILITY_CERT_LABEL" true true
grant_utility "$RO_KEY" "$UTILITY_LABEL"      true false


# Seed one record so the load test search stage hits a real index entry, then write a JMeter
# properties file from the committed template with this run's credentials filled in.
section "Load test properties"
SEED_VALUE="$(date +%s)00"   # 12 digits, matches the ID entity regex
vault_call_as "$RW_KEY" "$RW_SECRET" "$(jq -nc --arg e "$ID_ENTITY" --arg c "$(b64 "$SEED_VALUE")" \
  '{_func:"store_data",entityType:"ID",entityName:$e,content:$c}')"
if [ "$HTTP_STATUS" = "201" ]; then
  pass "seeded search record"
else
  fail "seed search record"
  exit 1
fi
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
TEMPLATE="$REPO_ROOT/tests/load-test.properties"
LOAD_PROPS="${LOAD_PROPS_FILE:-$REPO_ROOT/tests/load-test.local.properties}"
if [ -f "$TEMPLATE" ]; then
  umask 077
  sed -e "s|^base.url=.*|base.url=$BASE_URL|" \
      -e "s|^api.key=.*|api.key=$RW_KEY|" \
      -e "s|^api.secret=.*|api.secret=$RW_SECRET|" \
      -e "s|^entity.code=.*|entity.code=$ID_ENTITY|" \
      -e "s|^entity.type=.*|entity.type=ID|" \
      -e "s|^search.term=.*|search.term=$SEED_VALUE|" \
      -e "s|^utility.id=.*|utility.id=$UTILITY_LABEL|" \
      "$TEMPLATE" > "$LOAD_PROPS"
  pass "wrote $LOAD_PROPS"
else
  echo "  $TEMPLATE not found, skipping load test properties"
fi

umask 077
cat > "$OUT" <<ENV
# Written by setup-test-fixtures.sh. Test credentials only.
export BASE_URL="$BASE_URL"
export ADMIN_TOKEN="$ADMIN_TOKEN"
export API_KEY="$RW_KEY"
export API_SECRET="$RW_SECRET"
export RO_API_KEY="$RO_KEY"
export RO_API_SECRET="$RO_SECRET"
export ID_ENTITY="$ID_ENTITY"
export DATA_ENTITY="$DATA_ENTITY"
export FILE_ENTITY="$FILE_ENTITY"
export UTILITY_LABEL="$UTILITY_LABEL"
export UTILITY_CERT_LABEL="$UTILITY_CERT_LABEL"
ENV
echo
echo "Wrote $OUT"
summary
