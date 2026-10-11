#!/usr/bin/env bash
# Checks that entity rules are enforced when storing:
#   - ID value must match the entity regex
#   - entityType must match the entity flavor
#   - FILE bytes must match the accepted MIME types
#   - file content must match its extension
#   - missing file name is rejected
#   - oversized payloads are rejected
# It also checks that invalid entity definitions are rejected by the admin API.
#
# Requires: curl, jq, base64. Run setup/setup-test-fixtures.sh first.
# The definition checks need ADMIN_TOKEN, and are skipped when it is not set.
#
# Usage:
#   ./test-entity-validation.sh
#   ADMIN_TOKEN=<jwt> ./test-entity-validation.sh

set -uo pipefail
. "$(dirname "$0")/../common.sh"
require_cmds
load_fixtures
require_client_env
: "${ID_ENTITY:?Set ID_ENTITY}" "${DATA_ENTITY:?Set DATA_ENTITY}" "${FILE_ENTITY:?Set FILE_ENTITY}"

store() { # flavor entity content [fileName]
  vault_call "$(jq -nc --arg t "$1" --arg e "$2" --arg c "$3" --arg f "${4:-}" \
    '{_func:"store_data",entityType:$t,entityName:$e,content:$c} + (if $f=="" then {} else {fileName:$f} end)')"
}

section "Preflight"
# One value that breaks the ID regex. An instance that stores it is not running the
# build with entity rules, so the remaining checks would only create junk data.
store ID "$ID_ENTITY" "$(b64 'not-a-number')"
if [ "$HTTP_STATUS" = "201" ]; then
  echo "  This instance accepted a value that breaks the entity regex."
  echo "  It is probably running an older build without entity rules."
  echo "  Rebuild and redeploy (see examples/README.md), then run this script again."
  exit 2
fi
pass "instance rejects a value that breaks the entity regex"

PDF_B64="$(b64 $'%PDF-1.4\n%%EOF\n')"
PNG_B64="$(printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' | base64 | tr -d '\n')"
EXE_B64="$(printf 'MZ\x90\x00\x03\x00\x00\x00' | base64 | tr -d '\n')"

section "Value format (ID entity, regex ^[0-9]{12}\$)"
store ID "$ID_ENTITY" "$(b64 '123456789012')"
expect_status 201 "12 digits accepted"
store ID "$ID_ENTITY" "$(b64 '12345')"
expect_status 422 "5 digits rejected"
store ID "$ID_ENTITY" "$(b64 '123456789012x')"
expect_status 422 "trailing character rejected"

section "Flavor"
store FILE "$ID_ENTITY" "$PDF_B64" "a.pdf"
expect_status 400 "FILE sent to an ID entity is rejected"
store DATA "$FILE_ENTITY" "$(b64 'hello')"
expect_status 400 "DATA sent to a FILE entity is rejected"

section "File type (FILE entity accepts application/pdf and image/png)"
store FILE "$FILE_ENTITY" "$PDF_B64" "report.pdf"
expect_status 201 "PDF accepted"
store FILE "$FILE_ENTITY" "$PNG_B64" "scan.png"
expect_status 201 "PNG accepted"
store FILE "$FILE_ENTITY" "$EXE_B64" "report.pdf"
expect_status 415 "executable renamed to .pdf rejected"
store FILE "$FILE_ENTITY" "$PNG_B64" "report.pdf"
expect_status 415 "PNG named .pdf rejected (extension mismatch)"
store FILE "$FILE_ENTITY" "$(b64 'just some text')" "notes.txt"
expect_status 415 "plain text rejected (type not accepted)"

section "File name and encoding"
store FILE "$FILE_ENTITY" "$PDF_B64"
expect_status 400 "missing fileName rejected"
store FILE "$FILE_ENTITY" "not base64 !!" "a.pdf"
expect_status 400 "content that is not Base64 rejected"
store FILE "$FILE_ENTITY" "$PDF_B64" "../../etc/report.pdf"
expect_status 201 "path in fileName is stripped, not rejected"
REF="$(jqr '.reference_key')"
vault_call "$(jq -nc --arg r "$REF" '{_func:"fetch_data","reference-key":$r}')"
expect_jq '.fileName' "report.pdf" "stored file name has no path"

section "Size limit"
# 64 KB over the limit (MAX_UPLOAD_KB, default 5120), sent as a DATA value.
MAX_KB="${MAX_UPLOAD_KB:-5120}"
BIG="$(head -c $((MAX_KB * 1024 + 65536)) /dev/zero | tr '\0' 'a' | base64 | tr -d '\n')"
# Built with printf, because Base64 is JSON safe and the value is too big for a command argument.
vault_call "$(printf '{"_func":"store_data","entityType":"DATA","entityName":"%s","content":"%s"}' "$DATA_ENTITY" "$BIG")"
expect_status 413 "payload over the limit rejected"

section "Entity definitions (admin API)"
if [ -z "${ADMIN_TOKEN:-}" ]; then
  echo "  SKIP  ADMIN_TOKEN not set"
else
  def() { # code flavor regex mime
    admin_call entity "$(jq -nc --arg c "$1" --arg f "$2" --arg r "$3" --arg m "$4" \
      '{_func:"create_entity",active:true,entity_code:$c,entity_name:"validation example",flavor:$f,validation_regex:$r,mime_types:$m}')"
  }
  def "EX_BAD_FLAVOR" "BLOB" "" ""
  expect_status 400 "unknown flavor rejected"
  def "EX_BAD_REGEX" "ID" "([a-z" ""
  expect_status 400 "regex that does not compile rejected"
  def "EX_FILE_NO_MIME" "FILE" "" ""
  expect_status 400 "FILE entity without MIME types rejected"
  def "EX_BAD_MIME" "FILE" "" "pdf"
  expect_status 400 "MIME type without a slash rejected"
  def "bad code!" "ID" "" ""
  expect_status 400 "entity code with unsafe characters rejected"
fi

summary
