#!/usr/bin/env bash
# Builds the war, starts it with a throwaway PostgreSQL (db/*.sql applied), creates two admins and
# runs the setup, store-fetch, search, access, validation, utilities and erasure example scripts against it. Needs docker, mvn, curl and jq.
# Uses its own network and containers, and removes them afterwards.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN="$$"
NET="tsi-vault-e2e-net-$RUN"
DBC="tsi-vault-e2e-db-$RUN"
APPC="tsi-vault-e2e-app-$RUN"
IMAGE="tsi-vault-e2e:$RUN"
PORT="${E2E_PORT:-$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')}"
DB=tsi_privacy_vault
DBUSER=tsi_admin
DBPASS="e2e-$RUN"
SETUP_TOKEN="e2e-setup-token-$RUN"
ADMIN_EMAIL="admin@e2e.test"; ADMIN_PASSWORD="E2e-Admin-$RUN-pass"
VIEWER_EMAIL="viewer@e2e.test"; VIEWER_PASSWORD="E2e-Viewer-$RUN-pass"
BASE="http://127.0.0.1:${PORT}"

cleanup() {
    docker rm -f "$APPC" "$DBC" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    docker rmi "$IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$ROOT"
mvn -B -q -DskipTests package

docker build -q -t "$IMAGE" -f Dockerfile . >/dev/null
docker network create "$NET" >/dev/null
docker run -d --name "$DBC" --network "$NET" \
    -e POSTGRES_DB="$DB" -e POSTGRES_USER="$DBUSER" -e POSTGRES_PASSWORD="$DBPASS" \
    -v "$ROOT/db:/docker-entrypoint-initdb.d:ro" postgres:16 >/dev/null

echo "Waiting for PostgreSQL..."
for _ in $(seq 1 60); do
    # the init scripts restart the server once, so wait until the real one answers
    if docker exec "$DBC" psql -U "$DBUSER" -d "$DB" -tAc "select 1 from vault_key_ring limit 1" >/dev/null 2>&1; then break; fi
    sleep 1
done

docker run -d --name "$APPC" --network "$NET" --user root -p "127.0.0.1:${PORT}:8080" \
    -e POSTGRES_HOST="jdbc:postgresql://${DBC}:5432" -e POSTGRES_DB="$DB" \
    -e POSTGRES_USER="$DBUSER" -e POSTGRES_PASSWD="$DBPASS" \
    -e TSI_PRIVACY_VAULT_ENV=e2e -e TSI_PRIVACY_VAULT_NODE_ID=E2E_NODE \
    -e TSI_PRIVACY_VAULT_MASTER_KEY=0123456789abcdef0123456789abcdef \
    -e TSI_PRIVACY_VAULT_JWT_SECRET=e2e-jwt-secret-0123456789abcdef0123 \
    -e TSI_PRIVACY_VAULT_INDEX_SECRET=e2e-index-secret-0123456789abcdef \
    -e TSI_PRIVACY_VAULT_BOOTSTRAP_TOKEN="$SETUP_TOKEN" \
    -e TSI_PRIVACY_VAULT_MAX_UPLOAD_KB=5120 -e TSI_EXPORT_PATH=/tmp/ \
    -e TSI_PRIVACY_VAULT_ERASURE_JOB_MINUTES=0 \
    "$IMAGE" >/dev/null

echo "Waiting for the vault..."
for _ in $(seq 1 90); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/index.html" || true)"
    [ "$code" = "200" ] && break
    sleep 1
done
[ "$code" = "200" ] || { echo "vault did not start"; docker logs "$APPC" | tail -40; exit 1; }

post() { curl -sS -H 'Content-Type: application/json' "$@"; }

echo "Creating admins..."
post "$BASE/api/admin/setup" -d "$(jq -nc --arg e "$ADMIN_EMAIL" --arg p "$ADMIN_PASSWORD" --arg t "$SETUP_TOKEN" \
    '{_func:"create_user",username:"e2e-admin",email:$e,password:$p,role:"SYSTEM_ADMIN",active:true,setup_token:$t}')" >/dev/null
TOKEN="$(post "$BASE/api/admin/login" -d "$(jq -nc --arg e "$ADMIN_EMAIL" --arg p "$ADMIN_PASSWORD" '{_func:"admin_login",email:$e,password:$p}')" | jq -r .token)"
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || { echo "admin login failed"; docker logs "$APPC" | tail -40; exit 1; }
post "$BASE/api/admin/user" -H "Authorization: Bearer $TOKEN" -d "$(jq -nc --arg e "$VIEWER_EMAIL" --arg p "$VIEWER_PASSWORD" \
    '{_func:"create_user",username:"e2e-viewer",email:$e,password:$p,role:"AUDIT_VIEWER",active:true}')" >/dev/null

export BASE_URL="$BASE" ADMIN_EMAIL ADMIN_PASSWORD VIEWER_EMAIL VIEWER_PASSWORD
FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"; cleanup' EXIT
EX="$ROOT/examples/scripts"
export FIXTURES_FILE="$FIX/fixtures.env" LOAD_PROPS_FILE="$FIX/load.properties"

fail=0
run() { echo; echo "##### $1"; "$@" || fail=1; }
run "$EX/setup/setup-test-fixtures.sh"
run "$EX/store-fetch/test-store-fetch.sh"
run "$EX/search/test-blind-index-search.sh"
run "$EX/access/test-access-control.sh"
run "$EX/validation/test-entity-validation.sh"
run "$EX/utilities/test-utilities.sh"
run "$EX/erasure/test-erasure.sh"

echo; echo "##### roles, audit chain and the erasure console"
VIEWER_TOKEN="$(post "$BASE/api/admin/login" -d "$(jq -nc --arg e "$VIEWER_EMAIL" --arg p "$VIEWER_PASSWORD" '{_func:"admin_login",email:$e,password:$p}')" | jq -r .token)"
status() { # token body url -> HTTP status
    curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -H "Authorization: Bearer $1" -d "$2" "$3"
}
expect() { # description actual expected
    if [ "$2" = "$3" ]; then echo "  PASS  $1"; else echo "  FAIL  $1 (got $2, want $3)"; fail=1; fi
}
expect "viewer cannot create an entity" "$(status "$VIEWER_TOKEN" '{"_func":"create_entity","entity_code":"E2E_ROLE_PROBE","entity_name":"probe","flavor":"DATA","active":true}' "$BASE/api/admin/entity")" 403
expect "viewer cannot create a user" "$(status "$VIEWER_TOKEN" '{"_func":"list_users"}' "$BASE/api/admin/user")" 403
expect "viewer cannot activate a key anchor" "$(status "$VIEWER_TOKEN" '{"_func":"activate_key_anchor","anchor_type":"LOCAL"}' "$BASE/api/admin/keyanchor")" 403
expect "viewer can read entities" "$(status "$VIEWER_TOKEN" '{"_func":"get_all_entities"}' "$BASE/api/admin/entity")" 200
expect "viewer can read the erasure register" "$(status "$VIEWER_TOKEN" '{"_func":"get_erasure_register"}' "$BASE/api/admin/erasure")" 200

CHAIN="$(post "$BASE/api/admin/audit" -H "Authorization: Bearer $VIEWER_TOKEN" -d '{"_func":"verify_audit_chain"}')"
echo "$CHAIN" | jq -c .
expect "audit chain verifies for a viewer" "$(echo "$CHAIN" | jq -r .valid)" true
HEAD_SEQ="$(echo "$CHAIN" | jq -r .head_seq)"; HEAD_HASH="$(echo "$CHAIN" | jq -r .head_hash)"
expect "audit chain matches a recorded head" "$(post "$BASE/api/admin/audit" -H "Authorization: Bearer $VIEWER_TOKEN" \
    -d "$(jq -nc --argjson s "$HEAD_SEQ" --arg h "$HEAD_HASH" '{_func:"verify_audit_chain",expected_head_seq:$s,expected_head_hash:$h}')" | jq -r .valid)" true
expect "audit chain rejects a wrong head" "$(post "$BASE/api/admin/audit" -H "Authorization: Bearer $VIEWER_TOKEN" \
    -d "$(jq -nc --argjson s "$HEAD_SEQ" '{_func:"verify_audit_chain",expected_head_seq:$s,expected_head_hash:"0000000000000000000000000000000000000000000000000000000000000000"}')" | jq -r .valid)" false

ACT="$(post "$BASE/api/admin/audit" -H "Authorization: Bearer $TOKEN" \
    -d '{"_func":"get_audit_logs","operationPrefixes":["ERASURE_","LEGAL_HOLD_"],"size":5}')"
expect "erasure activity is queryable by prefix" "$(echo "$ACT" | jq -r '(.totalElements // 0) >= 1')" true
DEN="$(post "$BASE/api/admin/audit" -H "Authorization: Bearer $TOKEN" \
    -d '{"_func":"get_audit_logs","operationPrefixes":["ADMIN_ENTITY:"],"outcome":"DENIED","size":5}')"
expect "a role refusal is in the audit log" "$(echo "$DEN" | jq -r '(.totalElements // 0) >= 1')" true
REG="$(post "$BASE/api/admin/erasure" -H "Authorization: Bearer $VIEWER_TOKEN" -d '{"_func":"get_erasure_register"}')"
expect "the register lists the erased principals" "$(echo "$REG" | jq -r '(.register | length) >= 1')" true

COOKIES="$(mktemp)"
curl -s -o /dev/null -c "$COOKIES" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg e "$ADMIN_EMAIL" --arg p "$ADMIN_PASSWORD" '{_func:"admin_login",email:$e,password:$p}')" "$BASE/api/admin/login"
expect "erasure console page redirects without a session" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/erasure.html")" 302
expect "erasure console page is served with a session" "$(curl -s -o /dev/null -w '%{http_code}' -b "$COOKIES" "$BASE/erasure.html")" 200
expect "erasure console page is the monitor" "$(curl -s -b "$COOKIES" "$BASE/erasure.html" | grep -c 'Erasure Monitor')" 1
rm -f "$COOKIES"

echo; echo "##### dashboard file storage"
DASH="$(post "$BASE/api/admin/dashboard" -H "Authorization: Bearer $TOKEN" -d '{"_func":"get_dashboard_stats"}')"
echo "$DASH" | jq -c .file_storage
check() { # description jq-filter expected
    if [ "$(echo "$DASH" | jq -r "$2")" = "$3" ]; then echo "  PASS  $1"; else echo "  FAIL  $1"; fail=1; fi
}
check "dashboard reports the DATABASE backend" '.file_storage.backend' DATABASE
check "dashboard reports it healthy" '.file_storage.healthy' true
check "dashboard counts FILE records in the database" '(.file_storage.files_by_backend.DATABASE // 0) >= 1' true

if [ "$fail" != 0 ]; then echo "--- app log tail"; docker logs "$APPC" 2>&1 | tail -40; fi
exit $fail
