#!/usr/bin/env bash
# Runs the erasure tests against a throwaway PostgreSQL container with db/*.sql applied.
# Needs docker and mvn. Nothing is written outside the container.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NAME="tsi-vault-erasure-test-$$"
PG_IMAGE="${PG_IMAGE:-postgres:16}"
PORT="${PG_TEST_PORT:-$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')}"
DB=tsi_privacy_vault
USER_NAME=tsi_admin
PASS="erasure-test-$$"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:5432" \
    -e POSTGRES_DB="$DB" -e POSTGRES_USER="$USER_NAME" -e POSTGRES_PASSWORD="$PASS" \
    "$PG_IMAGE" >/dev/null

echo "Waiting for PostgreSQL..."
for _ in $(seq 1 60); do
    if docker exec "$NAME" pg_isready -U "$USER_NAME" -d "$DB" >/dev/null 2>&1 \
       && docker exec "$NAME" psql -U "$USER_NAME" -d "$DB" -c 'select 1' >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Same order as docker-entrypoint-initdb.d
for f in "$ROOT"/db/*.sql; do
    docker exec -i "$NAME" psql -v ON_ERROR_STOP=1 -q -U "$USER_NAME" -d "$DB" < "$f"
done

cd "$ROOT"
TSI_TEST_PG_URL="jdbc:postgresql://localhost:${PORT}/${DB}" \
TSI_TEST_PG_USER="$USER_NAME" \
TSI_TEST_PG_PASSWORD="$PASS" \
POSTGRES_HOST="jdbc:postgresql://localhost:${PORT}" \
POSTGRES_DB="$DB" POSTGRES_USER="$USER_NAME" POSTGRES_PASSWD="$PASS" \
TSI_PRIVACY_VAULT_NODE_ID=ERASURE_TEST \
mvn -B -Dtest="${TEST_CLASS:-ErasureServicePostgresTest}" test
