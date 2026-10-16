#!/usr/bin/env bash
# Runs the FileStore contract test against a throwaway MinIO container (TLS).
# Needs docker, openssl, keytool, curl and mvn. Nothing is written outside a temp dir.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
NAME="tsi-vault-minio-test-$$"
# A free port, unless one is forced with MINIO_TEST_PORT.
PORT="${MINIO_TEST_PORT:-$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')}"
BUCKET="vault-contract-test"
ACCESS="vaulttestaccess"
SECRET="vaulttestsecret-$(openssl rand -hex 8)"
# minio/minio is no longer published on Docker Hub; any image whose entrypoint is `minio` works.
MINIO_IMAGE="${MINIO_IMAGE:-cgr.dev/chainguard/minio:latest}"
TRUST_PASS="changeit"

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# Self-signed certificate for localhost, trusted only by the test JVM.
mkdir -p "$WORK/certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout "$WORK/certs/private.key" -out "$WORK/certs/public.crt" 2>/dev/null
chmod 644 "$WORK/certs/private.key"
keytool -importcert -noprompt -alias minio -file "$WORK/certs/public.crt" \
    -keystore "$WORK/truststore.jks" -storepass "$TRUST_PASS" >/dev/null

# A top-level directory under the data root is a bucket, so no mc client is needed.
mkdir -p "$WORK/data/$BUCKET"
chmod -R 777 "$WORK/data"

# Run as the host user so the temp dir can be removed afterwards.
docker run -d --user "$(id -u):$(id -g)" --name "$NAME" -p "127.0.0.1:${PORT}:9000" \
    -e MINIO_ROOT_USER="$ACCESS" -e MINIO_ROOT_PASSWORD="$SECRET" \
    -v "$WORK/certs:/certs:ro" -v "$WORK/data:/data" \
    "$MINIO_IMAGE" server /data --certs-dir /certs >/dev/null

echo "Waiting for MinIO..."
for _ in $(seq 1 30); do
    if curl -fsS --cacert "$WORK/certs/public.crt" "https://localhost:${PORT}/minio/health/ready" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
curl -fsS --cacert "$WORK/certs/public.crt" "https://localhost:${PORT}/minio/health/ready" >/dev/null \
    || { echo "MinIO did not become ready"; docker logs "$NAME"; exit 1; }

cd "$ROOT"
TSI_TEST_S3_ENDPOINT="https://localhost:${PORT}" \
TSI_TEST_S3_BUCKET="$BUCKET" \
AWS_ACCESS_KEY_ID="$ACCESS" \
AWS_SECRET_ACCESS_KEY="$SECRET" \
mvn -B -Dtest='S3FileStoreMinioTest' \
    -DargLine="-Djavax.net.ssl.trustStore=$WORK/truststore.jks -Djavax.net.ssl.trustStorePassword=$TRUST_PASS" \
    test
