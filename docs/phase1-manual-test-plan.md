# Manual Test Plan - Phase 0/1 Key Management (LOCAL + AWS KMS Anchor)

Covers milestones M0-M2 of docs/roadmap.md: provider factory, key-version
metadata, fail-closed boot gate, hardened AWS KMS anchor, anchor activation
and the DEK re-wrap migration.

## Conventions

- Base URL: `http://localhost:8081` (compose maps `APP_PORT_MAP`, default 8081).
- `$JWT` = admin Bearer token obtained in step A3.
- `$APIKEY` = a client API key with READ/WRITE on the test entity.
- DB shell:
  `docker exec -it tsi_privacy_vault_db psql -U tsi_admin -d tsi_privacy_vault`

---

## A. Phase 0 regression - LOCAL anchor (no AWS involved)

### A1. Fresh install schema

```bash
sudo docker compose down -v        # wipes postgres_data; destroys all data - test envs only
sudo docker compose up -d
```

- [ ] Postgres logs show `00_init.sql` then `01_key_management.sql` executed (in that order).
- [ ] `SELECT * FROM vault_key_ring;` returns exactly one row:
      `key_version=1, anchor_type=LOCAL, cipher=AES_CBC_PKCS5, status=ACTIVE`.
- [ ] `\d vault_entities` and `\d vault_utilities` show `key_version` (default 1)
      and `payload_cipher` (default `AES_CBC_PKCS5`).

### A2. Upgrade path (existing database)

On a pre-existing volume, init scripts do not re-run. Apply manually:

```bash
docker exec -i tsi_privacy_vault_db psql -U tsi_admin -d tsi_privacy_vault \
  < db/01_key_management.sql
```

- [ ] Script is idempotent: running it twice produces no errors and still one ACTIVE row.
- [ ] Pre-existing `vault_entities` rows show `key_version=1, payload_cipher=AES_CBC_PKCS5`.

### A3. Boot health check (healthy path)

- [ ] App log contains `KMS health check passed: anchor=LOCAL key_version=1`.
- [ ] Admin login works:

```bash
curl -s http://localhost:8081/api/admin/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"<admin-email>","password":"<password>"}'
# capture token -> JWT
```

### A4. Fail closed - missing master key

1. In `.env`, comment out `TSI_PRIVACY_VAULT_MASTER_KEY`; also remove the
   compose default for this test (edit `docker-compose.yml` fallback to empty).
2. `sudo docker compose up -d --force-recreate jetty_app`

- [ ] App log: `CRITICAL: KMS health check failed - data plane disabled: TSI_PRIVACY_VAULT_MASTER_KEY is not set...`
- [ ] `event_log` has a row: `who=SYSTEM, operation_type=KMS_HEALTH_CHECK, outcome=ERROR`.
- [ ] Data plane refuses (503):

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8081/api/client/vault \
  -H "X-API-Key: $APIKEY" -H 'Content-Type: application/json' \
  -d '{"_func":"get_authorized_entities"}'
# expect 503
```

- [ ] Admin login (control plane) still returns 200.
- [ ] Restore the env var, recreate the container, verify health passes again.

### A5. Store/fetch round trip and version stamping

```bash
# store
curl -s http://localhost:8081/api/client/vault \
  -H "X-API-Key: $APIKEY" -H 'Content-Type: application/json' \
  -d '{"_func":"store_data","entityType":"ID","entityName":"<ENTITY_CODE>","content":"TEST-9912-3456"}'
# capture reference_key

# fetch
curl -s http://localhost:8081/api/client/vault \
  -H "X-API-Key: $APIKEY" -H 'Content-Type: application/json' \
  -d '{"_func":"fetch_data","reference-key":"<reference_key>"}'
```

- [ ] Fetch returns the original value.
- [ ] DB row: `SELECT key_version, payload_cipher FROM vault_entities WHERE entity_ref='<reference_key>';`
      shows `1, AES_CBC_PKCS5`.
- [ ] Search (`search_data`) still finds the record.

### A6. Utility lifecycle (admin + client)

- [ ] Admin `enroll` a utility (admin UI or `/api/admin/utility`), then `checkout`
      returns the cleartext; DB row shows `key_version=1, payload_cipher=AES_CBC_PKCS5`.
- [ ] `rotate` the utility; checkout returns the new payload.
- [ ] Client `resolve_utility` via `/api/client/vault` returns the secret.

### A7. Key anchor status endpoint

```bash
curl -s http://localhost:8081/api/admin/keyanchor \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"_func":"get_key_anchor_status"}'
```

- [ ] `healthy=true`, `active_key_version=1`, `configured_anchor=LOCAL`,
      `key_ring` lists v1, `pending_rewrap` counts are 0.

---

## B. Phase 1 - AWS KMS anchor

Run against a real AWS account **or** LocalStack. For LocalStack, add the
container to the compose network and create a key:

```bash
docker run -d --name localstack --network tsi-privacy-vault_tsi_internal \
  -p 4566:4566 localstack/localstack
docker exec localstack awslocal kms create-key --description "tsi-vault-test"
# capture KeyId
```

`.env` for this section:

```
TSI_PRIVACY_VAULT_KMS_PROVIDER=AWS_KMS
TSI_PRIVACY_VAULT_AWS_REGION=us-east-1            # or your region
TSI_PRIVACY_VAULT_AWS_KMS_KEY_ID=<key ARN or alias ARN>
TSI_PRIVACY_VAULT_AWS_ENDPOINT=http://localstack:4566   # LocalStack only; unset for real AWS
AWS_ACCESS_KEY_ID=test                            # LocalStack only; IAM role for real AWS
AWS_SECRET_ACCESS_KEY=test
```

Recreate the app container after editing `.env`.

### B1. Pre-activation state

- [ ] Boot log shows health check passed for anchor LOCAL **plus** the warning:
      `WARN: TSI_PRIVACY_VAULT_KMS_PROVIDER=AWS_KMS differs from active key ring anchor LOCAL...`
- [ ] Store one record now (it will be the "legacy" record for migration tests);
      note its `reference_key`.

### B2. Activate the AWS anchor

```bash
curl -s http://localhost:8081/api/admin/keyanchor \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"_func":"activate_key_anchor","anchor_type":"AWS_KMS"}'
```

- [ ] Response: `success=true, key_version=2, anchor_type=AWS_KMS, cipher=AES_GCM`.
- [ ] `vault_key_ring`: v1 now `DECRYPT_ONLY`, v2 `ACTIVE` with `anchor_ref` = key ARN.
- [ ] `event_log` has `ACTIVATE_KEY_ANCHOR:AWS_KMS:v2` with `outcome=SUCCESS`.
- [ ] App log shows a fresh `KMS health check passed: anchor=AWS_KMS key_version=2`.
- [ ] (Real AWS) CloudTrail shows `GenerateDataKey`/`Decrypt` with encryption
      context `vault_node_id=<TSI_PRIVACY_VAULT_NODE_ID>`.

### B3. Mixed-version reads and writes

- [ ] Store a new record: DB row shows `key_version=2, payload_cipher=AES_GCM`;
      fetch returns the value.
- [ ] Fetch the B1 legacy record (`key_version=1`): still decrypts correctly
      (CBC payload, locally-wrapped DEK).
- [ ] Enroll + checkout a new utility: row shows v2/GCM; resolve_utility works
      from the client API.
- [ ] `get_key_anchor_status`: `pending_rewrap` shows the count of v1 rows.

### B4. Re-wrap migration

```bash
curl -s http://localhost:8081/api/admin/keyanchor \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"_func":"rewrap_data_keys","batch_size":100}'
# repeat until remaining_entities=0 and remaining_utilities=0
```

- [ ] Counts decrease monotonically across calls; the job is resumable (safe to
      stop/restart the app between batches).
- [ ] Final call reports `retired_old_versions=true`; `vault_key_ring` v1 = `RETIRED`.
- [ ] Migrated legacy rows: `key_version=2` but `payload_cipher` still
      `AES_CBC_PKCS5` (payload untouched - only the wrapped DEK changed).
- [ ] Legacy record from B1 still fetches correctly after re-wrap.
- [ ] `event_log` has `REWRAP_DATA_KEYS:v2:...` entries with `outcome=SUCCESS`.

### B5. Retire the local master key

1. Remove `TSI_PRIVACY_VAULT_MASTER_KEY` from `.env` (and the compose fallback).
2. Recreate the app container.

- [ ] Health check passes (AWS anchor needs no local key).
- [ ] All records - including pre-migration ones - still fetch correctly.

### B6. Failure-path tests

- [ ] **Bad key id:** set `TSI_PRIVACY_VAULT_AWS_KMS_KEY_ID` to a nonexistent
      ARN, recreate, attempt `activate_key_anchor` from a LOCAL-active state →
      400 with `Anchor AWS_KMS failed verification`, `event_log` `outcome=ERROR`.
- [ ] **KMS outage while active:** with AWS_KMS active, stop LocalStack (or
      detach network), recreate the app → boot health check fails, data plane
      returns 503, admin login still works, `event_log` records the failure.
- [ ] **Recovery without restart:** restore KMS, then call
      `get_key_anchor_status` → it re-runs the health check, returns
      `healthy=true`, and the data plane serves traffic again.
- [ ] **Retired-version guard:** after B4, manually set one row back to
      `key_version=1` in SQL and fetch it → request fails with the
      `key_version 1 is RETIRED` error (proves retired anchors are fenced).
      Restore the row afterwards.

### B7. Validation guards

- [ ] `activate_key_anchor` with `anchor_type":"GCP_KMS"` → 400 schema validation error.
- [ ] `rewrap_data_keys` with `batch_size: 0` → 400 schema validation error.
- [ ] `keyanchor` calls without `Authorization` header → 401.

---

## C. Sign-off matrix

| Area | Test | Result |
|---|---|---|
| Schema | A1, A2 | |
| Fail-closed boot | A4, B6 | |
| LOCAL regression | A5, A6 | |
| Anchor activation | B2 | |
| Mixed-version reads | B3 | |
| Re-wrap migration | B4, B5 | |
| Forensics | A4, B2, B4, B6 (event_log rows) | |
