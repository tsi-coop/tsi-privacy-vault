# AWS KMS Configuration Guide

How to anchor the TSI Privacy Vault to an AWS KMS Customer Managed Key (CMK),
per Phase 1 of [the key management roadmap](roadmap.md). After this setup, every
record's data key is wrapped by AWS KMS instead of the local Master Key, while
payload encryption and decryption still happen locally - AWS never sees your data.

Manual verification steps for this whole flow are in
[phase1-manual-test-plan.md](phase1-manual-test-plan.md) (Section B).

---

## 1. Prerequisites

- A running TSI Privacy Vault with the Phase 0/1 release (the `vault_key_ring`
  table exists - see `db/01_key_management.sql`).
- An AWS account and permission to create KMS keys and IAM policies.
- Admin credentials for the vault console (to call the `keyanchor` API).
- AWS CLI v2 (only needed for the CLI snippets below).

## 2. Create the KMS key

Console: *KMS -> Customer managed keys -> Create key* with key type
**Symmetric**, usage **Encrypt and decrypt**. Or via CLI:

```bash
aws kms create-key \
  --description "TSI Privacy Vault root key anchor" \
  --key-spec SYMMETRIC_DEFAULT \
  --key-usage ENCRYPT_DECRYPT \
  --region ap-south-1
# note the KeyId / Arn in the output

# Optional but recommended: a stable alias
aws kms create-alias \
  --alias-name alias/tsi-privacy-vault \
  --target-key-id <KeyId> \
  --region ap-south-1
```

Recommendations:

- Create the key in the same region as the vault deployment to minimize latency.
- Enable automatic key rotation - it is transparent to the vault (old ciphertext
  remains decryptable; no re-wrap needed):

```bash
aws kms enable-key-rotation --key-id <KeyId> --region ap-south-1
```

- Record the **key ARN** (or alias ARN). You will configure it in step 5.

## 3. Minimal IAM policy

The vault needs exactly three KMS actions, scoped to the single key:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TsiPrivacyVaultKmsAnchor",
      "Effect": "Allow",
      "Action": [
        "kms:GenerateDataKey",
        "kms:Decrypt",
        "kms:Encrypt"
      ],
      "Resource": "arn:aws:kms:ap-south-1:<account-id>:key/<key-id>"
    }
  ]
}
```

- `GenerateDataKey` - wrap a fresh data key on every store/enroll.
- `Decrypt` - unwrap data keys on fetch/checkout/resolve.
- `Encrypt` - used only by the `rewrap_data_keys` migration job; you may remove
  it after the LOCAL -> AWS_KMS migration completes.

Attach the policy to the identity the vault runs as (step 4).

## 4. Credentials

The vault uses the AWS SDK **default credential chain** - no AWS secrets are
read from vault-specific configuration. Pick one, in order of preference:

| Deployment | Mechanism |
|---|---|
| EC2 | Instance profile (IAM role) attached to the instance |
| ECS / EKS | Task role / IRSA service account |
| Anywhere else | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in `.env` |

If you must use static keys, create a dedicated IAM user that has **only** the
policy from step 3, set the two variables in `.env`, and rotate them regularly.
The provided `docker-compose.yml` already passes `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` through to the container.

## 5. Configure the vault

Edit `.env` (template in `.example`):

```bash
# Declare intent; the actual switch happens via the admin API in step 6
TSI_PRIVACY_VAULT_KMS_PROVIDER=AWS_KMS
TSI_PRIVACY_VAULT_AWS_REGION=ap-south-1
TSI_PRIVACY_VAULT_AWS_KMS_KEY_ID=arn:aws:kms:ap-south-1:<account-id>:key/<key-id>

# Static credentials only if no IAM role is available (see step 4)
#AWS_ACCESS_KEY_ID=...
#AWS_SECRET_ACCESS_KEY=...
```

Keep `TSI_PRIVACY_VAULT_MASTER_KEY` in place for now - it is still needed to
unwrap existing records until the migration in step 7 finishes.

Apply the configuration:

```bash
sudo docker compose up -d --force-recreate jetty_app
```

Expected in the application log:

```
KMS health check passed: anchor=LOCAL key_version=1
WARN: TSI_PRIVACY_VAULT_KMS_PROVIDER=AWS_KMS differs from active key ring anchor LOCAL. Run activate_key_anchor to migrate.
```

The warning is normal: configuration alone never switches the wrapping anchor.

### A note on the encryption context

Every KMS call binds ciphertext to this vault instance with the encryption
context `vault_node_id=<TSI_PRIVACY_VAULT_NODE_ID>`. This enriches CloudTrail
and prevents wrapped keys from being decrypted by another deployment.

**Do not change `TSI_PRIVACY_VAULT_NODE_ID` after activating the AWS anchor** -
KMS will refuse to unwrap keys whose context no longer matches
(`InvalidCiphertextException`). If you must rename a node, restore the old
value, re-wrap is not sufficient; treat it as an anchor migration.

## 6. Activate the AWS anchor

Log in to the admin console to obtain a JWT, then:

```bash
# 1. Confirm current state
curl -s http://localhost:8081/api/admin/keyanchor \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"_func":"get_key_anchor_status"}'

# 2. Activate (verifies a GenerateDataKey + Decrypt round-trip first)
curl -s http://localhost:8081/api/admin/keyanchor \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"_func":"activate_key_anchor","anchor_type":"AWS_KMS"}'
```

A successful response creates key version 2 (`AWS_KMS`, `AES_GCM`, `ACTIVE`)
and demotes version 1 to `DECRYPT_ONLY`. From this moment all **new** writes
are wrapped by AWS KMS; existing records remain readable under version 1.

If activation returns `Anchor AWS_KMS failed verification`, see
Troubleshooting (step 9) - nothing has been changed in the key ring.

## 7. Migrate existing records (re-wrap)

Re-wraps only the ~48-byte wrapped data key per row; payload ciphertext is
untouched, so this is cheap and safely resumable:

```bash
curl -s http://localhost:8081/api/admin/keyanchor \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"_func":"rewrap_data_keys","batch_size":500}'
```

Repeat until the response shows `remaining_entities=0` and
`remaining_utilities=0`. The final pass reports `retired_old_versions=true`,
marking the LOCAL version `RETIRED`.

## 8. Retire the local Master Key

Once version 1 is `RETIRED`:

1. Remove `TSI_PRIVACY_VAULT_MASTER_KEY` from `.env` (and any compose default).
2. `sudo docker compose up -d --force-recreate jetty_app`
3. Verify the health check passes and a pre-migration record still fetches.

The vault now has no local root key material; the AWS CMK is the sole anchor.

## 9. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `TSI_PRIVACY_VAULT_AWS_KMS_KEY_ID is not set` | Variable missing in `.env` or not passed by compose; recreate the container after editing. |
| `Anchor AWS_KMS failed verification` on activate | Wrong region, bad key ARN, key disabled/pending deletion, or missing IAM permissions. Check CloudTrail for the denied call. |
| Data plane returns 503 `Vault key anchor unavailable` | Boot health check failed (KMS unreachable, credentials expired). Fix the cause, then call `get_key_anchor_status` - it re-runs the check and reopens the data plane without a restart. |
| `AccessDeniedException` in logs | IAM policy not attached, or missing `kms:Encrypt` during re-wrap (step 3). |
| `InvalidCiphertextException` on fetch | Encryption context mismatch - `TSI_PRIVACY_VAULT_NODE_ID` was changed after activation (see step 5), or the wrong CMK/region is configured. |
| Throttling under load | The provider retries 3 times with backoff automatically; sustained throttling needs a KMS quota increase. |
| `key_version N is RETIRED` errors | A row still references a retired version (e.g., restored from an old backup). Re-activate the old anchor temporarily or re-run the re-wrap after setting the version back to `DECRYPT_ONLY` in `vault_key_ring`. |

## 10. Testing without AWS (LocalStack)

For evaluation only - LocalStack keys are not durable or secure:

```bash
docker run -d --name localstack \
  --network tsi-privacy-vault_tsi_internal -p 4566:4566 localstack/localstack

docker exec localstack awslocal kms create-key --description "tsi-vault-test"
```

`.env`:

```bash
TSI_PRIVACY_VAULT_KMS_PROVIDER=AWS_KMS
TSI_PRIVACY_VAULT_AWS_REGION=us-east-1
TSI_PRIVACY_VAULT_AWS_KMS_KEY_ID=<KeyId from create-key>
TSI_PRIVACY_VAULT_AWS_ENDPOINT=http://localstack:4566
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test
```

Then follow steps 6-8 as normal. **Unset `TSI_PRIVACY_VAULT_AWS_ENDPOINT` in
production** - it overrides the real AWS endpoint.
