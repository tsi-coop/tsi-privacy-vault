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
- An AWS account and permission to create KMS keys and IAM policies. This is
  an account-admin identity (root user or an IAM admin role) - not the
  vault's own runtime credentials, which stay least-privilege (see step 3).
- Admin credentials for the vault console - steps 6-7 are done on the
  **Key Anchor** page (`keyanchor.html`) in the admin console.

## 2. Create the KMS key

In the AWS Console, using an account-admin identity:

1. Go to **KMS -> Customer managed keys -> Create key**.
2. Key type: **Symmetric**. Key usage: **Encrypt and decrypt**.
3. Use the same region as the vault deployment (e.g. `ap-south-1`) to
   minimize latency.
4. Add an alias, e.g. `tsi-privacy-vault`, for readability.
5. On the **Define key administrative permissions** / **Define key usage
   permissions** pages, accept the defaults (the account root keeps `kms:*`
   via IAM). **Do not paste the policy JSON from step 3 here** - that is an
   IAM identity policy meant for the vault's runtime role, not a KMS key
   policy. Key policies require a `Principal` on every statement, so reusing
   that JSON as the key policy fails with `MalformedPolicyDocumentException:
   Policy contains a statement with no principal`.
6. On the key's detail page, enable **Automatic key rotation** - it is
   transparent to the vault (old ciphertext remains decryptable; no re-wrap
   needed).
7. Record the **key ARN** (or alias ARN) shown on the detail page. You will
   configure it in step 5.

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

In the IAM console, create this policy and attach it to the identity the
vault runs as (step 4).

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
Once you see this WARN, the vault is ready - proceed straight to step 6 to
activate the anchor (no further restart is needed for activation itself).

### A note on the encryption context

Every KMS call binds ciphertext to this vault instance with the encryption
context `vault_node_id=<TSI_PRIVACY_VAULT_NODE_ID>`. This enriches CloudTrail
and prevents wrapped keys from being decrypted by another deployment.

**Do not change `TSI_PRIVACY_VAULT_NODE_ID` after activating the AWS anchor** -
KMS will refuse to unwrap keys whose context no longer matches
(`InvalidCiphertextException`). If you must rename a node, restore the old
value, re-wrap is not sufficient; treat it as an anchor migration.

## 6. Activate the AWS anchor

**Timing**: do this once step 5 is applied and the container has restarted -
the `WARN: ... Run activate_key_anchor to migrate` log line is your cue that
the vault is ready. Activation switches the wrapping anchor for **new**
writes immediately; existing records stay readable under the old version
until step 7 re-wraps them.

Log in to the admin console and open the **Key Anchor** page:

1. **Configured Anchor** should already read `AWS_KMS` (from step 5), while
   the **Key Ring** table still shows version 1 as `LOCAL` / `ACTIVE` - that
   gap is exactly what activation closes.
2. Click **Activate Anchor**, choose anchor type `AWS_KMS`, check "I
   understand this will change the live encryption key ring", and confirm.
3. The page calls `activate_key_anchor`, which first runs a GenerateDataKey +
   Decrypt round trip against the AWS CMK - nothing changes if that fails.

A successful activation creates key version 2 (`AWS_KMS`, `AES_GCM`,
`ACTIVE`) and demotes version 1 to `DECRYPT_ONLY`, both visible immediately in
the Key Ring table.

If activation fails with "Anchor AWS_KMS failed verification", see
Troubleshooting (step 9) - nothing has been changed in the key ring.

## 7. Migrate existing records (re-wrap)

Still on the **Key Anchor** page, use the **Rewrap Data Keys** card. This
re-wraps only the ~48-byte wrapped data key per row - payload ciphertext is
untouched, so it's cheap and safely resumable:

1. Leave **Batch Size** at 500 (or raise it, up to 5000).
2. Click **Run Batch**. Repeat until the result shows `Remaining Entities: 0`
   and `Remaining Utilities: 0` ("All data keys re-wrapped.") - the
   **Pending Re-wrap** stat card at the top tracks the same counts.
3. The final pass also retires key version 1, shown as `RETIRED` in the Key
   Ring table.

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
| Data plane returns 503 `Vault key anchor unavailable` | Boot health check failed (KMS unreachable, credentials expired). Fix the cause, then click **Refresh** on the Key Anchor page - it re-runs the check and reopens the data plane without a restart. |
| `AccessDeniedException` in logs | IAM policy not attached, or missing `kms:Encrypt` during re-wrap (step 3). |
| `AccessDeniedException ... not authorized to perform: kms:CreateKey` | The signed-in identity is the vault's least-privilege runtime user, not an account admin. Use an account-admin identity in the console for step 2, then attach the step 3 policy to the runtime identity. |
| `MalformedPolicyDocumentException: Policy contains a statement with no principal` on `CreateKey` | The step 3 IAM policy was pasted into the key's policy field during step 2. Key policies require a `Principal` per statement; accept the default key policy in step 2 and attach the step 3 policy to the runtime identity separately. |
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
