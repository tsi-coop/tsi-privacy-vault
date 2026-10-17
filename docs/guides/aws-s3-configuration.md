# AWS S3 Configuration Guide

> Before this: you have a working integration, and have defined a `FILE` entity ([Entities](entity-management.md)). This is a production step, and files are kept in PostgreSQL without it. All guides: [where to start](README.md).

How to store `FILE` records in AWS S3 instead of PostgreSQL. This is the storage backend described in
[Storage backends](../design/architecture.md#storage-backends-next-pluggable-file-storage).
Payload encryption is unchanged: files are encrypted inside the vault process with
their own data key, and only the ciphertext is uploaded. A bucket breach, a wrong
ACL or a cloud operator therefore sees nothing readable.

Only the `FILE` flavour moves. `ID` and `DATA` values stay in PostgreSQL.

---

## 1. Prerequisites

- A running TSI Privacy Vault with `db/02_file_storage.sql` applied. Fresh installs
  get it automatically. On an existing database:
  ```bash
  psql -U tsi_admin -d tsi_privacy_vault -f db/02_file_storage.sql
  ```
  If you also use erasure by principal, apply `db/03_erasure.sql` as well.
- An AWS account and permission to create buckets and IAM policies.
- Decide the region first. A bucket in another region or jurisdiction changes where
  personal data physically sits. It must match your data residency commitments.

## 2. Create the bucket

In the AWS Console, using an account-admin identity:

1. Go to **S3 -> Create bucket**. Pick the region from step 1.
   Enter a **Bucket name**. Bucket names are globally unique across all of AWS, so
   `my-vault-files` will usually be taken. Use something specific to you, for
   example `acme-vault-files-prod`. **Write down the exact bucket name and region.**
   You will use them in steps 3 and 5.
2. Leave **Block all public access** on.
3. Turn on **Bucket Versioning**. The database backup no longer restores external
   files by itself, so versioning (or cross-region replication) is what lets you
   recover them. See [Backup and recovery](#8-backup-recovery-and-erasure).
4. Under **Default encryption**, choose SSE-S3 or SSE-KMS. This is defense in depth.
   The vault's own encryption is what protects the data.
5. Optional: use one bucket for several vaults and separate them with the key
   prefix in step 5.

## 3. Minimal IAM policy

> **Where this goes.** This is an *identity-based* policy. Create it under
> **IAM -> Policies -> Create policy -> JSON**, then attach it to the role or user the
> vault runs as (step 4). Do **not** paste it into the bucket's **Permissions ->
> Bucket policy** editor. That editor requires a `Principal` field and fails with
> `Missing required field Principal`.

### 3.1 Replace the placeholders

The policy below contains three placeholders in `<ANGLE_BRACKETS>`. Replace all of
them, including the brackets, before saving.

| Placeholder | Replace with | Example |
|---|---|---|
| `<YOUR_BUCKET_NAME>` | The exact bucket name from step 2 | `acme-vault-files-prod` |
| `<YOUR_PREFIX>` | The key prefix, or remove the `/<YOUR_PREFIX>` part if you use none | `vault-prod` |

The prefix must match `TSI_PRIVACY_VAULT_S3_PREFIX` in step 5. If you set no prefix,
use `arn:aws:s3:::<YOUR_BUCKET_NAME>/*` for the first resource.

### 3.2 The policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TsiPrivacyVaultObjects",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::<YOUR_BUCKET_NAME>/<YOUR_PREFIX>/*"
    },
    {
      "Sid": "TsiPrivacyVaultBucket",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::<YOUR_BUCKET_NAME>"
    }
  ]
}
```

With the example values above, the two `Resource` lines become:

```
"Resource": "arn:aws:s3:::acme-vault-files-prod/vault-prod/*"
"Resource": "arn:aws:s3:::acme-vault-files-prod"
```

Name the policy `tsi-privacy-vault-s3` and create it.

### 3.3 What each permission does

- `PutObject` stores a file on every upload.
- `GetObject` reads a file on fetch.
- `DeleteObject` removes the object when a record is erased, and cleans up after a
  failed store. Without it, erasure still destroys the key, but the object stays in
  the bucket and the erasure job keeps retrying.
- `ListBucket` is used by the boot health check (`HeadBucket`). It also makes S3
  report a missing object as "not found" instead of "access denied", which the
  vault relies on to tell a missing file from a permissions problem. Do not add a
  `s3:prefix` condition to it, because `HeadBucket` carries no prefix and would be
  refused.

### 3.4 Attach it

Attach the policy to the identity from step 4 (instance role, task role, IRSA role
or dedicated IAM user).

## 4. Credentials

The vault uses the AWS SDK **default credential chain**. No S3 secrets are read from
vault-specific configuration. In order of preference:

| Deployment | Mechanism |
|---|---|
| EC2 | Instance profile (IAM role) attached to the instance |
| ECS / EKS | Task role / IRSA service account |
| Anywhere else | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in `.env` |

If you must use static keys, create a dedicated IAM user that has **only** the policy
from step 3, and rotate the keys regularly. If you also use the AWS KMS anchor, the
same identity can hold both policies. See the
[AWS KMS Configuration Guide](aws-kms-configuration.md).

`docker-compose.yml` already passes the `AWS_*` variables through to the container.

## 5. Configure the vault

Edit `.env` (template in `.example`). Use the same bucket name, region and prefix as
in steps 2 and 3, and do not leave the `<...>` placeholders or the `# e.g.` comments on
the value lines:

```bash
TSI_PRIVACY_VAULT_FILE_STORE=AWS_S3
TSI_PRIVACY_VAULT_S3_BUCKET=<YOUR_BUCKET_NAME>     # e.g. acme-vault-files-prod
TSI_PRIVACY_VAULT_S3_REGION=<YOUR_BUCKET_REGION>   # e.g. ap-south-1

# Optional: lets one bucket serve several vaults. A trailing slash is added if missing.
# Must match <YOUR_PREFIX> in the IAM policy (step 3).
#TSI_PRIVACY_VAULT_S3_PREFIX=<YOUR_PREFIX>/        # e.g. vault-prod/

# Static credentials only if no IAM role is available (see step 4)
#AWS_ACCESS_KEY_ID=...
#AWS_SECRET_ACCESS_KEY=...
```

| Variable | Meaning |
|---|---|
| `TSI_PRIVACY_VAULT_FILE_STORE` | `DATABASE` (default) or `AWS_S3` |
| `TSI_PRIVACY_VAULT_S3_BUCKET` | Target bucket. Required |
| `TSI_PRIVACY_VAULT_S3_REGION` | Bucket region. Required |
| `TSI_PRIVACY_VAULT_S3_PREFIX` | Optional key prefix |
| `TSI_PRIVACY_VAULT_S3_ENDPOINT` | Optional custom endpoint, for example an AWS VPC endpoint. HTTPS only. Leave unset normally |

Apply the configuration:

```bash
sudo docker compose up -d --force-recreate jetty_app
```

## 6. Verify

1. **Log.** The application log shows:
   ```
   File store health check passed: backend=AWS_S3
   ```
2. **Dashboard.** The **File Storage** card on the dashboard shows `AWS S3`, your
   bucket and region, a green Healthy indicator, and the count of files per backend.
3. **Round trip.** Store a file from the Data Client tour page or with
   `examples/scripts/store-fetch/test-store-fetch.sh`, then fetch it back and compare.
4. **Bucket.** The new object is named by the record's `reference_key` (an opaque
   UUID), under your prefix. The file name and entity code never appear in the key.
   The bytes are ciphertext and cannot be opened without the vault.

## 7. How it behaves

- **New files only.** The setting applies to `FILE` records stored after the change.
  Existing files stay in PostgreSQL and keep reading from there. Each row records its
  own backend, so database and S3 records coexist.
- **Integrity.** The vault stores the SHA-256 of each object. A missing object or a
  hash mismatch on read returns HTTP 500 "Stored file failed its integrity check"
  and is written to `event_log`. It is never returned as a silent bad read.
- **Order of writes.** The object is uploaded first, then the row is inserted. A
  failure in between leaves an orphan object, never a row pointing at nothing. The
  vault deletes the orphan when it can.
- **Upload limits.** The Base64 JSON upload contract and
  `TSI_PRIVACY_VAULT_MAX_UPLOAD_KB` are unchanged. Streaming and multipart uploads
  are not part of this release.
- **Fail closed.** If the bucket is unreachable at boot, the data plane returns 503
  with "Vault file store unavailable". While unhealthy, the vault re-checks at most
  every 30 seconds, so it recovers on its own once the bucket is back. A bucket
  outage mid run fails only the records stored there.

## 8. Backup, recovery and erasure

- **Two systems now.** A database backup alone no longer restores external files. Pair
  it with bucket versioning or replication, and keep them on a comparable schedule.
  Restoring the database without the bucket leaves rows pointing at missing objects,
  which read as integrity failures.
- **Erasure.** Shredding a principal destroys the wrapped key first, in its own
  commit, so the object is unreadable ciphertext immediately. The object is then
  deleted. With versioning on, the delete only adds a delete marker and older
  versions remain until a lifecycle rule expires them. They stay unreadable, because
  the key is gone, but add a lifecycle rule for noncurrent versions so the bytes do
  not sit there indefinitely.
- **Residency.** Replication or a bucket in another region moves personal data across
  that boundary. Check it against your commitments before turning either on.

## 9. Switching back to the database

Set `TSI_PRIVACY_VAULT_FILE_STORE=DATABASE` and restart. New files go to PostgreSQL.
Files already in S3 keep reading from the bucket, so **keep the S3 settings in
`.env` and keep the bucket** until nothing references it. The dashboard's
**Files By Backend** count shows when that is true. Moving existing files between
backends is not built yet.

## 10. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `503 Vault file store unavailable: ... is not set` | `TSI_PRIVACY_VAULT_S3_BUCKET` or `_S3_REGION` is missing |
| `503 ...: TSI_PRIVACY_VAULT_S3_ENDPOINT must use https` | Endpoint starts with `http://`. Use HTTPS |
| Health check fails with `NoSuchBucket` (404) | Wrong bucket name, or the bucket is in another account |
| Health check fails with `403` | The identity lacks `s3:ListBucket` on the bucket, or the bucket policy denies it |
| Health check fails with a redirect or region error | `TSI_PRIVACY_VAULT_S3_REGION` does not match the bucket's region |
| Store returns `503 File storage backend unavailable` | `PutObject` was refused or the bucket is unreachable. Check the IAM policy and the application log |
| Fetch returns `500 ... failed its integrity check` | The object is missing or was modified. Check bucket versioning, lifecycle rules and whether the database was restored without the bucket |
| Files still read from the database after the change | Expected. Only files stored after the change go to S3 |
