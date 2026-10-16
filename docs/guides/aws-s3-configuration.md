# AWS S3 Configuration Guide

How to store `FILE` records in AWS S3, or in an S3-compatible object store such as
MinIO or Ceph, instead of PostgreSQL. This is the storage backend described in
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
- An AWS account and permission to create buckets and IAM policies, or an
  S3-compatible service reachable over HTTPS.
- Decide the region first. A bucket in another region or jurisdiction changes where
  personal data physically sits. It must match your data residency commitments.

## 2. Create the bucket

In the AWS Console, using an account-admin identity:

1. Go to **S3 -> Create bucket**. Pick the region from step 1.
2. Leave **Block all public access** on.
3. Turn on **Bucket Versioning**. The database backup no longer restores external
   files by itself, so versioning (or cross-region replication) is what lets you
   recover them. See [Backup and recovery](#9-backup-recovery-and-erasure).
4. Under **Default encryption**, choose SSE-S3 or SSE-KMS. This is defense in depth.
   The vault's own encryption is what protects the data.
5. Optional: use one bucket for several vaults and separate them with the key
   prefix in step 5.

## 3. Minimal IAM policy

The vault needs object read, write and delete on the one bucket (or prefix), and
`s3:ListBucket` on the bucket itself:

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
      "Resource": "arn:aws:s3:::my-vault-files/vault-prod/*"
    },
    {
      "Sid": "TsiPrivacyVaultBucket",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::my-vault-files"
    }
  ]
}
```

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

Replace `my-vault-files` and `vault-prod/` with your bucket and prefix. Leave the
prefix out of the resource if you do not set one.

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

Edit `.env` (template in `.example`):

```bash
TSI_PRIVACY_VAULT_FILE_STORE=AWS_S3
TSI_PRIVACY_VAULT_S3_BUCKET=my-vault-files
TSI_PRIVACY_VAULT_S3_REGION=ap-south-1

# Optional: lets one bucket serve several vaults. A trailing slash is added if missing.
#TSI_PRIVACY_VAULT_S3_PREFIX=vault-prod/

# Static credentials only if no IAM role is available (see step 4)
#AWS_ACCESS_KEY_ID=...
#AWS_SECRET_ACCESS_KEY=...
```

| Variable | Meaning |
|---|---|
| `TSI_PRIVACY_VAULT_FILE_STORE` | `DATABASE` (default), `AWS_S3` or `S3_COMPATIBLE` |
| `TSI_PRIVACY_VAULT_S3_BUCKET` | Target bucket. Required for both S3 backends |
| `TSI_PRIVACY_VAULT_S3_REGION` | Bucket region. Required for both S3 backends |
| `TSI_PRIVACY_VAULT_S3_PREFIX` | Optional key prefix |
| `TSI_PRIVACY_VAULT_S3_ENDPOINT` | Custom endpoint. Required for `S3_COMPATIBLE`. HTTPS only |

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

## 8. S3-compatible stores (MinIO, Ceph, on-prem)

For an on-prem object store, set the selector to `S3_COMPATIBLE` and give it an
endpoint:

```bash
TSI_PRIVACY_VAULT_FILE_STORE=S3_COMPATIBLE
TSI_PRIVACY_VAULT_S3_ENDPOINT=https://minio.internal:9000
TSI_PRIVACY_VAULT_S3_BUCKET=vault-files
TSI_PRIVACY_VAULT_S3_REGION=us-east-1
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

- The endpoint **must be HTTPS**. An `http://` endpoint, even on a private network,
  fails the file store health check, so the data plane returns 503.
- With an endpoint set, the vault uses path-style addressing
  (`https://host/bucket/key`), which most on-prem stores expect.
- Create the bucket and an access key yourself. The vault never creates buckets.
- Use `us-east-1` as the region if your store does not care about it. The value must
  still be set.
- A private CA or a self-signed certificate must be trusted by the vault's JVM. Add
  it to the Java truststore of the container, or mount a truststore and start the
  JVM with `-Djavax.net.ssl.trustStore=<path>`.

`AWS_S3` also accepts `TSI_PRIVACY_VAULT_S3_ENDPOINT`, for example for a VPC endpoint
or LocalStack.

## 9. Backup, recovery and erasure

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

## 10. Switching back to the database

Set `TSI_PRIVACY_VAULT_FILE_STORE=DATABASE` and restart. New files go to PostgreSQL.
Files already in S3 keep reading from the bucket, so **keep the S3 settings in
`.env` and keep the bucket** until nothing references it. The dashboard's
**Files By Backend** count shows when that is true. Moving existing files between
backends is not built yet.

## 11. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `503 Vault file store unavailable: ... is not set` | `TSI_PRIVACY_VAULT_S3_BUCKET` or `_S3_REGION` is missing |
| `503 ...: TSI_PRIVACY_VAULT_S3_ENDPOINT must use https` | Endpoint starts with `http://`. Use HTTPS |
| `503 ...: TSI_PRIVACY_VAULT_S3_ENDPOINT is required for S3_COMPATIBLE` | Selector is `S3_COMPATIBLE` with no endpoint |
| Health check fails with `NoSuchBucket` (404) | Wrong bucket name, or the bucket is in another account |
| Health check fails with `403` | The identity lacks `s3:ListBucket` on the bucket, or the bucket policy denies it |
| Health check fails with a redirect or region error | `TSI_PRIVACY_VAULT_S3_REGION` does not match the bucket's region |
| Store returns `503 File storage backend unavailable` | `PutObject` was refused or the bucket is unreachable. Check the IAM policy and the application log |
| Fetch returns `500 ... failed its integrity check` | The object is missing or was modified. Check bucket versioning, lifecycle rules and whether the database was restored without the bucket |
| `PKIX path building failed` in the log | The store's certificate is not trusted by the JVM. See step 8 |
| Files still read from the database after the change | Expected. Only files stored after the change go to S3 |

## 12. Testing

`tests/runners/run-minio-contract.sh` runs the backend contract tests against a
throwaway MinIO container over TLS. See [tests/README.md](../../tests/README.md).
