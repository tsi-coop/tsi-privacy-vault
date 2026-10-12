# TSI Privacy Vault Architecture

This document explains how the vault protects data, how records are searched
without being decrypted, how the root key anchor is managed, and where the key
management design is heading. It is the single reference for design and
roadmap. Operational runbooks live alongside it:

- [aws-kms-configuration.md](aws-kms-configuration.md): step-by-step AWS KMS setup.
- [tests/test-cases.md](../tests/test-cases.md): functional test cases for the key management flows.
- [tests/README.md](../tests/README.md): JMeter load test for the data plane.

## Contents

1. [Overview](#1-overview)
2. [Envelope encryption](#2-envelope-encryption)
3. [Blind index search](#3-blind-index-search)
4. [Key anchors and the key ring](#4-key-anchors-and-the-key-ring)
5. [Request path and fail-closed behavior](#5-request-path-and-fail-closed-behavior)
6. [Forensic evidence](#6-forensic-evidence)
7. [Roadmap](#7-roadmap)

---

## 1. Overview

The vault is a Java servlet application (Jetty) backed by PostgreSQL. Client
applications talk to a small REST data plane; administrators use a separate
admin console and API. Every sensitive value is encrypted before it reaches
the database, and the keys that protect it are themselves protected by a
root key anchor.

| Concern | Mechanism |
|---|---|
| Confidentiality at rest | Per-record Data Encryption Key (DEK), AES encryption done locally |
| Key protection | DEK wrapped by a root key anchor (LOCAL master key or AWS KMS CMK) |
| Searchability | Deterministic keyed hash (blind index), no decryption needed |
| Authentication and authorization | API key and secret (PBKDF2-hashed at rest), then per-entity READ/WRITE permissions |
| Evidence | Every request logged with user, client and machine identity in `event_log` |

### Data flavours

| Flavour | Used for | Handling |
|---|---|---|
| `ID` | Aadhaar, Voter ID, ABHA ID, PAN | Tokenized: the caller gets a `reference_key`, a hash supports lookup by value |
| `DATA` | Names, addresses, medical records | Field-level encryption, blind index for search |
| `FILE` | Contracts, scans | Encrypted binary storage with size and MIME limits |

Utilities (API keys, service credentials, certificates) use the same
encryption machinery and are stored in `vault_utilities`, bound to a machine
identity as a hardware anchor.

### Main components

| Component | Role |
|---|---|
| `api/client/Vault.java` | Data plane: store, fetch, search, resolve |
| `api/admin/*` | Admin plane: login, entities, API keys, permissions, utilities, audit, key anchor |
| `framework/InterceptingFilter.java` | Routing, authentication, and the key anchor health gate |
| `framework/KmsProvider.java` | Contract every anchor implements: `generateDataKey`, `decryptDataKey`, `aesEncrypt`, `aesDecrypt` |
| `framework/KmsProviderFactory.java` | Single source of provider instances and the boot-time health check |
| `framework/VersionedKmsProvider.java` | Routes each record to the anchor that wrapped it, using `key_version` |
| `framework/KeyRing.java` | In-memory view of the `vault_key_ring` table |
| `framework/LocalKmsProvider.java`, `AwsKmsProvider.java` | The two shipped anchors |
| `framework/CipherUtil.java` | AES-GCM for new versions, AES-CBC retained for legacy records |
| `framework/ForensicEngine.java` | Machine identity and audit logging |

---

## 2. Envelope encryption

![Envelope encryption: a locked box inside a bank vault](images/envelope-encryption-diagram.png)

Every record is encrypted with its own one-time Data Encryption Key (DEK). The
DEK is then encrypted ("wrapped") by the root key anchor before it is stored.
The anchor's master key never touches record data directly. It only ever
protects the small keys that do.

**Storing a record**

1. The app asks the anchor for a new data key.
2. The anchor returns the DEK in two forms: plaintext, and wrapped.
3. The app encrypts the payload locally with the plaintext DEK and discards it.
4. The row is written with `encrypted_content` and `encrypted_data_key`,
   plus the `key_version` and `payload_cipher` used.

**Reading a record**

1. The app reads `encrypted_content` and `encrypted_data_key` from the row.
2. It asks the anchor named by the row's `key_version` to unwrap the DEK.
3. It decrypts the payload locally, then discards the DEK from memory.

**Why this matters**

- If the database is stolen, the attacker holds two locked things and no key
  that opens either. Unlocking even one record requires the anchor itself.
- With AWS KMS as the anchor, the anchor only ever sees a wrapped data key of
  about 48 bytes. Your data never leaves the vault process.
- Changing the anchor only re-wraps those small per-record keys. Payload
  ciphertext is never re-encrypted, so migration is cheap and resumable.

### Ciphers

| Cipher | Used for | Notes |
|---|---|---|
| `AES_CBC_PKCS5` | Legacy records (`key_version` 1 under the LOCAL anchor) | Kept readable for backward compatibility |
| `AES_GCM` | All records written under newer key versions | 12-byte nonce, 128-bit tag, authenticated |

The cipher is recorded per row in `payload_cipher`, so old and new records
coexist during migration.

---

## 3. Blind index search

![Blind index: searching data you cannot read](images/blind-index-search-diagram.png)

Encrypted content uses a random IV per record, so it can never be searched
directly. To make lookups possible without decryption, the vault maintains a
separate inverted index of keyed hashes in `vault_search_index`.

**Indexing a record (write time)**

1. The plaintext value is normalized (trimmed, upper-cased).
2. One token is produced per search shape:
   - `FULL`: the whole value.
   - `PART`: each word, when the value has more than one.
   - `PREFIX`: the first three characters.
3. Each token is hashed as `SHA-256(secret + token)`, where the secret is
   `TSI_PRIVACY_VAULT_INDEX_SECRET`, held only in the application environment.
4. A row `(index_hash, entity_ref, attribute_type)` is inserted. The row points
   at the encrypted record but contains no data.

**Searching (query time)**

1. The search term is normalized and hashed with the same secret and recipe.
2. The hash is matched against `vault_search_index.index_hash`, an exact-match
   lookup with no decryption.
3. Matches are filtered through `isAuthorized(apiKey, entity_code)`, which
   drops anything the caller has no READ permission for.
4. The caller receives `reference_key` and `flavor`, not the plaintext. Reading
   the value still needs a fetch and the key unwrap path from section 2.

**Properties**

- The hash is deterministic on purpose: that is what makes equality lookup work.
- Without the index secret, even a correct guess at the plaintext does not
  produce a matching hash, so the index resists offline dictionary attacks.
- Treat `TSI_PRIVACY_VAULT_INDEX_SECRET` as a long-lived secret. Changing it
  invalidates the existing index.

---

## 4. Key anchors and the key ring

A root key anchor is whatever protects the DEKs at rest. The data plane never
knows which anchor is in use. It talks only to `KmsProvider`.

| Anchor | Status | Root key | Best for |
|---|---|---|---|
| `LOCAL` | Shipped (default) | `TSI_PRIVACY_VAULT_MASTER_KEY`, SHA-256 normalized to 32 bytes, held in process memory | Evaluation, on-prem and air-gapped deployments |
| `AWS_KMS` | Shipped in v0.2.0 | AWS KMS Customer Managed Key, never leaves AWS | Production deployments wanting cloud HSM custody, rotation and CloudTrail |
| `GCP_KMS`, `AZURE_KV` | Planned, on demand (Cloud track) | Cloud KMS CryptoKey, Key Vault key | Multi-cloud parity |
| `OPENBAO` | Planned (Sovereign track) | Transit key in a customer-run OpenBao (or HashiCorp Vault) | On-prem and air-gapped deployments that need Shamir unseal, HSM sealing and central key policy |

### LOCAL vs AWS KMS

Out of the box, with no extra setup, the vault runs on the LOCAL anchor: the
master key in your `.env` file. This is what the Docker install gives you, and
it is all you need to evaluate the vault or run it fully on-prem or air-gapped.
AWS KMS is opt-in, a one-time migration you run later if you want the root key
held in an AWS-managed HSM instead of an environment variable. You do not need
AWS at all to use the vault.

| | LOCAL (default) | AWS KMS (opt-in) |
|---|---|---|
| Root key | `TSI_PRIVACY_VAULT_MASTER_KEY` env var (SHA-256 normalized, held in process memory) | AWS KMS Customer Managed Key, never leaves AWS |
| Best for | Local evaluation, air-gapped and on-prem deployments | Production deployments wanting cloud HSM custody, automatic rotation and CloudTrail audit logging |
| Setup | Works out of the box via `.env` | One-time: create the CMK, attach a least-privilege IAM policy, activate the anchor and re-wrap existing records from the Key Anchor page |

Payload ciphertext is always decrypted locally either way. AWS only ever sees a
wrapped data key of about 48 bytes, never your data.

### The key ring

`vault_key_ring` records every anchor generation the vault has used.

| Column | Meaning |
|---|---|
| `key_version` | Serial version number, referenced by every wrapped record |
| `anchor_type` | `LOCAL`, `AWS_KMS`, and future values |
| `anchor_ref` | Cloud key ARN or resource name, `NULL` for local |
| `cipher` | Payload cipher for records written under this version |
| `status` | `ACTIVE`, `DECRYPT_ONLY` or `RETIRED` |

Rules:

- Exactly one version is `ACTIVE` at a time (enforced by a partial unique index).
  It wraps all new DEKs.
- `DECRYPT_ONLY` versions can still unwrap existing records but never wrap new
  ones.
- `RETIRED` versions are no longer referenced by any row.
- `vault_entities` and `vault_utilities` carry `key_version` and
  `payload_cipher`, so each record says which anchor and cipher protect it.

### Switching anchors

1. Configure the new anchor (for AWS KMS: region, key ARN, IAM policy).
2. Activate it from the Key Anchor page (`activate_key_anchor`). The vault
   first performs a `GenerateDataKey` plus `Decrypt` round trip, and only then
   creates the new ACTIVE version and demotes the old one to `DECRYPT_ONLY`.
3. Run the re-wrap job (`rewrap_data_keys`) in batches until nothing is
   pending. Each row's DEK is unwrapped under the old version and wrapped under
   the new one. The final pass retires the old version.
4. Remove the old root key material from the environment.

Existing records stay readable throughout. See
[aws-kms-configuration.md](aws-kms-configuration.md) for the full runbook.

### What re-wrap is, and why it is a separate step

Every record's payload is encrypted with its own one-time DEK, and that DEK is
wrapped by whichever anchor was active when the record was written: LOCAL at
first, AWS KMS once you switch. Re-wrap unwraps each record's DEK under the old
anchor and wraps it under the new one, so old records become readable under the
new anchor too. It touches only that small wrapped key. The payload ciphertext
is never re-encrypted, so re-wrapping a large vault is cheap.

Activation and re-wrap are separate because activating a new anchor only
affects new writes. Existing records keep pointing at the old key version until
you migrate them. Re-wrap does that in batches, resumable, while the vault stays
online, and retires the old version when nothing references it. It runs from
the Key Anchor page (**Rewrap Data Keys**, **Run Batch**) or through the
`rewrap_data_keys` admin API call.

### AWS KMS specifics

- Region and key come from `TSI_PRIVACY_VAULT_AWS_REGION` and
  `TSI_PRIVACY_VAULT_AWS_KMS_KEY_ID`. Credentials use the AWS default chain
  (instance profile, task role, or environment).
- Every KMS call carries the encryption context
  `vault_node_id=<TSI_PRIVACY_VAULT_NODE_ID>`, binding wrapped keys to this
  vault instance and enriching CloudTrail. Do not change the node ID after
  activation.
- A single shared KMS client is built once and reused. Throttling is retried
  with backoff.
- The IAM policy needs only `kms:GenerateDataKey`, `kms:Decrypt` and
  `kms:Encrypt` (the last only for the re-wrap job), scoped to one key.

---

## 5. Request path and fail-closed behavior

`InterceptingFilter` sits in front of every API call.

1. The request path is resolved against the processor registry.
2. Admin endpoints (other than login, reset and setup) require a valid admin
   JWT. Client endpoints require an API key and secret.
3. Data-plane requests (`api/client` and `api/admin/utility`) are rejected with
   `503 Vault key anchor unavailable` while the key anchor health check is
   failing.
4. The request is dispatched to the processor, which enforces per-entity
   permissions through the `permissions` table.

### Boot health gate

At startup, `KmsProviderFactory.healthCheck()` loads the key ring and runs a
`GenerateDataKey` plus `Decrypt` round trip against the ACTIVE anchor.

- On success the data plane opens.
- On failure the data plane stays closed (no degraded read-only mode) and the
  failure is written to `event_log` as `KMS_HEALTH_CHECK` with outcome `ERROR`.
- Admin login and status stay reachable. After fixing the cause, **Refresh** on
  the Key Anchor page re-runs the check and reopens the data plane without a
  restart.

If `TSI_PRIVACY_VAULT_KMS_PROVIDER` differs from the ACTIVE ring anchor, the
vault logs a warning. Configuration alone never changes the wrapping anchor.

---

## 6. Forensic evidence

Every request is recorded in `event_log`: who, operation type, entity code and
reference, client IP, user agent, machine identifier, outcome (`SUCCESS`,
`DENIED`, `ERROR`) and a failure reason. The machine identifier acts as a
hardware anchor, so each action is tied to a user and a device. This is the
basis for the audit trail and the BSA Section 63 certificate output. Key
operations (anchor activation, re-wrap, KMS failures) use the same logging
path.

---

## 7. Roadmap

The vault supports two deployment tracks. Both are supported today. They
evolve independently, and the next phase extends each one.

| Track | For | Shipped today | Next phase |
|---|---|---|---|
| **Sovereign** | On-prem and air-gapped environments, no public cloud | `LOCAL` anchor | `OPENBAO` anchor (Transit) |
| **Cloud** | Deployments that want a managed, HSM-backed root key | `AWS_KMS` anchor | `GCP_KMS` and `AZURE_KV`, added on demand |

A deployment picks one track. Switching tracks later is an anchor migration,
and only the small wrapped DEKs are re-wrapped.

File storage is a third, independent dimension. Where the encrypted bytes of a
`FILE` record live (the database today, or an object store such as S3 or GCS
later) does not depend on which key anchor is active. See
[Storage backends](#storage-backends-next-pluggable-file-storage).

Erasure is a fourth dimension, also independent of the anchor. Linking records
to a principal lets one data principal's records be made unrecoverable without touching
anyone else's. See
[Per-principal keys and crypto-erasure](#compliance-next-per-principal-keys-and-crypto-erasure).

### Status

| Milestone | Track | Contents | Status |
|---|---|---|---|
| M0 | Both | Provider factory, fail-closed local key, key ring schema, AES-GCM, removal of the legacy KMS prototype | Shipped |
| M1 | Cloud | AWS KMS provider: env config, default credential chain, encryption context, health check, retries | Shipped (v0.2.0) |
| M2 | Both | `activate_key_anchor`, LOCAL to AWS re-wrap job, IAM docs, anchor status in the admin console | Shipped (v0.2.0) |
| M3 | Sovereign | OpenBao provider: Transit wrap and unwrap, AppRole auth, TLS, health check, LOCAL to OpenBao re-wrap, runbook | Planned |
| M4 | Cloud | GCP KMS or Azure Key Vault provider, shared cloud provider base class, anchor migration runbook | Planned, on demand |
| M5 | Storage | `FileStore` abstraction, `DATABASE` backend behind it (no behavior change), storage columns, `AWS_S3` and S3-compatible backend, health check | Planned |
| M6 | Storage | `GCS` and `AZURE_BLOB` backends, backend-to-backend migration job, runbook | Planned, on demand |
| M7 | Compliance | Per-principal keys: `principal_id` on store, Erasure Register (`principal_erasures`), resumable `shred` admin operation that destroys all DEKs linked to a principal, erasure certificate | Planned |

The two next-phase key items are independent. They can ship in either order.
Build the cloud provider that a real user asks for first. The shared base class
makes the second one small. The storage milestones (M5 and M6) are independent
of both key tracks. M7 should land before M5 ships external storage, because
the purge path must also delete external objects, and that is easier to build
in than to retrofit.

### Design principles

- Anchors differ only in how DEKs are protected at rest. The data plane is
  anchor-agnostic and talks only to `KmsProvider`.
- Every wrapped DEK records the key version that wrapped it, enabling rotation
  and anchor migration without a one-shot re-encryption.
- Payload ciphertext is never bulk re-encrypted during migration. Only the
  wrapped DEK is re-wrapped.

```
                 +--------------------------------------------+
                 |              Root Key Anchors              |
                 |                                            |
   Shipped  ->   |  LOCAL    : master key from environment    |
   Shipped  ->   |  AWS_KMS  : AWS KMS CMK                    |
   Next     ->   |  GCP_KMS  : Cloud KMS CryptoKey            |
   Next     ->   |  AZURE_KV : Key Vault / Managed HSM key    |
   Next     ->   |  OPENBAO  : OpenBao / Vault Transit key    |
                 +---------------------+----------------------+
                                       | wraps (with key_version)
                                       v
                 +--------------------------------------------+
                 |  Per-record Data Encryption Keys (DEKs)    |
                 |  stored as encrypted_data_key              |
                 +--------------------------------------------+
```

### Phases 0 and 1: delivered

Phase 0 introduced the provider factory, key ring and key version metadata,
the fail-closed boot gate, and AES-GCM for new versions. Phase 1 delivered the
AWS KMS anchor, the activation flow and the resumable re-wrap migration. Their
behavior is described in sections 4 and 5, and the changelog records the
release contents.

Known follow-ups carried over from this work:

- Fold the existing utility `rotate` admin function into the key-version
  mechanism, so that rotation means a new key ring version under the same
  anchor plus re-wrap.
- Keep `TSI_PRIVACY_VAULT_NODE_ID` stable. It is part of the KMS encryption
  context and the utility hardware anchor.

### Cloud track next: Google Cloud KMS and Azure Key Vault

Both reuse the Phase 1 (AWS) machinery: factory, key ring, re-wrap migration, health
checks and forensic logging. Shared concerns move into an
`AbstractCloudKmsProvider` extracted from the AWS provider.

**Google Cloud KMS (`GcpKmsProvider`)**

- Dependency: `com.google.cloud:google-cloud-kms`.
- GCP KMS has no `GenerateDataKey` API. The 32-byte DEK is generated locally
  with `SecureRandom`, then encrypted under the CryptoKey with
  `additionalAuthenticatedData`.
- Config: `TSI_PRIVACY_VAULT_GCP_KMS_KEY_RESOURCE`. Auth through Application
  Default Credentials or workload identity.
- Required role: `roles/cloudkms.cryptoKeyEncrypterDecrypter`.

**Azure Key Vault (`AzureKvProvider`)**

- Dependencies: `com.azure:azure-security-keyvault-keys` and
  `com.azure:azure-identity`.
- The DEK is generated locally and protected with `wrapKey` and `unwrapKey`
  (`RSA-OAEP-256`, or `AES-KW` on Managed HSM for symmetric parity).
- Config: `TSI_PRIVACY_VAULT_AZURE_KEY_ID` (full key identifier URL). Auth
  through `DefaultAzureCredential`, with managed identity preferred.
- Required permissions: `wrapKey` and `unwrapKey` only.

**Packaging.** Adding the GCP and Azure SDKs to the WAR is acceptable at first.
If size becomes a concern, introduce Maven profiles (`-Pkms-aws`, `-Pkms-gcp`,
`-Pkms-azure`) with reflective provider loading so the default build stays lean
and fully sovereign.

**Cross-cloud migration.** Switching anchors (for example AWS_KMS to GCP_KMS)
uses the same flow as section 4: activate a new key ring version, run the
re-wrap job, retire the old version. No payload re-encryption is ever needed.

### Sovereign track next: OpenBao anchor

For on-prem and air-gapped deployments that want the root key outside the
vault process, with unseal workflows, HSM sealing and key policy handled by
infrastructure the customer already runs. OpenBao exposes a Vault-compatible
API, so the same provider should also work with HashiCorp Vault.

**Provider (`OpenBaoKmsProvider`)**

- Uses the Transit secrets engine. The 32-byte DEK is generated locally with
  `SecureRandom`, then wrapped with `POST /v1/<mount>/encrypt/<key>` and
  unwrapped with `POST /v1/<mount>/decrypt/<key>`. Plaintext is base64 on the
  wire.
- The Transit ciphertext (`vault:v<n>:...`) is stored as `encrypted_data_key`.
  The Transit key version travels inside it, so OpenBao-side rotation needs no
  schema change.
- The record's existing encryption context is passed as the Transit `context`
  value when the key is created with derivation enabled.
- Rotation of the Transit key can use the `rewrap` endpoint, which re-wraps a
  DEK inside OpenBao without returning plaintext. Anchor changes use the
  standard re-wrap job from section 4.
- A plain `java.net.http` client is enough. No SDK dependency is needed.

**Configuration**

| Variable | Meaning |
|---|---|
| `TSI_PRIVACY_VAULT_KMS_PROVIDER=OPENBAO` | Selects the anchor |
| `TSI_PRIVACY_VAULT_OPENBAO_ADDR` | Base URL. HTTPS only |
| `TSI_PRIVACY_VAULT_OPENBAO_TRANSIT_MOUNT` | Transit mount path, default `transit` |
| `TSI_PRIVACY_VAULT_OPENBAO_KEY_NAME` | Transit key name |
| `TSI_PRIVACY_VAULT_OPENBAO_CA_CERT` | Path to the CA certificate for private PKI |
| `TSI_PRIVACY_VAULT_OPENBAO_ROLE_ID`, `_SECRET_ID_FILE` | AppRole credentials. The secret ID is read from a file, not from `.env` |

**Security and operations**

- The vault logs in with AppRole, renews its token before expiry, and
  re-authenticates after a failure. The policy grants only `encrypt` and
  `decrypt` on the one Transit key.
- Unseal, HA, backup and audit of OpenBao belong to the operator. If OpenBao is
  sealed or unreachable, unwrap fails and the vault fails closed, the same as
  for AWS KMS. The boot health check surfaces this.
- The vault still holds each plaintext DEK in memory briefly, as it does with
  every anchor. Only the root key stays inside OpenBao.
- For validated hardware, the operator configures an HSM seal on the OpenBao
  side. The vault needs no change.
- Migration from LOCAL or AWS_KMS uses the standard activate and re-wrap flow.

### Storage backends next: pluggable file storage

Today every record, including `FILE` content, is stored encrypted in
PostgreSQL. That stays the default. Large files (contracts, scans) are the
case where a database is a poor fit: they bloat backups and the buffer cache,
and they compete with the connection pool. Deployments that already run an
object store should be able to keep file bytes there instead.

**Principle.** The object store only ever receives ciphertext. Envelope
encryption is unchanged: the DEK is generated and wrapped by the key anchor, the
payload is encrypted in the vault process, and only the result is handed to a
storage backend. A bucket breach, a misconfigured ACL or a cloud operator
therefore exposes nothing readable. Storage-side encryption (SSE-KMS, CMEK) is
defense in depth, never the control the design relies on.

**Backends**

| Backend | Selector | For | Status |
|---|---|---|---|
| Database | `DATABASE` | Default. Small and medium files, simplest operations, one backup covers everything | Shipped (current behavior) |
| AWS S3 | `AWS_S3` | Cloud track | Planned (M5) |
| S3-compatible | `S3_COMPATIBLE` | Sovereign track: MinIO, Ceph RGW, on-prem appliances, via a custom endpoint | Planned (M5, same client as `AWS_S3`) |
| Google Cloud Storage | `GCS` | Cloud track | Planned, on demand (M6) |
| Azure Blob Storage | `AZURE_BLOB` | Cloud track | Planned, on demand (M6) |

Build S3 first. The S3 API is also what most on-prem object stores speak, so
one implementation serves both the Cloud and Sovereign tracks.

**Abstraction (`FileStore`)**

- A small interface used only by the data plane: `put(key, bytes)`,
  `get(key)`, `delete(key)`, `exists(key)`, `health()`. The data plane stays
  backend-agnostic, the same way it is anchor-agnostic.
- A `FileStoreFactory` selects the active backend at boot, mirroring
  `KmsProviderFactory`. Provider SDKs are loaded reflectively behind Maven
  profiles (`-Pstore-s3`, `-Pstore-gcs`, `-Pstore-azure`) so the default build
  stays lean and sovereign.
- The existing database path becomes the `DATABASE` implementation. M5 changes
  no behavior for current deployments.

**Schema and routing**

- Each `vault_entities` row records where its content lives: `storage_backend`
  (default `DATABASE`), `storage_key` (object key or URI) and `content_sha256`.
  For external backends `encrypted_content` holds no payload.
- Reads route by the row's own `storage_backend`, not by the globally active
  one. Old and new records can coexist, which is what makes switching backends
  non-disruptive, the same property `key_version` gives for anchors.
- The object key is an opaque UUID derived from the reference key. File names,
  entity codes and any personal data never appear in object keys or bucket
  metadata. The blind index and the sanitized file name stay in the database.
- Only the `FILE` flavour moves in the first phase. `ID` and `DATA` values are
  small and are indexed together with their row, so they stay in the database.

**Write and read semantics**

- Write order: encrypt, upload the object, then insert the row and index
  entries. A failure after the upload leaves an orphan object, never a row that
  points at nothing. A periodic sweep lists objects with no row and removes
  those older than a grace period.
- Read: row lookup, authorization check, fetch the object, verify
  `content_sha256`, unwrap the DEK, decrypt. A hash mismatch is an integrity
  failure logged to `event_log`, not a silent bad read.
- The Base64 JSON upload contract and `TSI_PRIVACY_VAULT_MAX_UPLOAD_KB` are
  unchanged in M5. Larger files need a streaming or multipart contract, which
  is a separate API decision and is not assumed here.

**Configuration**

| Variable | Meaning |
|---|---|
| `TSI_PRIVACY_VAULT_FILE_STORE=DATABASE` | Active backend for new `FILE` records. Default `DATABASE` |
| `TSI_PRIVACY_VAULT_S3_BUCKET`, `_S3_REGION` | Target bucket and region for `AWS_S3` |
| `TSI_PRIVACY_VAULT_S3_ENDPOINT` | Custom endpoint for `S3_COMPATIBLE`. HTTPS only |
| `TSI_PRIVACY_VAULT_S3_PREFIX` | Optional key prefix, so one bucket can serve several vaults |
| `TSI_PRIVACY_VAULT_GCS_BUCKET`, `TSI_PRIVACY_VAULT_AZURE_CONTAINER` | Targets for `GCS` and `AZURE_BLOB` |

Credentials come from the platform default chain (instance profile, workload
identity, managed identity), never from `.env` secrets where an identity is
available. The vault's identity needs object read, write and delete on the one
bucket or prefix, and nothing else.

**Operations**

- Fail closed. If the active backend is unreachable at boot, the health check
  fails and the data plane returns 503, as it does for an unhealthy anchor.
  A backend outage mid-run fails only the records stored there.
- Migration between backends is a resumable background job like the re-wrap:
  copy the ciphertext, verify the hash, update the row, then delete the source.
  Payloads are never decrypted or re-encrypted, and the DEK is untouched.
- Backup and recovery now span two systems. The database backup alone no
  longer restores external files, so the runbook must pair it with bucket
  versioning or replication.
- Residency: a bucket in another region or jurisdiction changes where personal
  data physically sits. The chosen region must match the deployment's data
  residency commitments.
- Audit: every external put, get and delete is logged to `event_log` with the
  backend and object key, using the existing forensic path.

### Compliance next: per-principal keys and crypto-erasure

Privacy law increasingly requires that a person's data can be erased on
request, while financial and audit records must stay intact for regulators
(for example India's DPDP Act erasure right alongside RBI retention rules).
Deleting rows is not enough when copies live in backups, replicas and object
stores. Destroying the key that makes the ciphertext readable is. The vault
already encrypts every record under its own DEK, so this is a natural
extension rather than a new design.

**Principle.** Erasure is key destruction. Every record (ID, DATA and FILE)
already has its own DEK. Linking records to a principal lets one purge request
destroy all of that principal's DEKs. Once they are gone, the ciphertext is
unrecoverable wherever it was copied, with no need to find and scrub each copy.
No new key level is needed. The ledger and audit rows that reference the data
stay in place, with no readable identity behind them.

**Linking records to a principal**

- A data principal is the person or entity whose data it is, identified by an
  opaque `principal_id` supplied by the caller at store time. It must not be
  a name, PAN, phone or any value that is itself personal data.
- The store call accepts an optional `principal_id` next to `entityType`,
  `entityName` and `content`. A store for an already shredded `principal_id` is
  rejected. Search and retrieve are unchanged. Only the admin purge takes a
  `principal_id`.
- `vault_entities` gains a nullable, indexed `principal_id`. Records stored
  without one behave exactly as today and can still be shredded one at a time
  by `reference_key`. Existing deployments change nothing on upgrade.
- The Erasure Register (`principal_erasures`) holds one row per shredded
  principal:
  `principal_id`, `state` (`SHREDDING` or `SHREDDED`), `requested_by`,
  `shredded_at`, and the count of records destroyed. It holds no key material.

**Shred operation**

1. An authorized admin requests erasure for a `principal_id`, or for a single
   `reference_key`.
2. The vault checks for a legal hold or retention rule on the principal's
   records and refuses while one is active. Which records fall under retention
   is a policy decision the operator records, not something the vault infers.
3. The register entry is written first with `state = SHREDDING`. From this moment
   reads of the principal's records fail closed, and new stores for that
   `principal_id` are rejected.
4. In resumable batches: null `encrypted_data_key` and `encrypted_content`,
   delete the blind index entries, and queue deletion of any external objects
   for each record. The batch job is idempotent, so a crash mid-run resumes
   instead of leaving a partial purge.
5. When no record remains, the entry moves to `SHREDDED`, an `event_log`
   entry records the shred with actor, principal and time, and an erasure
   certificate is available from the existing legal export.
6. Later reads fail with a distinct "erased" outcome, not a decryption error,
   so callers can tell erasure from corruption.

**What stays intact.** Transaction records, balances and audit events that the
caller keeps outside the vault, plus the vault's own `event_log`, remain.
They hold `reference_key` values that no longer resolve to anything. Callers
must keep personal identifiers out of their ledgers and use the
`reference_key` as the link, otherwise erasure in the vault does not erase the
identity from the caller's system.

**Limits to state plainly**

- Shredding is only as strong as key destruction is complete. A database
  backup or replica taken before the shred still holds the wrapped DEKs, and
  the anchor can still unwrap them. Backup retention must be bounded and
  documented, or the shred must be replayed from the Erasure Register when an
  old backup is restored, before the data plane serves traffic. Keep the
  register in a place the restore does not roll back.
- The anchor's own key is shared and is never the shred target. Destroying it
  would erase every principal at once.
- Cost is proportional to the number of records the principal holds. That is
  fine for ordinary principals, and the resumable batch design keeps a very
  large one from holding a long transaction.
- Blind index entries for a principal must go with the key. Left behind they
  would still let someone test whether a known value was ever stored.
- Shredding is irreversible by design. There is no recovery path, so the
  operation needs explicit confirmation and should support two-person
  approval for production.
- This is an engineering control, not legal advice. Whether crypto-erasure
  satisfies a given statute, and which records must be retained, is for the
  operator's counsel to confirm.

**Testing**

- Shred, then read: every record of the principal returns "erased", other
  principals are untouched.
- Kill the shred job mid-batch and confirm it resumes, and that reads and new
  stores for the principal stay blocked meanwhile.
- Restore a pre-shred backup in a test environment and confirm the replay from
the Erasure Register re-shreds before the data plane serves traffic.
- Anchor re-wrap skips shredded records.
- Mixed records with and without `principal_id` read correctly after upgrade.

### Testing expectations for remaining phases

- **Unit:** wrap and unwrap round trips per provider; legacy CBC blobs still
  decrypt after upgrade.
- **Integration:** GCP and Azure through emulators or mocked clients; OpenBao
  against a dev-mode container (wrap, unwrap, key rotation, sealed server
  fails closed); anchor activation and re-wrap resumability (kill mid-batch).
- **Storage:** `FileStore` contract tests run against every backend (S3 via
  MinIO or LocalStack, GCS and Azure via emulators). Cover put, get, delete,
  hash mismatch detection, orphan sweep, unreachable backend failing closed,
  and mixed `DATABASE` and external records reading correctly.
- **Erasure:** a principal shred makes all of that principal's records
  unreadable across database and external storage, leaves other principals
  intact, and is audited. See the compliance section for the full list.
- **Forensics:** every anchor activation, re-wrap, KMS failure and external
  storage operation appears in `event_log` with the machine anchor.
- **Docs:** README, `.example`, `docker-compose.yml`, the tour and the user
  guide updated per phase.
