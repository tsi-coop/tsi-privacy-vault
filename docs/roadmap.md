# TSI Privacy Vault - Key Management Roadmap

**Scope:** Evolve the vault's key management from the current single Master
Key model toward hardened root-key anchors, in priority order:

1. **Phase 1 - AWS KMS** as the first production-grade cloud anchor.
2. **Phase 2 - Google Cloud KMS and Azure Key Vault** for multi-cloud parity.
3. **Phase 3 - Split Key Orchestration** using Shamir's Secret Sharing for
   fully sovereign, no-single-person-unlock deployments.

By supporting these diverse anchors, organizations can keep local sovereign
control while benefiting from the hardened infrastructure of major cloud
providers.

---

## 1. Current State Analysis

The vault already implements **envelope encryption** behind a provider
abstraction, which gives us a clean seam for every roadmap item:

| Component | Role | Observations |
|---|---|---|
| `framework/KmsProvider.java` | Interface: `generateDataKey()`, `decryptDataKey()`, `aesEncrypt()`, `aesDecrypt()` | The contract all new providers must implement. |
| `framework/LocalKmsProvider.java` | Wraps per-record Data Encryption Keys (DEKs) with a Master Key | Master Key = SHA-256 of `TSI_PRIVACY_VAULT_MASTER_KEY` env var; held in a `static final byte[]` for the JVM lifetime. Falls back to a **hard-coded default seed** when the env var is missing. |
| `framework/AwsKmsProvider.java` | AWS KMS-backed DEK generation/unwrap | Functional skeleton; configured via system properties (`aws.region`, `aws.kms.identifier`) rather than the project's env-var convention. AWS SDK (`software.amazon.awssdk:kms`) is already in `pom.xml`. |
| `framework/KmsService.java` | Older AWS KMS prototype | Duplicates `AwsKmsProvider`; contains a hard-coded sample key ARN and a `main()` test harness. Candidate for removal. |
| `api/client/Vault.java` | Data plane (store/fetch/search/resolve) | Selects provider via system property `vault.provider` (`LOCAL`/`AWS`). |
| `api/admin/Utility.java` | Utility secret storage | **Hard-codes `new LocalKmsProvider()`** in three places - bypasses provider selection. Data stored under one provider cannot be resolved if another is active. |
| `db/init.sql` | Schema | `vault_entities` and `vault_utilities` store `encrypted_data_key` alongside ciphertext, but record **no metadata about which key/provider/version wrapped it**. |

### Gaps the roadmap must close

1. **Inconsistent provider wiring:** `Utility.java` hard-codes the local
   provider while `Vault.java` honors `vault.provider`; AWS config uses system
   properties instead of env vars; the dead `KmsService` class lingers.
   *This is the main blocker for shipping AWS KMS support - fix first.*
2. **No key versioning:** wrapped DEKs carry no provider/key-version metadata,
   so the anchor can never be rotated or migrated (LOCAL → AWS) without
   breaking existing ciphertext.
3. **Insecure default key:** `LocalKmsProvider` silently falls back to a
   published default seed - every dev-path deployment shares the same Master Key.
4. **Single point of failure (addressed last, Phase 3):** one env var unlocks
   everything; anyone with host/`.env`/memory-dump access can reconstruct the
   Master Key. No concept of the vault being "sealed."
5. **Cipher hardening (opportunistic):** AES/CBC/PKCS5Padding without
   authentication; AES-GCM should be adopted for new key versions.

---

## 2. Target Architecture

```
                 ┌────────────────────────────────────────────┐
                 │              Root Key Anchors              │
                 │                                            │
   Phase 1 ──►  │  AWS_KMS  : AWS KMS CMK                    │
   Phase 2 ──►  │  GCP_KMS  : Cloud KMS CryptoKey            │
                 │  AZURE_KV : Key Vault / Managed HSM key    │
   Phase 3 ──►  │  SHAMIR   : K-of-N custodian shares        │
                 └─────────────────┬──────────────────────────┘
                                   │ protects / wraps (with key_version)
                                   ▼
                 ┌────────────────────────────────────────────┐
                 │  Per-record Data Encryption Keys (DEKs)    │
                 │  stored as encrypted_data_key (unchanged)  │
                 └────────────────────────────────────────────┘
```

Design principles:

- Anchors differ only in *how DEKs are protected at rest*; the data plane
  (`Vault.java`, `Utility.java`) is anchor-agnostic and talks only to
  `KmsProvider`.
- Every wrapped DEK records the **key version** that wrapped it, enabling
  rotation and anchor migration (LOCAL → AWS_KMS → others) without
  re-encrypting payloads in one shot.
- Payload ciphertext is never bulk re-encrypted during migration - only the
  ~48-byte wrapped DEK is re-wrapped.

---

## 3. Phase 0 - Refactoring Prerequisites (small, ships first)

1. **`KmsProviderFactory`** (new, `framework/`): single place that reads
   `TSI_PRIVACY_VAULT_KMS_PROVIDER` (values: `LOCAL`, `AWS_KMS`, `GCP_KMS`,
   `AZURE_KV`, `SHAMIR`; default `LOCAL`) and returns a shared provider
   instance. Replace the constructor logic in `Vault.java` and all three
   hard-coded `new LocalKmsProvider()` sites in `Utility.java`.
2. **Delete `KmsService.java`** (legacy prototype with a hard-coded ARN).
3. **Fail closed on missing key:** remove the default-seed fallback in
   `LocalKmsProvider`; refuse to start when `TSI_PRIVACY_VAULT_MASTER_KEY` is
   absent and the provider is `LOCAL`.
4. **Key-version metadata:**
   - Schema: `ALTER TABLE vault_entities ADD COLUMN key_version INT NOT NULL DEFAULT 1;`
     same for `vault_utilities`; new table:

     ```sql
     CREATE TABLE vault_key_ring (
         key_version   SERIAL PRIMARY KEY,
         anchor_type   VARCHAR(16) NOT NULL,        -- LOCAL | AWS_KMS | GCP_KMS | AZURE_KV | SHAMIR
         anchor_ref    TEXT,                        -- cloud key ARN/resource name; NULL for local/shamir
         cipher        VARCHAR(32) NOT NULL,        -- AES_CBC_PKCS5 (legacy) | AES_GCM
         status        VARCHAR(16) NOT NULL,        -- ACTIVE | DECRYPT_ONLY | RETIRED
         created_at    TIMESTAMP NOT NULL DEFAULT now()
     );
     ```
   - Extend `KmsProvider` with `int getActiveKeyVersion()` and
     `String decryptDataKey(String encryptedDataKeyB64, int keyVersion)`;
     keep the old signature delegating to the active version for
     compatibility.
5. **AES-GCM for new key versions:** introduce `AES/GCM/NoPadding` (12-byte
   nonce, 128-bit tag) selected via the `cipher` column; legacy CBC blobs
   remain readable under `key_version = 1`.

Deliverable: behavior-identical release; all existing data readable; ground
prepared for the AWS anchor and rotation.

---

## 4. Phase 1 - AWS KMS Anchor (priority)

### 4.1 Harden `AwsKmsProvider`

- **Configuration via env vars** (consistent with `.example` /
  `docker-compose.yml`), replacing system properties:
  - `TSI_PRIVACY_VAULT_AWS_REGION`
  - `TSI_PRIVACY_VAULT_AWS_KMS_KEY_ID` (key ARN or alias ARN)
- **Credentials via the AWS default chain** (IAM role / instance profile /
  env / shared config) - no AWS secrets in `.env` beyond the key identifier.
- **Encryption context** on every `GenerateDataKey`/`Decrypt` call
  (`vault_node_id` from `TSI_PRIVACY_VAULT_NODE_ID`, plus `record_type`),
  binding ciphertext to this vault instance and enriching CloudTrail.
- **AES-GCM** for the local payload encryption performed with the plaintext
  DEK (per Phase 0 cipher versioning).
- **Single shared `KmsClient`:** built once in `KmsProviderFactory` and reused
  for the application lifetime (the AWS SDK client is thread-safe), replacing
  the per-request provider construction `Vault.java` does today. *(Decided.)*
- **Fail closed:** the vault refuses to serve data-plane traffic when AWS KMS
  is unreachable at boot - no degraded read-only mode. A startup health check
  (one `GenerateDataKey` + `Decrypt` round-trip) fails the app loudly - with a
  forensic `event_log` entry - if the key is unreachable, disabled, or pending
  deletion. Retry with exponential backoff on KMS throttling during normal
  operation. *(Decided.)*
- **Forensic logging:** every KMS unwrap failure logged through the existing
  `ForensicEngine` / `event_log` pattern (court-ready evidence model applies
  to key operations too).
- Reuse the existing `software.amazon.awssdk:kms` dependency; pin/refresh its
  version in `pom.xml`.

### 4.2 Migration LOCAL → AWS_KMS

1. Deploy Phase 0; all existing rows are `key_version = 1` (legacy LOCAL).
2. Operator configures the AWS env vars and activates the anchor via a new
   admin function `activate_key_anchor` (with `.jschema` validator):
   creates `vault_key_ring` version 2 (`AWS_KMS`, `AES_GCM`, ACTIVE) and marks
   v1 DECRYPT_ONLY. New writes wrap DEKs via AWS KMS immediately.
3. Background **re-wrap job** (admin-triggered, batched via existing
   `BatchDB`): for each `key_version = 1` row in `vault_entities` /
   `vault_utilities`, unwrap the DEK with the legacy local key, re-wrap via
   `kms:Encrypt`/`GenerateDataKey`, update row + `key_version`. Resumable and
   cheap - payload ciphertext untouched.
4. When no v1 rows remain, mark v1 RETIRED and instruct the operator to remove
   `TSI_PRIVACY_VAULT_MASTER_KEY` from `.env`. Fold the existing `rotate`
   admin function into this key-version mechanism (rotation = new key-ring
   version under the same anchor + re-wrap).

### 4.3 Operations & documentation

- Minimal IAM policy doc: `kms:GenerateDataKey`, `kms:Decrypt` (plus
  `kms:Encrypt` for the re-wrap job) scoped to the single CMK.
- Update README, `.example`, `docker-compose.yml`, and the tour with the AWS
  setup runbook; note that enabling automatic CMK rotation in AWS is
  transparent to the vault.
- Admin UI: show active anchor + key version on the dashboard; surface
  re-wrap job progress.

### 4.4 Verification

- Integration tests against **LocalStack** KMS: store/fetch round-trip,
  utility resolve, anchor activation, re-wrap job (including kill/resume
  mid-batch), unreachable-key startup failure.
- Backward-compat test: v1 CBC blobs remain readable while v2 is active.

---

## 5. Phase 2 - Google Cloud KMS & Azure Key Vault

Both reuse the Phase 1 machinery (factory, key ring, re-wrap migration,
health checks, forensic logging). Shared concerns land in an
`AbstractCloudKmsProvider` extracted from the hardened AWS provider.

### 5.1 Google Cloud KMS (`GcpKmsProvider`)

- Dependency: `com.google.cloud:google-cloud-kms`.
- GCP KMS has **no GenerateDataKey API**: generate the 32-byte DEK locally
  with `SecureRandom`, then `Encrypt` it under the CryptoKey
  (`projects/.../locations/.../keyRings/.../cryptoKeys/...`) with
  `additionalAuthenticatedData`.
- Config: `TSI_PRIVACY_VAULT_GCP_KMS_KEY_RESOURCE`; auth via Application
  Default Credentials / workload identity.
- Required role: `roles/cloudkms.cryptoKeyEncrypterDecrypter`.

### 5.2 Azure Key Vault (`AzureKvProvider`)

- Dependencies: `com.azure:azure-security-keyvault-keys`, `com.azure:azure-identity`.
- Generate DEK locally; protect it with `CryptographyClient.wrapKey` /
  `unwrapKey` (`RSA-OAEP-256`, or `AES-KW` on Managed HSM for symmetric
  parity with AWS/GCP).
- Config: `TSI_PRIVACY_VAULT_AZURE_KEY_ID` (full key identifier URL); auth via
  `DefaultAzureCredential` (managed identity preferred).
- Required permissions: `wrapKey`, `unwrapKey` only.

### 5.3 Build packaging

Adding GCP + Azure SDKs to the WAR is acceptable initially; if WAR size
becomes a concern, introduce Maven profiles (`-Pkms-aws`, `-Pkms-gcp`,
`-Pkms-azure`) with reflective provider loading in the factory so the default
build stays lean and fully sovereign.

### 5.4 Anchor migration between clouds

Switching anchors (AWS_KMS → GCP_KMS, etc.) reuses the same flow: activate a
new `vault_key_ring` version under the new anchor, run the DEK re-wrap job,
retire the old version. No payload re-encryption ever required.

---

## 6. Phase 3 - Split Key Orchestration (Shamir's Secret Sharing)

For fully sovereign deployments where no cloud dependency is acceptable and
**no single individual or compromised server may unlock the vault alone**.

### 6.1 Concept

A randomly generated 32-byte **Vault Master Key (VMK)** - never derived from a
passphrase - is split into **N shares** distributed to named key custodians;
any **K shares (threshold)** reconstruct it. The server stores only *wrapped*
material, never the VMK. The vault gains an explicit lifecycle:
`UNINITIALIZED → SEALED → UNSEALED`. While SEALED, data-plane and utility APIs
return `503 Vault Sealed`; admin login, status, and unseal endpoints remain
available. After every restart the vault starts SEALED (a feature, not a bug).

### 6.2 Cryptography

- New `framework/ShamirSecretSharing.java`: split/combine over **GF(256)**
  (one byte at a time, share = N points on a random degree K-1 polynomial).
  ~150 lines of well-understood code with published test vectors; in-repo
  implementation keeps the project's minimal-dependency posture. Alternative:
  vendor `com.codahale:shamir` (Apache-2.0, tiny) - decide at review.
- Shares distributed as `TSIV1-<share_index>-<base64(share)>-<crc32>` so
  custodians can detect typos at entry.
- The server persists **only** SHA-256 fingerprints of shares, N, K, and
  custodian labels - never share material.

### 6.3 Components & schema

- `framework/SealManager.java` (singleton): holds the VMK in memory only;
  collects shares; on K valid distinct shares, reconstructs the VMK, verifies
  a stored check value, transitions to UNSEALED; `seal()` zeroes it.
  `InterceptingFilter` consults it and rejects data-plane requests while SEALED.
- `framework/ShamirKmsProvider.java`: same wrap/unwrap as the local provider
  but sources the Master Key from `SealManager`; AES-GCM.

```sql
CREATE TABLE vault_seal_config (
    id              SMALLINT PRIMARY KEY DEFAULT 1,
    share_count     SMALLINT NOT NULL,       -- N (2..16)
    threshold       SMALLINT NOT NULL,       -- K (2..N)
    vmk_check_value VARCHAR(64) NOT NULL,
    initialized_at  TIMESTAMP NOT NULL
);

CREATE TABLE vault_key_custodians (
    share_index       SMALLINT PRIMARY KEY,
    custodian_label   VARCHAR(120) NOT NULL, -- name/role only
    share_fingerprint VARCHAR(64) NOT NULL,  -- SHA-256 of share, for audit
    issued_at         TIMESTAMP NOT NULL
);
```

### 6.4 API surface (admin processor, with `.jschema` validators)

| `_func` | Behavior |
|---|---|
| `init_split_key` | One-time key ceremony: takes N, K, custodian labels; generates VMK, returns the N shares **once**, stores fingerprints + check value, activates a new `vault_key_ring` entry (`SHAMIR`, `AES_GCM`). |
| `submit_unseal_share` | Accepts one share; returns progress (`{submitted: 2, threshold: 3}`). Forensic-logs every attempt (custodian index, IP, UA, outcome). |
| `get_seal_status` | `UNINITIALIZED | SEALED | UNSEALED`, progress, active key version. Unauthenticated-safe (no secrets). |
| `seal_vault` | Admin-only; zeroes the VMK, returns vault to SEALED. |
| `rekey_shares` | Requires K fresh shares (plus admin JWT) as authorization; generates a new VMK, re-wraps all DEKs via the Phase 1 re-wrap job, issues new shares. Also used to change N/K or revoke a custodian. |

UI: extend `init.html` with the key-ceremony step (display shares once, force
per-custodian acknowledgment); new `unseal.html` for seal status and share
submission; dashboard seal-state badge.

### 6.5 Security & operations

- Shares submitted over HTTPS only; rate-limit and forensic-log failed
  submissions.
- The existing `break_glass_reset` covers admin passwords only. Document
  explicitly that **loss of more than N−K shares is unrecoverable by design**;
  recommend N ≥ 5, K = 3 with geographically separate custodians.
- Migration from any prior anchor uses the standard key-ring re-wrap flow.

### 6.6 Stretch: Hybrid cloud auto-unseal

Combine anchors for "sovereign control + hardened cloud": the Shamir-protected
VMK is additionally wrapped by a cloud KMS key (Phase 1/2 providers) and
stored in `vault_key_ring`. On startup the vault auto-unseals via cloud KMS;
if the cloud key is revoked or unreachable, custodians can still unseal
manually with K shares. The cloud provider alone can never decrypt - DEK
unwrap happens locally. Config:
`TSI_PRIVACY_VAULT_AUTO_UNSEAL=AWS_KMS|GCP_KMS|AZURE_KV|NONE`.

---

## 7. Testing & Verification (cross-phase)

- **Unit:** wrap/unwrap round-trips per provider; legacy CBC v1 blobs still
  decrypt after upgrade; (Phase 3) GF(256) split/combine for all K-of-N up to
  16 and a property test that K−1 shares fail the check value.
- **Integration:** AWS via LocalStack; GCP/Azure via emulators or mocked
  clients; anchor activation + re-wrap job resumability (kill mid-batch);
  (Phase 3) seal → unseal → store → seal → fetch-returns-503 → unseal → fetch.
- **Forensics:** every anchor activation, re-wrap, KMS failure, and (Phase 3)
  unseal attempt appears in `event_log` with machine anchor, per the existing
  court-ready evidence model.
- **Docs:** README, `.example`, `docker-compose.yml`, the tour (`web/tour/`),
  and the User Guide updated per phase.

---

## 8. Sequencing & Milestones

| Milestone | Contents | Depends on |
|---|---|---|
| **M0** | Phase 0 refactor: factory, fail-closed key, key-ring schema, AES-GCM, delete `KmsService` | - |
| **M1** | AWS KMS provider hardening: env config, default credential chain, encryption context, health check, retries | M0 |
| **M2** | `activate_key_anchor` + LOCAL → AWS re-wrap migration job, IAM docs, dashboard anchor status | M1 |
| **M3** | GCP KMS + Azure Key Vault providers, `AbstractCloudKmsProvider`, anchor-migration runbook | M2 |
| **M4** | Shamir: split/combine, SealManager, seal-aware filter | M0 |
| **M5** | Shamir: key ceremony + unseal APIs/UI, custodian audit, rekey | M4 |
| **M6** | Hybrid cloud auto-unseal (stretch) | M2, M5 |

M1-M3 (cloud track) is the priority; M4-M5 (Shamir) starts only after the
cloud track ships, though it depends only on M0 technically.

---

## 9. Decisions & Open Questions

### Decided (2026-06-11)

1. **Fail closed at boot:** when AWS KMS is unreachable, the vault refuses to
   serve data-plane traffic - no degraded read-only mode. (See section 4.1.)
2. **Single shared `KmsClient`:** built once in `KmsProviderFactory` and
   reused, replacing per-request construction in `Vault.java`. (See
   sections 3 and 4.1.)

### Open (to be decided later)

3. Maven profiles for cloud SDKs now, or accept WAR growth until Phase 2?
4. Phase 3: vendor `com.codahale:shamir` or maintain GF(256) in-repo?
   (Recommendation: in-repo, given the manually-reviewed contribution model.)
