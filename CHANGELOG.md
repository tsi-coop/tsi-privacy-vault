# Changelog

## v0.3.0 (unreleased)

Three themes: files can live in object storage, a data principal's records can be
erased, and the audit log can prove it has not been altered. Admin write access is
also now limited to `SYSTEM_ADMIN`.

### Upgrade notes
- **Apply the database scripts** to existing databases, in order: `db/02_file_storage.sql`, `db/03_erasure.sql`, `db/04_audit_chain.sql`. Fresh installs pick them up automatically. `04` chains existing audit rows from that point on and makes `event_log` append-only, so make sure no clean-up job updates or deletes audit rows.
- **Write access is `SYSTEM_ADMIN` only.** Any other console role is now read only. Check who manages entities, keys, anchors and secrets before upgrading. See [Audit and access control](docs/guides/audit-and-access-control.md#1-admin-roles).

### Added
- **Pluggable file storage.** `FILE` content can be kept in AWS S3 or an S3-compatible store (MinIO, Ceph) instead of PostgreSQL, selected with `TSI_PRIVACY_VAULT_FILE_STORE`. Only ciphertext reaches the bucket. The default stays `DATABASE`. The dashboard shows a File Storage card. Design: [Storage backends](docs/design/architecture.md#storage-backends-next-pluggable-file-storage). Setup: [AWS S3 configuration guide](docs/guides/aws-s3-configuration.md).
- **Erasure by principal (crypto-erasure).** `store_data` accepts an opaque `principal_id`. A `SYSTEM_ADMIN` shreds a principal through `/api/admin/erasure`, which destroys the key, content, search index entries and any object-store copy of every erasable record, while records inside their policy hold stay readable. Reads of erased records return `410`. Includes a policy hold per entity (days from creation), legal holds, a resumable batch job and an erasure certificate. Design: [Per-principal keys and crypto-erasure](docs/design/architecture.md#compliance-next-per-principal-keys-and-crypto-erasure). Operation: [Erasure management guide](docs/guides/erasure-management.md).
- **Erasure page in the admin console** (`/erasure.html`). A read-only monitor of the register, certificates, legal holds and recent erasure events, whether requests came from the API, the example scripts or your own application. See [Erasure management, section 9](docs/guides/erasure-management.md#9-reports-and-audit).
- **Erasure card on the dashboard.** Counts of the Erasure Register by state (`SHREDDING`, `PARTIAL`, `SHREDDED`), shreds stuck for more than 24 hours, partial shreds whose retention has elapsed, and open legal holds. Counts only, no principal ids. `get_dashboard_stats` returns them under `erasure`.
- **Erasure job history.** Every pass of the erasure job, scheduled or manual, is recorded in `erasure_job_runs` (re-apply `db/03_erasure.sql`). `get_erasure_job` on `/api/admin/erasure` reports status (`HEALTHY`, `FAILING`, `OVERDUE`, `WAITING`, `DISABLED`), last success, consecutive failures and 30 day totals. The Erasure page has a job summary and links to a new run history page (`/erasure-jobs.html`). Overdue means no success within twice the interval.
- **Settings page** (`/settings.html`) in the admin console, with Key Anchor, File Storage, Erasure Job and General tabs. Key Anchor activation and re-wrap moved here from `/keyanchor.html`, which now redirects. Settings from `.env` are shown read-only with their variable names; secrets are never returned. New `get_settings` on `/api/admin/settings`. The dashboard shows a File Storage alert only when the store is unavailable.
- **Custody trail and certificate by principal.** The Legal page now starts from a `principal_id` (or a reference key, for records stored without one) and shows every record the vault holds for that person with its lifecycle: STORE, FETCH, SEARCH and ERASE events against each record, the erasure position and legal holds. One BSA Section 63 custody certificate covers the whole principal. It embeds the erasure and hold position, verifies the audit chain from the earliest event to the head before issuing (refused with `409` if broken), and carries a digest over every record and event. New `get_principal_custody` and `generate_principal_certificate` on `/api/admin/legal`. The record-only certificate remains per record.
- **Search is now audited.** `search_data` writes one `SEARCH` event per record returned to the caller (up to 100 per search), so a search shows up in that record's custody trail. The search term is never logged.
- **Erasure from the client API.** `shred_principal` and `get_erasure_certificate` on `/api/client/vault`, using the same API key as store and fetch. The key needs write (shred) or read (certificate) access to every entity type that holds the person's records, and legal and policy holds apply as for an admin. The Data Client has an **Erase a person** action, and the Erasure console page shows whether each request came from a client key or an administrator.
- **Tamper-evident audit log.** Every `event_log` row is hash-chained to the one before it by a database trigger, and the table is append-only. `verify_audit_chain` on `/api/admin/audit` reports the first broken row and returns the current head, which you can record and check later to detect truncation. Design: [Tamper-evident audit log](docs/design/architecture.md#tamper-evident-audit-log). Operation: [Audit and access control guide](docs/guides/audit-and-access-control.md#2-tamper-evident-audit-log).
- **Audit integrity in the BSA Section 63 certificate.** The certificate cites the certified event and the log head at issue. The chain is verified first, and issuing returns `409` if it is broken. The certified event is now the successful `STORE` event. See [what the certificate shows](docs/guides/audit-and-access-control.md#24-what-the-bsa-certificate-shows).
- Entity definitions take `retain_days`, a policy hold in days from creation, editable on the Entities page. The Entities form now shows only the fields that apply to the chosen flavor (regex for ID and DATA, MIME types for FILE) and a Rules column.
- `get_audit_logs` accepts `operationPrefixes` for operations with a variable suffix.
- Tests, all under [`tests/`](tests/README.md): service and contract tests against throwaway PostgreSQL and MinIO, audit chain and role tests, and an end-to-end runner (`tests/runners/run-e2e.sh`) that drives the example scripts over HTTP.

### Security
- **Mutating admin APIs require `SYSTEM_ADMIN`.** Previously any signed-in console user could create users and recovery keys, activate or re-wrap key anchors, edit entities, issue API keys and permissions, and enroll, check out or rotate secrets. A missing role is refused. Refusals return `403` and are audited as `ADMIN_<AREA>:<FUNCTION>`. The `setup` and `resetpass` routes keep their bootstrap-token and recovery-key protection. Design: [Admin roles](docs/design/architecture.md#admin-roles).

### Fixed
- A file store that failed its boot health check kept the data plane at 503 until a restart. It now re-checks at most every 30 seconds and recovers on its own.
- Several data-plane audit entries used the outcome `FAILURE`, which `event_log` rejects, so they were never written. They now use `DENIED` or `ERROR`.
- The BSA certificate printed a software version from an environment variable and ignored the one computed for it. It now prints the build's `pom.xml` version (`0.3.0-SNAPSHOT`; bump `<version>` when you cut a release).
- The legal certificate endpoint appended `{}` to the PDF stream.

## v0.2.1

### Security
- Admin console pages (`dashboard`, `apikeys`, `audit`, `entities`, `keyanchor`, `legal`, `users`, `utilities`) are now gated server-side. Previously the only check was client-side JavaScript, so the full page source was served to any HTTP client. A valid admin session (HttpOnly `console_session` cookie set at login, cleared by the new `/api/admin/logout`) is required, otherwise the request redirects to `/index.html`.
- First-run setup (`/api/admin/setup`) now requires `setup_token` matching `TSI_PRIVACY_VAULT_BOOTSTRAP_TOKEN`, compared in constant time. If the variable is unset, setup is refused with 503. The token is checked before any database access.
- The unauthenticated `/api/admin/setup` and `/api/admin/resetpass` routes no longer expose every user-management function. Setup accepts only `create_user` for the `SYSTEM_ADMIN` role, and reset accepts only `break_glass_reset`. Previously `generate_master_recovery_key` and `list_users` were reachable without a login through either route.
- Creating the first `SYSTEM_ADMIN` is atomic (SERIALIZABLE transaction), so two concurrent setup requests cannot both succeed.
- Directory listing is disabled on the web application.
- The client API now verifies `X-API-Secret` against the stored PBKDF2 hash. Previously only the `X-API-Key` was checked, so the key alone granted access to the data plane. **Clients must now send both headers**; requests without a valid secret return 401.
- `store_data` now enforces the entity definition. The entity's stored `flavor` is authoritative, and a mismatched `entityType` is rejected with 400. Previously the client's value was trusted.
- `validation_regex` is applied to `ID` and `DATA` values (full match, bounded effort so a hostile pattern cannot hang a thread). A non-matching value returns 422.
- `mime_types` is applied to `FILE` uploads by sniffing the decoded bytes (PDF, PNG, JPEG, GIF, ZIP-based Office files, UTF-8 text). Unknown or disallowed content returns 415. A `FILE` entity with no accepted types rejects every upload.
- File names are sanitized (path stripped, unsafe characters replaced) before they are stored and indexed. A missing `fileName` on a `FILE` entity returns 400 instead of crashing.
- Rejected stores are written to `event_log` with outcome `DENIED`.

### Fixed
- The upload limit read `VAULT_MAX_UPLOAD_KB`, so the documented `TSI_PRIVACY_VAULT_MAX_UPLOAD_KB` was ignored. The documented name is now read, and the old one still works as a fallback. The limit applies to the decoded size, and the entity's own `max_size_kb` can lower it.
- A failed store now returns a 500 response. Before, the request got no response body and the failure was logged with an outcome the table does not allow.
- Admin API error responses were sent with HTTP status 200 and the real code only in the JSON body. Clients and the console that check the HTTP status saw errors as success. The status line now matches the body.
- `update_entity` used different field names from the console form and could not be validated against its schema. It now matches `create_entity`.

### Changed
- `TSI_PRIVACY_VAULT_BOOTSTRAP_TOKEN` is a new environment variable (see `.example` and `docker-compose.yml`). Existing installations that are already set up are unaffected.
- New `POST /api/admin/logout` endpoint, used by the console's Logout action.
- `create_entity` and `update_entity` validate the definition: `flavor` must be `ID`, `DATA` or `FILE`, the regex must compile, `mime_types` is required for `FILE` and must be `type/subtype` values, and `entity_code` is limited to letters, digits, underscore and hyphen. Invalid definitions return 400, and a duplicate code returns 409.
- Existing `FILE` entities without `mime_types` must be edited to add them before further uploads are accepted.
- The Entities page has a Max Size field, shows server errors, and no longer builds its Edit button from unescaped values.

## v0.2.0

### Added
- AWS KMS key anchor support, as an opt-in alternative to the LOCAL anchor: create a Customer Managed Key, activate it as the root key anchor, and re-wrap existing records from the admin console's Key Anchor page.
- Resumable re-wrap migration (batched, via admin console or `rewrap_data_keys` admin API) to move existing records' wrapped Data Encryption Keys from one anchor to another without re-encrypting payload data.
- Admin console Key Anchor screen for activating anchors and tracking re-wrap progress.

### Fixed
- Re-wrap bug fix.

## v0.1.0

### Added
- Initial release of TSI Privacy Vault.
- Three Data Flavours: specialized handling for IDs (tokenization), DATA (field-level encryption), and FILES (secure binary storage).
- Encrypted search via Deterministic Blind Index, supporting full-name, segment, and 3-character-prefix lookups without decrypting data.
- Utilities Management for the lifecycle of API keys and SSL certificates.
- Forensic Anchoring of every access request to a user and machine ID for an immutable audit trail.
- Automated Governance: certificate expiry alerts and mandatory key rotation tooling.
- Secure storage and tokenization for Aadhaar, Voter ID, and ABHA ID.
- RESTful APIs for external clients (store, fetch by reference, fetch reference by ID value).
- Admin Portal APIs (login, register admin, client management, ID type management, audit logs).
- Docker Compose setup for local development (PostgreSQL, Jetty).
- Deterministic hashing for ID lookups.
- Comprehensive logging for all vault operations.

### Changed
- Initial setup of project structure and core components.
