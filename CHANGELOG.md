# Changelog

## v0.2.1

### Security
- Admin console pages (`dashboard`, `apikeys`, `audit`, `entities`, `keyanchor`, `legal`, `users`, `utilities`) are now gated server-side. Previously the only check was client-side JavaScript, so the full page source was served to any HTTP client. A valid admin session (HttpOnly `console_session` cookie set at login, cleared by the new `/api/admin/logout`) is required, otherwise the request redirects to `/index.html`.
- First-run setup (`/api/admin/setup`) now requires `setup_token` matching `TSI_PRIVACY_VAULT_BOOTSTRAP_TOKEN`, compared in constant time. If the variable is unset, setup is refused with 503. The token is checked before any database access.
- The unauthenticated `/api/admin/setup` and `/api/admin/resetpass` routes no longer expose every user-management function. Setup accepts only `create_user` for the `SYSTEM_ADMIN` role, and reset accepts only `break_glass_reset`. Previously `generate_master_recovery_key` and `list_users` were reachable without a login through either route.
- Creating the first `SYSTEM_ADMIN` is atomic (SERIALIZABLE transaction), so two concurrent setup requests cannot both succeed.
- Directory listing is disabled on the web application.
- The client API now verifies `X-API-Secret` against the stored PBKDF2 hash. Previously only the `X-API-Key` was checked, so the key alone granted access to the data plane. **Clients must now send both headers**; requests without a valid secret return 401.

### Changed
- `TSI_PRIVACY_VAULT_BOOTSTRAP_TOKEN` is a new environment variable (see `.example` and `docker-compose.yml`). Existing installations that are already set up are unaffected.
- New `POST /api/admin/logout` endpoint, used by the console's Logout action.

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
