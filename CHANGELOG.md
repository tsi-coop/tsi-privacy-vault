# Changelog

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
