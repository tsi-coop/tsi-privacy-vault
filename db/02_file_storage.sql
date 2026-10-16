-- 02_file_storage.sql
-- Pluggable FILE storage (docs/design/architecture.md, "Storage backends").
-- Runs after 01_key_management.sql on fresh installs. For existing databases, apply
-- manually: psql -U tsi_admin -d tsi_privacy_vault -f 02_file_storage.sql

-- storage_backend: where the ciphertext lives. DATABASE keeps it inline in
-- encrypted_content. AWS_S3 and S3_COMPATIBLE keep it in the object store under
-- storage_key, and encrypted_content is then an empty string.
-- content_sha256: SHA-256 of the stored ciphertext, verified on every external read.
ALTER TABLE vault_entities
    ADD COLUMN IF NOT EXISTS storage_backend VARCHAR(16) NOT NULL DEFAULT 'DATABASE',
    ADD COLUMN IF NOT EXISTS storage_key TEXT,
    ADD COLUMN IF NOT EXISTS content_sha256 CHAR(64);
