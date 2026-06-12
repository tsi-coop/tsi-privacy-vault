-- 01_key_management.sql
-- Phase 0 key-version metadata (docs/roadmap.md, section 3).
-- Runs after 00_init.sql on fresh installs. For existing databases, apply
-- manually: psql -U tsi_admin -d tsi_privacy_vault -f 01_key_management.sql

-- Registry of root key anchors. Every wrapped DEK records the key_version
-- that wrapped it, enabling rotation and anchor migration (LOCAL -> AWS_KMS)
-- without re-encrypting payloads.
CREATE TABLE IF NOT EXISTS vault_key_ring (
    key_version   SERIAL PRIMARY KEY,
    anchor_type   VARCHAR(16) NOT NULL,   -- LOCAL | AWS_KMS | GCP_KMS | AZURE_KV | SHAMIR
    anchor_ref    TEXT,                   -- cloud key ARN/resource name; NULL for LOCAL/SHAMIR
    cipher        VARCHAR(32) NOT NULL,   -- payload cipher for records written under this version
    status        VARCHAR(16) NOT NULL
        CHECK (status IN ('ACTIVE', 'DECRYPT_ONLY', 'RETIRED')),
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- At most one ACTIVE version at any time
CREATE UNIQUE INDEX IF NOT EXISTS idx_key_ring_single_active
    ON vault_key_ring (status) WHERE status = 'ACTIVE';

-- Seed version 1 = legacy local Master Key anchor (TSI_PRIVACY_VAULT_MASTER_KEY)
INSERT INTO vault_key_ring (anchor_type, cipher, status)
SELECT 'LOCAL', 'AES_CBC_PKCS5', 'ACTIVE'
WHERE NOT EXISTS (SELECT 1 FROM vault_key_ring);

-- key_version: which vault_key_ring entry wraps the row's DEK (updated by re-wrap).
-- payload_cipher: cipher used on the payload at write time (never changes on re-wrap).
ALTER TABLE vault_entities
    ADD COLUMN IF NOT EXISTS key_version INT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS payload_cipher VARCHAR(32) NOT NULL DEFAULT 'AES_CBC_PKCS5';

ALTER TABLE vault_utilities
    ADD COLUMN IF NOT EXISTS key_version INT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS payload_cipher VARCHAR(32) NOT NULL DEFAULT 'AES_CBC_PKCS5';

-- Supports the batched re-wrap job and pending-migration counts
CREATE INDEX IF NOT EXISTS idx_vault_entities_key_version ON vault_entities (key_version);
CREATE INDEX IF NOT EXISTS idx_vault_utilities_key_version ON vault_utilities (key_version);
