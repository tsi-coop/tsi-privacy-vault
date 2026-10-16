-- 03_erasure.sql
-- Crypto-erasure by principal (docs/design/architecture.md, "per-principal keys and crypto-erasure").
-- Runs after 02_file_storage.sql on fresh installs. For existing databases, apply
-- manually: psql -U tsi_admin -d tsi_privacy_vault -f 03_erasure.sql

-- Policy hold per entity type: days from creation during which a record cannot be erased.
-- NULL or 0 means no hold. Copied onto each record as retain_until at store time, so a later
-- change never alters what an existing record was promised. The consent manager decides when
-- erasure is due; this only states the days the organisation must keep a record regardless
-- (statutory or company policy). Legal holds (below) are separate and open ended.
ALTER TABLE vault_entity_master
    ADD COLUMN IF NOT EXISTS retain_days INT CHECK (retain_days IS NULL OR retain_days >= 0);

-- principal_id : opaque id of the data principal, supplied by the caller. Never personal data.
-- retain_until : earliest instant the record may be destroyed. NULL means erasable now.
-- erased_at    : set the moment the record is condemned. Reads fail closed from then on, while
--                the batch job destroys the key, the content and the blind index entries.
ALTER TABLE vault_entities
    ADD COLUMN IF NOT EXISTS principal_id    VARCHAR(100),
    ADD COLUMN IF NOT EXISTS retain_until    TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS erased_at       TIMESTAMP WITH TIME ZONE;

-- Databases that applied an earlier draft of this file carried closure-based retention
-- (erasable, retain_from, retention_open). Records still awaiting a closure event are held for
-- their snapshotted days from now, then the draft columns are dropped.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'vault_entities' AND column_name = 'retention_open') THEN
        UPDATE vault_entities
           SET retain_until = CURRENT_TIMESTAMP + (COALESCE(retain_days, 0) || ' days')::interval
         WHERE retention_open = TRUE AND erased_at IS NULL;
    END IF;
END $$;
ALTER TABLE vault_entities DROP COLUMN IF EXISTS retention_open;
ALTER TABLE vault_entities DROP COLUMN IF EXISTS retain_days;
ALTER TABLE vault_entities DROP COLUMN IF EXISTS retain_from;
ALTER TABLE vault_entity_master DROP COLUMN IF EXISTS erasable;
ALTER TABLE vault_entity_master DROP COLUMN IF EXISTS retain_from;

-- A shredded record keeps its row (reference_key, entity type, timestamps) but nothing
-- that could identify the value. The plaintext SHA-256 and the file name go too, because
-- an unsalted hash of a low-entropy identifier would still let someone test a guess.
ALTER TABLE vault_entities
    ALTER COLUMN encrypted_content DROP NOT NULL,
    ALTER COLUMN hashed_value_sha256 DROP NOT NULL;

CREATE INDEX IF NOT EXISTS idx_vault_entities_principal ON vault_entities (principal_id) WHERE principal_id IS NOT NULL;
-- Work queue of the shred job: condemned rows whose key or object is still present
CREATE INDEX IF NOT EXISTS idx_vault_entities_erase_queue ON vault_entities (erased_at)
    WHERE erased_at IS NOT NULL AND (encrypted_data_key IS NOT NULL OR storage_key IS NOT NULL);

-- Erasure Register: one row per principal with an erasure request. Holds no key material.
CREATE TABLE IF NOT EXISTS principal_erasures (
    principal_id      VARCHAR(100) PRIMARY KEY,
    state             VARCHAR(10) NOT NULL CHECK (state IN ('SHREDDING', 'PARTIAL', 'SHREDDED')),
    requested_by      VARCHAR(255) NOT NULL,
    requested_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    shredded_at       TIMESTAMP WITH TIME ZONE,
    records_destroyed BIGINT NOT NULL DEFAULT 0,
    records_retained  BIGINT NOT NULL DEFAULT 0,
    next_due          TIMESTAMP WITH TIME ZONE   -- earliest retain_until among the retained records
);
CREATE INDEX IF NOT EXISTS idx_principal_erasures_due ON principal_erasures (next_due) WHERE state = 'PARTIAL';

-- Legal holds override the policy hold. reason and case_ref must not contain personal data.
CREATE TABLE IF NOT EXISTS legal_holds (
    hold_id      SERIAL PRIMARY KEY,
    principal_id VARCHAR(100) NOT NULL,
    reason       TEXT NOT NULL,
    case_ref     VARCHAR(100),
    placed_by    VARCHAR(255) NOT NULL,
    placed_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    released_at  TIMESTAMP WITH TIME ZONE,
    released_by  VARCHAR(255)
);
CREATE INDEX IF NOT EXISTS idx_legal_holds_open ON legal_holds (principal_id) WHERE released_at IS NULL;

-- Job run history: one row per pass of the erasure job, scheduled or manual, successful or not.
-- Read by the console to tell a quiet job from a broken one. Holds counts and an error message
-- only. Rows older than 90 days are removed by the job itself.
CREATE TABLE IF NOT EXISTS erasure_job_runs (
    run_id              BIGSERIAL PRIMARY KEY,
    trigger_type        VARCHAR(10) NOT NULL CHECK (trigger_type IN ('SCHEDULED', 'MANUAL')),
    started_at          TIMESTAMP WITH TIME ZONE NOT NULL,
    finished_at         TIMESTAMP WITH TIME ZONE,
    status              VARCHAR(10) NOT NULL CHECK (status IN ('OK', 'FAILED')),
    records_drained     BIGINT NOT NULL DEFAULT 0,
    principals_resumed  INT NOT NULL DEFAULT 0,
    principals_shredded INT NOT NULL DEFAULT 0,
    principals_held     INT NOT NULL DEFAULT 0,
    error               VARCHAR(500)
);
CREATE INDEX IF NOT EXISTS idx_erasure_job_runs_started ON erasure_job_runs (started_at DESC);
