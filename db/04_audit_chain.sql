-- 04_audit_chain.sql
-- Tamper-evident audit log. Every event_log row carries the hash of the row before it, so an
-- edited, removed or re-ordered row breaks the chain from that point on.
-- Runs after 03_erasure.sql on fresh installs. For existing databases, apply manually:
--   psql -U tsi_admin -d tsi_privacy_vault -f 04_audit_chain.sql
-- Rows that exist when this runs are chained in log_id order. History before that moment is
-- protected from then on, not retroactively.
--
-- This detects tampering; it does not prevent a database owner from rewriting the whole chain.
-- Record head_seq/head_hash from verify_event_log_chain() somewhere outside this database
-- (for example in a ticket or a signed report) and pass them back when you verify.

ALTER TABLE event_log
    ADD COLUMN IF NOT EXISTS chain_seq BIGINT,
    ADD COLUMN IF NOT EXISTS prev_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS row_hash  VARCHAR(64);

-- Hash over every audited field plus the previous hash. Timestamps are rendered in UTC so the
-- result does not depend on the session time zone.
CREATE OR REPLACE FUNCTION event_log_compute_hash(p_prev TEXT, r event_log) RETURNS TEXT AS $$
    SELECT encode(sha256(convert_to(
        p_prev || '|' || jsonb_build_array(
            r.chain_seq, r.log_id, r.who, r.operation_type, r.entity_code, r.entity_ref,
            r.utility_ref, r.client_ip, r.user_agent, r.machine_id, r.outcome, r.failure_reason,
            to_char(r.log_datetime AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US')
        )::text, 'UTF8')), 'hex');
$$ LANGUAGE sql STABLE;

-- One-time backfill of rows written before the chain existed.
DO $$
DECLARE
    r       event_log;
    seq     BIGINT := 0;
    prev    TEXT := repeat('0', 64);
    h       TEXT;
BEGIN
    IF EXISTS (SELECT 1 FROM event_log WHERE chain_seq IS NOT NULL) THEN
        RETURN;  -- already chained
    END IF;
    FOR r IN SELECT * FROM event_log ORDER BY log_id LOOP
        seq := seq + 1;
        r.chain_seq := seq;
        h := event_log_compute_hash(prev, r);
        UPDATE event_log SET chain_seq = seq, prev_hash = prev, row_hash = h WHERE log_id = r.log_id;
        prev := h;
    END LOOP;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_event_log_chain_seq ON event_log(chain_seq);

-- Chains each new row onto the last. The advisory lock serializes writers for the length of
-- the inserting transaction (all callers insert and commit immediately), so two concurrent
-- events can never fork the chain.
CREATE OR REPLACE FUNCTION event_log_chain_insert() RETURNS TRIGGER AS $$
DECLARE
    last_seq  BIGINT;
    last_hash TEXT;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('tsi_event_log_chain'));
    SELECT chain_seq, row_hash INTO last_seq, last_hash
      FROM event_log WHERE chain_seq IS NOT NULL ORDER BY chain_seq DESC LIMIT 1;
    NEW.chain_seq := COALESCE(last_seq, 0) + 1;
    NEW.prev_hash := COALESCE(last_hash, repeat('0', 64));
    NEW.row_hash  := event_log_compute_hash(NEW.prev_hash, NEW);
    RETURN NEW;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_event_log_chain ON event_log;
CREATE TRIGGER trg_event_log_chain BEFORE INSERT ON event_log
    FOR EACH ROW EXECUTE FUNCTION event_log_chain_insert();

-- The audit log is append-only.
CREATE OR REPLACE FUNCTION event_log_block_change() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'event_log is append-only (% blocked)', TG_OP;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_event_log_immutable ON event_log;
CREATE TRIGGER trg_event_log_immutable BEFORE UPDATE OR DELETE ON event_log
    FOR EACH ROW EXECUTE FUNCTION event_log_block_change();

DROP TRIGGER IF EXISTS trg_event_log_no_truncate ON event_log;
CREATE TRIGGER trg_event_log_no_truncate BEFORE TRUNCATE ON event_log
    FOR EACH STATEMENT EXECUTE FUNCTION event_log_block_change();

-- Walks the chain from p_from_seq (default: the start) and reports the first problem.
-- Detects: edited fields, a broken prev link, a gap (deleted row) and rows written with the
-- trigger bypassed. Truncation of the tail is only detectable against a previously recorded head.
CREATE OR REPLACE FUNCTION verify_event_log_chain(p_from_seq BIGINT DEFAULT NULL)
RETURNS TABLE (valid BOOLEAN, rows_checked BIGINT, first_bad_seq BIGINT, reason TEXT,
               head_seq BIGINT, head_hash TEXT) AS $$
DECLARE
    r            event_log;
    start_seq    BIGINT := GREATEST(COALESCE(p_from_seq, 1), 1);
    exp_seq      BIGINT := start_seq;
    exp_prev     TEXT;
    checked      BIGINT := 0;
BEGIN
    IF EXISTS (SELECT 1 FROM event_log WHERE chain_seq IS NULL) THEN
        RETURN QUERY SELECT FALSE, 0::BIGINT, NULL::BIGINT,
            'rows exist outside the chain (written with the trigger bypassed)'::TEXT, NULL::BIGINT, NULL::TEXT;
        RETURN;
    END IF;

    IF start_seq = 1 THEN
        exp_prev := repeat('0', 64);
    ELSE
        SELECT e.row_hash INTO exp_prev FROM event_log e WHERE e.chain_seq = start_seq - 1;
        IF exp_prev IS NULL THEN
            RETURN QUERY SELECT FALSE, 0::BIGINT, start_seq - 1, 'row before the start point is missing'::TEXT,
                NULL::BIGINT, NULL::TEXT;
            RETURN;
        END IF;
    END IF;

    FOR r IN SELECT * FROM event_log WHERE chain_seq >= start_seq ORDER BY chain_seq LOOP
        IF r.chain_seq <> exp_seq THEN
            RETURN QUERY SELECT FALSE, checked, exp_seq, 'row missing from the chain'::TEXT, NULL::BIGINT, NULL::TEXT;
            RETURN;
        END IF;
        IF r.prev_hash IS DISTINCT FROM exp_prev THEN
            RETURN QUERY SELECT FALSE, checked, r.chain_seq, 'prev_hash does not match the previous row'::TEXT,
                NULL::BIGINT, NULL::TEXT;
            RETURN;
        END IF;
        IF r.row_hash IS DISTINCT FROM event_log_compute_hash(r.prev_hash, r) THEN
            RETURN QUERY SELECT FALSE, checked, r.chain_seq, 'row content does not match its hash'::TEXT,
                NULL::BIGINT, NULL::TEXT;
            RETURN;
        END IF;
        exp_prev := r.row_hash;
        exp_seq := exp_seq + 1;
        checked := checked + 1;
    END LOOP;

    RETURN QUERY SELECT TRUE, checked, NULL::BIGINT, NULL::TEXT,
        CASE WHEN checked > 0 THEN exp_seq - 1 ELSE NULL END, exp_prev;
END $$ LANGUAGE plpgsql STABLE;
