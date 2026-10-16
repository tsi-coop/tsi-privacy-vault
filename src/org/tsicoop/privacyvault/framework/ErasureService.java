package org.tsicoop.privacyvault.framework;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

/**
 * Crypto-erasure by principal (docs/design/architecture.md, "per-principal keys and
 * crypto-erasure"). Every record already has its own DEK, so erasure is key
 * destruction: nulling the wrapped DEK makes the ciphertext unrecoverable
 * wherever it was copied.
 *
 * A record moves through two steps. Condemning sets erased_at, after which
 * reads fail closed. The drain then destroys the key, the content, the blind
 * index entries and any external object. Both steps are idempotent, so a crash
 * mid-run resumes instead of leaving a half-done purge.
 *
 * Policy (retention rules, holds) is enforced here, never decided here.
 */
public class ErasureService {

    public static final String STATE_SHREDDING = "SHREDDING";
    public static final String STATE_PARTIAL = "PARTIAL";
    public static final String STATE_SHREDDED = "SHREDDED";

    public static final String ENV_JOB_MINUTES = "TSI_PRIVACY_VAULT_ERASURE_JOB_MINUTES";
    private static final int DRAIN_BATCH = 200;

    /** Outcome of an operation: an HTTP-like status plus a body for the caller. */
    public static class Outcome {
        public final int status;
        public final JSONObject body;

        Outcome(int status, JSONObject body) {
            this.status = status;
            this.body = body;
        }

        static Outcome error(int status, String message) {
            JSONObject b = new JSONObject();
            b.put("success", false);
            b.put("error", message);
            return new Outcome(status, b);
        }
    }

    // ------------------------------------------------------------------ shred

    /** Erases a principal's erasable records. Refused whole when a legal hold is open. */
    public static Outcome shredPrincipal(String principalId, String actor, String ip, String ua) throws Exception {
        PoolDB pool = new PoolDB(false);
        Connection conn = pool.getConnection();
        try {
            lockPrincipal(conn, principalId);
            if (hasOpenHold(conn, principalId)) {
                conn.rollback();
                audit("ERASURE_SHRED:" + principalId, actor, ip, ua, "DENIED", "open legal hold");
                return Outcome.error(409, "Refused: an open legal hold exists for this principal. No keys were touched.");
            }
            String state = registerState(conn, principalId);
            if (state == null) {
                try (PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO principal_erasures (principal_id, state, requested_by) VALUES (?, ?, ?)")) {
                    ps.setString(1, principalId);
                    ps.setString(2, STATE_SHREDDING);
                    ps.setString(3, actor);
                    ps.executeUpdate();
                }
            } else if (STATE_PARTIAL.equals(state)) {
                setState(conn, principalId, STATE_SHREDDING);
            }
            long condemned = condemnErasable(conn, principalId);
            conn.commit();
            audit("ERASURE_SHRED:" + principalId + ":condemned=" + condemned, actor, ip, ua, "SUCCESS", null);
        } catch (Exception e) {
            rollbackQuietly(conn);
            throw e;
        } finally {
            pool.cleanup(null, null, conn);
        }

        drain(Integer.MAX_VALUE);
        JSONObject body = finalizePrincipal(principalId, actor, ip, ua);
        return new Outcome(200, body);
    }

    /** Erases one record by reference key, subject to its retention and its principal's holds. */
    public static Outcome shredRecord(String reference, String actor, String ip, String ua) throws Exception {
        UUID ref = UUID.fromString(reference);
        String principalId;
        PoolDB pool = new PoolDB(false);
        Connection conn = pool.getConnection();
        try {
            String retention;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT principal_id, erased_at, retain_until FROM vault_entities WHERE entity_ref = ? FOR UPDATE")) {
                ps.setObject(1, ref);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        conn.rollback();
                        return Outcome.error(404, "Reference not found.");
                    }
                    principalId = rs.getString("principal_id");
                    if (rs.getTimestamp("erased_at") != null) {
                        conn.rollback();
                        JSONObject b = new JSONObject();
                        b.put("success", true);
                        b.put("already_erased", true);
                        return new Outcome(200, b);
                    }
                    Timestamp until = rs.getTimestamp("retain_until");
                    if (until != null && until.after(new Timestamp(System.currentTimeMillis()))) {
                        retention = "retained until " + until.toInstant();
                    } else {
                        retention = null;
                    }
                }
            }
            if (principalId != null && hasOpenHold(conn, principalId)) {
                conn.rollback();
                audit("ERASURE_SHRED_RECORD:" + reference, actor, ip, ua, "DENIED", "open legal hold");
                return Outcome.error(409, "Refused: an open legal hold exists for this record's principal.");
            }
            if (retention != null) {
                conn.rollback();
                audit("ERASURE_SHRED_RECORD:" + reference, actor, ip, ua, "DENIED", "retention: " + retention);
                return Outcome.error(409, "Refused: record is under retention (" + retention + ").");
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE vault_entities SET erased_at = CURRENT_TIMESTAMP WHERE entity_ref = ?")) {
                ps.setObject(1, ref);
                ps.executeUpdate();
            }
            conn.commit();
        } catch (Exception e) {
            rollbackQuietly(conn);
            throw e;
        } finally {
            pool.cleanup(null, null, conn);
        }

        drain(Integer.MAX_VALUE);
        audit("ERASURE_SHRED_RECORD:" + reference, actor, ip, ua, "SUCCESS", null);
        if (principalId != null && registerExists(principalId)) {
            finalizePrincipal(principalId, actor, ip, ua);
        }
        JSONObject b = new JSONObject();
        b.put("success", true);
        b.put("reference_key", reference);
        return new Outcome(200, b);
    }

    // ------------------------------------------------------------------ drain

    /**
     * Destroys key material of condemned records, at most maxBatches batches per
     * call. Returns the number of records completed. The wrapped DEK goes first
     * and in its own commit, so the unrecoverable state is reached before the
     * slower external object delete is attempted. A failed object delete leaves
     * storage_key set and the row stays in the queue for the next run.
     */
    public static long drain(int maxBatches) throws Exception {
        long completed = 0;
        for (int batch = 0; batch < maxBatches; batch++) {
            List<Object[]> rows = new ArrayList<>();
            PoolDB pool = new PoolDB();
            Connection conn = pool.getConnection();
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT entity_ref, storage_backend, storage_key FROM vault_entities " +
                    "WHERE erased_at IS NOT NULL AND (encrypted_data_key IS NOT NULL OR storage_key IS NOT NULL) " +
                    "ORDER BY erased_at LIMIT ?")) {
                ps.setInt(1, DRAIN_BATCH);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        rows.add(new Object[]{rs.getObject("entity_ref"), rs.getString("storage_backend"), rs.getString("storage_key")});
                    }
                }
            } finally {
                pool.cleanup(null, null, conn);
            }
            if (rows.isEmpty()) break;

            long doneThisBatch = 0;
            for (Object[] row : rows) {
                if (destroy((UUID) row[0], (String) row[1], (String) row[2])) {
                    doneThisBatch++;
                }
            }
            completed += doneThisBatch;
            if (doneThisBatch == 0) break; // only failing object deletes left; retry on the next run
        }
        return completed;
    }

    private static boolean destroy(UUID ref, String backend, String storageKey) {
        PoolDB pool = null;
        Connection conn = null;
        try {
            pool = new PoolDB(false);
            conn = pool.getConnection();
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE vault_entities SET encrypted_data_key = NULL, encrypted_content = NULL, " +
                    "hashed_value_sha256 = NULL, content_sha256 = NULL, file_name = NULL WHERE entity_ref = ?")) {
                ps.setObject(1, ref);
                ps.executeUpdate();
            }
            try (PreparedStatement ps = conn.prepareStatement("DELETE FROM vault_search_index WHERE entity_ref = ?")) {
                ps.setObject(1, ref);
                ps.executeUpdate();
            }
            conn.commit();

            if (storageKey != null) {
                FileStore store = FileStoreFactory.getExternal(backend);
                if (store != null) {
                    store.delete(storageKey);
                }
                try (PreparedStatement ps = conn.prepareStatement("UPDATE vault_entities SET storage_key = NULL WHERE entity_ref = ?")) {
                    ps.setObject(1, ref);
                    ps.executeUpdate();
                }
                conn.commit();
            }
            return true;
        } catch (Exception e) {
            if (conn != null) rollbackQuietly(conn);
            System.err.println("ERASURE: could not finish destroying " + ref + ": " + e.getMessage());
            return false;
        } finally {
            if (pool != null) {
                try { pool.cleanup(null, null, conn); } catch (Exception ignored) { }
            }
        }
    }

    // ------------------------------------------------------------------ register

    /**
     * Recomputes the register entry from the records themselves: SHREDDING while
     * the queue is not empty, otherwise SHREDDED or PARTIAL with the retained
     * count and next_due. Returns the certificate summary.
     */
    public static JSONObject finalizePrincipal(String principalId, String actor, String ip, String ua) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = pool.getConnection();
        try {
            long pending = scalar(conn, "SELECT count(*) FROM vault_entities WHERE principal_id = ? AND erased_at IS NOT NULL " +
                    "AND (encrypted_data_key IS NOT NULL OR storage_key IS NOT NULL)", principalId);
            long destroyed = scalar(conn, "SELECT count(*) FROM vault_entities WHERE principal_id = ? AND erased_at IS NOT NULL", principalId);
            long retained = scalar(conn, "SELECT count(*) FROM vault_entities WHERE principal_id = ? AND erased_at IS NULL", principalId);
            Timestamp nextDue = null;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT min(retain_until) FROM vault_entities WHERE principal_id = ? AND erased_at IS NULL AND retain_until IS NOT NULL")) {
                ps.setString(1, principalId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) nextDue = rs.getTimestamp(1);
                }
            }

            String state = pending > 0 ? STATE_SHREDDING : (retained == 0 ? STATE_SHREDDED : STATE_PARTIAL);
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE principal_erasures SET state = ?, records_destroyed = ?, records_retained = ?, next_due = ?, " +
                    "shredded_at = CASE WHEN ? = 'SHREDDED' THEN COALESCE(shredded_at, CURRENT_TIMESTAMP) ELSE shredded_at END " +
                    "WHERE principal_id = ?")) {
                ps.setString(1, state);
                ps.setLong(2, destroyed);
                ps.setLong(3, retained);
                ps.setTimestamp(4, nextDue);
                ps.setString(5, state);
                ps.setString(6, principalId);
                ps.executeUpdate();
            }
            audit("ERASURE_RESULT:" + principalId + ":" + state + ":destroyed=" + destroyed + ":retained=" + retained,
                    actor, ip, ua, "SUCCESS", null);

            JSONObject out = new JSONObject();
            out.put("success", true);
            out.put("principal_id", principalId);
            out.put("state", state);
            out.put("records_destroyed", destroyed);
            out.put("records_retained", retained);
            out.put("next_due", nextDue == null ? null : nextDue.toInstant().toString());
            return out;
        } finally {
            pool.cleanup(null, null, conn);
        }
    }

    private static boolean registerExists(String principalId) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = pool.getConnection();
        try {
            return registerState(conn, principalId) != null;
        } finally {
            pool.cleanup(null, null, conn);
        }
    }

    /** True once the principal has any erasure request. New stores for it are refused. */
    public static boolean isPrincipalErased(Connection conn, String principalId) throws SQLException {
        return registerState(conn, principalId) != null;
    }

    /** Serialises stores and shreds for one principal for the rest of the transaction. */
    public static void lockPrincipal(Connection conn, String principalId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?))")) {
            ps.setString(1, "principal:" + principalId);
            ps.execute();
        }
    }

    private static String registerState(Connection conn, String principalId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT state FROM principal_erasures WHERE principal_id = ?")) {
            ps.setString(1, principalId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    private static void setState(Connection conn, String principalId, String state) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("UPDATE principal_erasures SET state = ? WHERE principal_id = ?")) {
            ps.setString(1, state);
            ps.setString(2, principalId);
            ps.executeUpdate();
        }
    }

    private static boolean hasOpenHold(Connection conn, String principalId) throws SQLException {
        return scalar(conn, "SELECT count(*) FROM legal_holds WHERE principal_id = ? AND released_at IS NULL", principalId) > 0;
    }

    /** Marks erasable records: retain_until empty or past. */
    private static long condemnErasable(Connection conn, String principalId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE vault_entities SET erased_at = CURRENT_TIMESTAMP WHERE principal_id = ? AND erased_at IS NULL " +
                "AND (retain_until IS NULL OR retain_until <= CURRENT_TIMESTAMP)")) {
            ps.setString(1, principalId);
            return ps.executeUpdate();
        }
    }

    // ------------------------------------------------------------------ holds

    public static Outcome placeHold(String principalId, String reason, String caseRef, String actor, String ip, String ua) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = pool.getConnection();
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO legal_holds (principal_id, reason, case_ref, placed_by) VALUES (?, ?, ?, ?) RETURNING hold_id")) {
            ps.setString(1, principalId);
            ps.setString(2, reason);
            ps.setString(3, caseRef);
            ps.setString(4, actor);
            int id;
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                id = rs.getInt(1);
            }
            audit("LEGAL_HOLD_PLACE:" + principalId + ":hold=" + id, actor, ip, ua, "SUCCESS", null);
            JSONObject b = new JSONObject();
            b.put("success", true);
            b.put("hold_id", id);
            return new Outcome(201, b);
        } finally {
            pool.cleanup(null, null, conn);
        }
    }

    public static Outcome releaseHold(int holdId, String actor, String ip, String ua) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = pool.getConnection();
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE legal_holds SET released_at = CURRENT_TIMESTAMP, released_by = ? " +
                "WHERE hold_id = ? AND released_at IS NULL RETURNING principal_id")) {
            ps.setString(1, actor);
            ps.setInt(2, holdId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return Outcome.error(404, "No open hold with that id.");
                audit("LEGAL_HOLD_RELEASE:" + rs.getString(1) + ":hold=" + holdId, actor, ip, ua, "SUCCESS", null);
            }
            JSONObject b = new JSONObject();
            b.put("success", true);
            return new Outcome(200, b);
        } finally {
            pool.cleanup(null, null, conn);
        }
    }

    public static JSONArray listHolds(boolean openOnly) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = pool.getConnection();
        JSONArray out = new JSONArray();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT hold_id, principal_id, reason, case_ref, placed_by, placed_at, released_at, released_by FROM legal_holds " +
                (openOnly ? "WHERE released_at IS NULL " : "") + "ORDER BY placed_at DESC LIMIT 500");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                JSONObject h = new JSONObject();
                h.put("hold_id", rs.getInt("hold_id"));
                h.put("principal_id", rs.getString("principal_id"));
                h.put("reason", rs.getString("reason"));
                h.put("case_ref", rs.getString("case_ref"));
                h.put("placed_by", rs.getString("placed_by"));
                h.put("placed_at", String.valueOf(rs.getTimestamp("placed_at")));
                h.put("released_at", rs.getTimestamp("released_at") == null ? null : rs.getTimestamp("released_at").toString());
                h.put("released_by", rs.getString("released_by"));
                out.add(h);
            }
        } finally {
            pool.cleanup(null, null, conn);
        }
        return out;
    }

    // ------------------------------------------------------------------ reporting

    public static JSONArray register(String stateFilter) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = pool.getConnection();
        JSONArray out = new JSONArray();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT p.principal_id, p.state, p.requested_by, p.requested_at, p.shredded_at, p.records_destroyed, " +
                "p.records_retained, p.next_due, " +
                "EXISTS (SELECT 1 FROM legal_holds h WHERE h.principal_id = p.principal_id AND h.released_at IS NULL) AS on_hold " +
                "FROM principal_erasures p WHERE (?::text IS NULL OR p.state = ?) ORDER BY p.requested_at DESC LIMIT 500")) {
            ps.setString(1, stateFilter);
            ps.setString(2, stateFilter);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    JSONObject r = new JSONObject();
                    r.put("principal_id", rs.getString("principal_id"));
                    r.put("state", rs.getString("state"));
                    r.put("requested_by", rs.getString("requested_by"));
                    r.put("requested_at", String.valueOf(rs.getTimestamp("requested_at")));
                    r.put("shredded_at", rs.getTimestamp("shredded_at") == null ? null : rs.getTimestamp("shredded_at").toString());
                    r.put("records_destroyed", rs.getLong("records_destroyed"));
                    long retained = rs.getLong("records_retained");
                    Timestamp due = rs.getTimestamp("next_due");
                    r.put("records_retained", retained);
                    r.put("next_due", due == null ? null : due.toInstant().toString());
                    r.put("on_hold", rs.getBoolean("on_hold"));
                    out.add(r);
                }
            }
        } finally {
            pool.cleanup(null, null, conn);
        }
        return out;
    }

    /**
     * Erasure certificate: what was destroyed and what was retained with its
     * retain_until, so the operator can show a regulator why each record was kept.
     * Lists reference keys and entity codes only.
     */
    public static Outcome certificate(String principalId) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = pool.getConnection();
        try {
            JSONObject cert = null;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT state, requested_by, requested_at, shredded_at FROM principal_erasures WHERE principal_id = ?")) {
                ps.setString(1, principalId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        cert = new JSONObject();
                        cert.put("principal_id", principalId);
                        cert.put("state", rs.getString("state"));
                        cert.put("requested_by", rs.getString("requested_by"));
                        cert.put("requested_at", String.valueOf(rs.getTimestamp("requested_at")));
                        cert.put("shredded_at", rs.getTimestamp("shredded_at") == null ? null : rs.getTimestamp("shredded_at").toString());
                    }
                }
            }
            if (cert == null) return Outcome.error(404, "No erasure request for this principal.");

            JSONArray destroyed = new JSONArray();
            JSONArray retained = new JSONArray();
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT entity_ref, id_type_code, entity_type, erased_at, retain_until, " +
                    "(encrypted_data_key IS NULL AND storage_key IS NULL) AS complete " +
                    "FROM vault_entities WHERE principal_id = ? ORDER BY created_at")) {
                ps.setString(1, principalId);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        JSONObject r = new JSONObject();
                        r.put("reference_key", rs.getString("entity_ref"));
                        r.put("entity_code", rs.getString("id_type_code"));
                        r.put("flavor", rs.getString("entity_type"));
                        if (rs.getTimestamp("erased_at") != null) {
                            r.put("erased_at", rs.getTimestamp("erased_at").toInstant().toString());
                            r.put("key_destroyed", rs.getBoolean("complete"));
                            destroyed.add(r);
                        } else {
                            Timestamp until = rs.getTimestamp("retain_until");
                            r.put("retain_until", until == null ? null : until.toInstant().toString());
                            retained.add(r);
                        }
                    }
                }
            }
            cert.put("destroyed", destroyed);
            cert.put("retained", retained);
            cert.put("machine_id", ForensicEngine.getMachineIdentifier());
            cert.put("generated_at", LocalDateTime.now().toString());
            cert.put("success", true);
            return new Outcome(200, cert);
        } finally {
            pool.cleanup(null, null, conn);
        }
    }

    // ------------------------------------------------------------------ job

    /**
     * One pass of the scheduled job: finish any interrupted drain, finalize
     * principals still SHREDDING, and shred PARTIAL principals whose retention
     * has expired unless a hold is open. Safe to run on every node.
     */
    public static JSONObject runDue() throws Exception {
        return runDue(TRIGGER_SCHEDULED);
    }

    /** One pass, recorded in erasure_job_runs whether it succeeds or fails. */
    public static synchronized JSONObject runDue(String trigger) throws Exception {
        Timestamp started = new Timestamp(System.currentTimeMillis());
        try {
            JSONObject out = runPass();
            recordRun(trigger, started, "OK", out, null);
            return out;
        } catch (Exception e) {
            recordRun(trigger, started, "FAILED", null, e.getMessage());
            throw e;
        }
    }

    private static JSONObject runPass() throws Exception {
        long drained = drain(Integer.MAX_VALUE);

        List<String> shredding = principalsWhere("state = 'SHREDDING'");
        List<String> due = principalsWhere("state = 'PARTIAL' AND next_due IS NOT NULL AND next_due <= CURRENT_TIMESTAMP");

        int resumed = 0;
        for (String p : shredding) {
            finalizePrincipal(p, "SYSTEM", "127.0.0.1", "ErasureService");
            resumed++;
        }
        int shredded = 0;
        int skippedHeld = 0;
        for (String p : due) {
            PoolDB pool = new PoolDB(false);
            Connection conn = pool.getConnection();
            boolean proceed = false;
            try {
                lockPrincipal(conn, p);
                if (hasOpenHold(conn, p)) {
                    skippedHeld++;
                } else {
                    setState(conn, p, STATE_SHREDDING);
                    condemnErasable(conn, p);
                    proceed = true;
                }
                conn.commit();
            } catch (Exception e) {
                rollbackQuietly(conn);
                throw e;
            } finally {
                pool.cleanup(null, null, conn);
            }
            if (proceed) {
                drain(Integer.MAX_VALUE);
                finalizePrincipal(p, "SYSTEM", "127.0.0.1", "ErasureService");
                shredded++;
            }
        }
        JSONObject out = new JSONObject();
        out.put("success", true);
        out.put("records_drained", drained);
        out.put("principals_resumed", resumed);
        out.put("principals_shredded", shredded);
        out.put("principals_held", skippedHeld);
        return out;
    }

    public static final String TRIGGER_SCHEDULED = "SCHEDULED";
    public static final String TRIGGER_MANUAL = "MANUAL";
    private static final int RUN_RETENTION_DAYS = 90;

    /** Interval of the scheduler in minutes. 0 means disabled, -1 means not started in this process. */
    private static volatile long intervalMinutes = -1;

    /**
     * Writes one row to erasure_job_runs. Never throws: losing the history must not fail the job,
     * and the table is absent until db/03_erasure.sql has been re-applied. The error text carries
     * the exception message only, which names no personal data.
     */
    private static void recordRun(String trigger, Timestamp started, String status, JSONObject r, String error) {
        PoolDB pool = null;
        Connection conn = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO erasure_job_runs (trigger_type, started_at, finished_at, status, records_drained, " +
                    "principals_resumed, principals_shredded, principals_held, error) " +
                    "VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?)")) {
                ps.setString(1, trigger);
                ps.setTimestamp(2, started);
                ps.setString(3, status);
                ps.setLong(4, r == null ? 0 : ((Number) r.get("records_drained")).longValue());
                ps.setInt(5, r == null ? 0 : ((Number) r.get("principals_resumed")).intValue());
                ps.setInt(6, r == null ? 0 : ((Number) r.get("principals_shredded")).intValue());
                ps.setInt(7, r == null ? 0 : ((Number) r.get("principals_held")).intValue());
                String err = error == null ? null : (error.length() > 500 ? error.substring(0, 500) : error);
                ps.setString(8, err);
                ps.executeUpdate();
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "DELETE FROM erasure_job_runs WHERE started_at < CURRENT_TIMESTAMP - (? || ' days')::interval")) {
                ps.setInt(1, RUN_RETENTION_DAYS);
                ps.executeUpdate();
            }
        } catch (Exception e) {
            System.err.println("Could not record erasure job run: " + e.getMessage());
        } finally {
            if (pool != null && conn != null) pool.cleanup(null, null, conn);
        }
    }

    /**
     * Job health for the console: configuration, last run, last success, consecutive failures,
     * a status (HEALTHY, FAILING, OVERDUE, WAITING, DISABLED), 30 day totals and the latest runs.
     * OVERDUE means no successful run within twice the interval.
     */
    public static JSONObject jobStatus(int limit) throws Exception {
        JSONObject out = new JSONObject();
        long interval = intervalMinutes;
        JSONObject config = new JSONObject();
        config.put("interval_minutes", interval);
        config.put("enabled", interval > 0);
        config.put("env", ENV_JOB_MINUTES);
        out.put("config", config);

        PoolDB pool = new PoolDB();
        Connection conn = pool.getConnection();
        try {
            JSONArray runs = new JSONArray();
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT run_id, trigger_type, started_at, finished_at, status, records_drained, " +
                    "principals_resumed, principals_shredded, principals_held, error " +
                    "FROM erasure_job_runs ORDER BY started_at DESC LIMIT ?")) {
                ps.setInt(1, Math.max(1, Math.min(limit, 200)));
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        JSONObject r = new JSONObject();
                        r.put("run_id", rs.getLong("run_id"));
                        r.put("trigger", rs.getString("trigger_type"));
                        r.put("started_at", rs.getTimestamp("started_at").toInstant().toString());
                        Timestamp fin = rs.getTimestamp("finished_at");
                        r.put("finished_at", fin == null ? null : fin.toInstant().toString());
                        r.put("status", rs.getString("status"));
                        r.put("records_drained", rs.getLong("records_drained"));
                        r.put("principals_resumed", rs.getInt("principals_resumed"));
                        r.put("principals_shredded", rs.getInt("principals_shredded"));
                        r.put("principals_held", rs.getInt("principals_held"));
                        r.put("error", rs.getString("error"));
                        runs.add(r);
                    }
                }
            }
            out.put("runs", runs);

            Timestamp lastOk = null;
            long consecutiveFailures = 0;
            long overdueMs = 0;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT " +
                    "(SELECT MAX(started_at) FROM erasure_job_runs WHERE status = 'OK'), " +
                    "(SELECT COUNT(*) FROM erasure_job_runs WHERE status = 'FAILED' AND started_at > " +
                    "   COALESCE((SELECT MAX(started_at) FROM erasure_job_runs WHERE status = 'OK'), '-infinity')), " +
                    "(SELECT COUNT(*) FROM erasure_job_runs)");
                 ResultSet rs = ps.executeQuery()) {
                rs.next();
                lastOk = rs.getTimestamp(1);
                consecutiveFailures = rs.getLong(2);
                out.put("total_runs", rs.getLong(3));
            }
            out.put("last_success", lastOk == null ? null : lastOk.toInstant().toString());
            out.put("consecutive_failures", consecutiveFailures);
            out.put("last_run", runs.isEmpty() ? null : ((JSONObject) runs.get(0)));

            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT COUNT(*), COUNT(*) FILTER (WHERE status = 'FAILED'), COALESCE(SUM(records_drained), 0), " +
                    "COALESCE(SUM(principals_resumed), 0), COALESCE(SUM(principals_shredded), 0), COALESCE(SUM(principals_held), 0) " +
                    "FROM erasure_job_runs WHERE started_at > CURRENT_TIMESTAMP - INTERVAL '30 days'");
                 ResultSet rs = ps.executeQuery()) {
                rs.next();
                JSONObject t = new JSONObject();
                t.put("runs", rs.getLong(1));
                t.put("failed", rs.getLong(2));
                t.put("records_drained", rs.getLong(3));
                t.put("principals_resumed", rs.getLong(4));
                t.put("principals_shredded", rs.getLong(5));
                t.put("principals_held", rs.getLong(6));
                out.put("totals_30d", t);
            }

            String status;
            long now = System.currentTimeMillis();
            if (interval == 0) {
                status = "DISABLED";
            } else if (!runs.isEmpty() && "FAILED".equals(((JSONObject) runs.get(0)).get("status"))) {
                status = "FAILING";
            } else if (interval < 0 || runs.isEmpty()) {
                status = "WAITING";
            } else if (lastOk == null || now - lastOk.getTime() > 2 * interval * 60_000L) {
                status = "OVERDUE";
            } else {
                status = "HEALTHY";
            }
            out.put("status", status);
            if (interval > 0 && lastOk != null) {
                config.put("next_expected", new Timestamp(lastOk.getTime() + interval * 60_000L).toInstant().toString());
            }
        } finally {
            pool.cleanup(null, null, conn);
        }
        out.put("success", true);
        return out;
    }

    private static List<String> principalsWhere(String condition) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = pool.getConnection();
        List<String> out = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement("SELECT principal_id FROM principal_erasures WHERE " + condition);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) out.add(rs.getString(1));
        } finally {
            pool.cleanup(null, null, conn);
        }
        return out;
    }

    private static ScheduledExecutorService scheduler;

    /** Starts the periodic job. Interval from TSI_PRIVACY_VAULT_ERASURE_JOB_MINUTES (default 60, 0 disables). */
    public static synchronized void startScheduler() {
        if (scheduler != null) return;
        long minutes = 60;
        String v = System.getenv(ENV_JOB_MINUTES);
        if (v != null && !v.trim().isEmpty()) {
            try {
                minutes = Long.parseLong(v.trim());
            } catch (NumberFormatException e) {
                System.err.println("WARN: " + ENV_JOB_MINUTES + " is not a number, using 60");
            }
        }
        intervalMinutes = Math.max(0, minutes);
        if (minutes <= 0) {
            System.out.println("Erasure job disabled (" + ENV_JOB_MINUTES + "=0)");
            return;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "erasure-job");
            t.setDaemon(true);
            return t;
        });
        // First run shortly after boot resumes anything a crash left half done.
        scheduler.scheduleWithFixedDelay(() -> {
            try {
                JSONObject r = runDue(TRIGGER_SCHEDULED);
                if (((Number) r.get("records_drained")).longValue() > 0 || ((Number) r.get("principals_shredded")).intValue() > 0) {
                    System.out.println("Erasure job: " + r.toJSONString());
                }
            } catch (Exception e) {
                System.err.println("Erasure job failed: " + e.getMessage());
            }
        }, 30, minutes * 60, TimeUnit.SECONDS);
        System.out.println("Erasure job scheduled every " + minutes + " minutes");
    }

    // ------------------------------------------------------------------ helpers

    private static long scalar(Connection conn, String sql, String arg) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, arg);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getLong(1);
            }
        }
    }

    private static void rollbackQuietly(Connection conn) {
        try {
            conn.rollback();
        } catch (Exception ignored) {
            // connection is being discarded
        }
    }

    /** Writes an erasure event to event_log. Never throws. */
    public static void audit(String operation, String actor, String ip, String ua, String outcome, String reason) {
        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            ps = conn.prepareStatement("INSERT INTO event_log (who, operation_type, client_ip, user_agent, machine_id, outcome, failure_reason, log_datetime) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
            ps.setString(1, actor.startsWith("VAULT:") ? actor : "ADMIN:" + actor);
            ps.setString(2, operation);
            ps.setString(3, ip == null ? "127.0.0.1" : ip);
            ps.setString(4, ua);
            ps.setString(5, ForensicEngine.getMachineIdentifier());
            ps.setString(6, outcome);
            ps.setString(7, reason);
            ps.setTimestamp(8, Timestamp.valueOf(LocalDateTime.now()));
            ps.executeUpdate();
        } catch (Exception e) {
            System.err.println("CRITICAL: Erasure audit logging failed: " + e.getMessage());
        } finally {
            if (pool != null) {
                try { pool.cleanup(null, ps, conn); } catch (Exception ignored) { }
            }
        }
    }
}
