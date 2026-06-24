package org.tsicoop.privacyvault.api.admin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.tsicoop.privacyvault.framework.*;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Key anchor administration (docs/roadmap.md Phase 1, milestone M2).
 * - get_key_anchor_status : key ring, health and pending re-wrap counts
 * - activate_key_anchor   : create a new ACTIVE key-ring version under an anchor
 * - rewrap_data_keys      : batched LOCAL -> active anchor DEK re-wrap migration
 */
public class KeyAnchor implements Action {

    private static final String FUNCTION = "_func";
    private static final int DEFAULT_BATCH_SIZE = 500;
    private static final int MAX_BATCH_SIZE = 5000;

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        String who = InputProcessor.getEmail(req);
        String clientIp = req.getRemoteAddr();
        String userAgent = req.getHeader("User-Agent");

        try {
            JSONObject input = InputProcessor.getInput(req);
            if (input == null) throw new Exception("Invalid JSON payload.");
            String func = (String) input.get(FUNCTION);

            if (func == null) {
                OutputProcessor.sendError(res, HttpServletResponse.SC_BAD_REQUEST, "Missing _func parameter.");
            } else if (func.equalsIgnoreCase("get_key_anchor_status")) {
                handleStatus(res);
            } else if (func.equalsIgnoreCase("activate_key_anchor")) {
                handleActivate(input, who, clientIp, userAgent, res);
            } else if (func.equalsIgnoreCase("rewrap_data_keys")) {
                handleRewrap(input, who, clientIp, userAgent, res);
            } else {
                OutputProcessor.sendError(res, HttpServletResponse.SC_BAD_REQUEST, "Unknown function: " + func);
            }
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.sendError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Key Anchor Error: " + e.getMessage());
        }
    }

    private void handleStatus(HttpServletResponse res) throws Exception {
        // Re-run the health check when unhealthy so a recovered KMS outage
        // re-opens the data plane without an application restart.
        if (!KmsProviderFactory.isHealthy()) {
            KmsProviderFactory.healthCheck();
        }

        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();

            JSONArray ringArr = new JSONArray();
            int activeVersion = -1;
            ps = conn.prepareStatement("SELECT key_version, anchor_type, anchor_ref, cipher, status, created_at FROM vault_key_ring ORDER BY key_version");
            rs = ps.executeQuery();
            while (rs.next()) {
                JSONObject row = new JSONObject();
                int version = rs.getInt("key_version");
                row.put("key_version", version);
                row.put("anchor_type", rs.getString("anchor_type"));
                row.put("anchor_ref", rs.getString("anchor_ref"));
                row.put("cipher", rs.getString("cipher"));
                row.put("status", rs.getString("status"));
                row.put("created_at", String.valueOf(rs.getTimestamp("created_at")));
                if (KeyRing.STATUS_ACTIVE.equals(rs.getString("status"))) activeVersion = version;
                ringArr.add(row);
            }
            rs.close();
            ps.close();

            JSONObject pending = new JSONObject();
            pending.put("entities", countPending(conn, "vault_entities", "encrypted_data_key", activeVersion));
            pending.put("utilities", countPending(conn, "vault_utilities", "encrypted_key", activeVersion));

            JSONObject out = new JSONObject();
            out.put("success", true);
            out.put("healthy", KmsProviderFactory.isHealthy());
            out.put("health_error", KmsProviderFactory.getHealthError());
            out.put("configured_anchor", KmsProviderFactory.getConfiguredAnchor());
            out.put("active_key_version", activeVersion);
            out.put("key_ring", ringArr);
            out.put("pending_rewrap", pending);
            OutputProcessor.send(res, HttpServletResponse.SC_OK, out);
        } finally {
            pool.cleanup(rs, ps, conn);
        }
    }

    private void handleActivate(JSONObject input, String who, String ip, String ua, HttpServletResponse res) throws Exception {
        String anchorType = ((String) input.get("anchor_type")).trim().toUpperCase();

        // Verify the target anchor is configured and operational before switching
        KmsProvider target;
        try {
            target = KmsProviderFactory.getAnchorProvider(anchorType);
            KmsProviderFactory.verifyRoundTrip(target);
        } catch (Exception e) {
            logEvent(who, "ACTIVATE_KEY_ANCHOR:" + anchorType, ip, ua, "ERROR", e.getMessage());
            OutputProcessor.sendError(res, HttpServletResponse.SC_BAD_REQUEST,
                    "Anchor " + anchorType + " failed verification: " + e.getMessage());
            return;
        }

        String anchorRef = (target instanceof AwsKmsProvider) ? ((AwsKmsProvider) target).getKmsKeyId() : null;

        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        int newVersion;
        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);
            try {
                ps = conn.prepareStatement("UPDATE vault_key_ring SET status = ? WHERE status = ?");
                ps.setString(1, KeyRing.STATUS_DECRYPT_ONLY);
                ps.setString(2, KeyRing.STATUS_ACTIVE);
                ps.executeUpdate();
                ps.close();

                ps = conn.prepareStatement(
                        "INSERT INTO vault_key_ring (anchor_type, anchor_ref, cipher, status) VALUES (?, ?, ?, ?) RETURNING key_version");
                ps.setString(1, anchorType);
                ps.setString(2, anchorRef);
                ps.setString(3, CipherUtil.AES_GCM);
                ps.setString(4, KeyRing.STATUS_ACTIVE);
                rs = ps.executeQuery();
                rs.next();
                newVersion = rs.getInt(1);
                conn.commit();
            } catch (Exception e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
        } finally {
            pool.cleanup(rs, ps, conn);
        }

        KeyRing.refresh();
        KmsProviderFactory.healthCheck();
        logEvent(who, "ACTIVATE_KEY_ANCHOR:" + anchorType + ":v" + newVersion, ip, ua, "SUCCESS", null);

        JSONObject out = new JSONObject();
        out.put("success", true);
        out.put("key_version", newVersion);
        out.put("anchor_type", anchorType);
        out.put("cipher", CipherUtil.AES_GCM);
        OutputProcessor.send(res, HttpServletResponse.SC_OK, out);
    }

    private void handleRewrap(JSONObject input, String who, String ip, String ua, HttpServletResponse res) throws Exception {
        int batchSize = DEFAULT_BATCH_SIZE;
        Object bs = input.get("batch_size");
        if (bs instanceof Number) batchSize = Math.min(((Number) bs).intValue(), MAX_BATCH_SIZE);
        if (batchSize < 1) batchSize = DEFAULT_BATCH_SIZE;

        KmsProvider kms = KmsProviderFactory.getProvider();
        int activeVersion = kms.getActiveKeyVersion();

        Connection conn = null;
        PoolDB pool = new PoolDB();
        long rewrappedEntities;
        long rewrappedUtilities;
        long remainingEntities;
        long remainingUtilities;
        boolean retired = false;
        try {
            conn = pool.getConnection();
            rewrappedEntities = rewrapBatch(conn, kms, activeVersion, batchSize,
                    "vault_entities", "entity_ref", "encrypted_data_key");
            rewrappedUtilities = rewrapBatch(conn, kms, activeVersion, batchSize,
                    "vault_utilities", "utility_ref", "encrypted_key");

            remainingEntities = countPending(conn, "vault_entities", "encrypted_data_key", activeVersion);
            remainingUtilities = countPending(conn, "vault_utilities", "encrypted_key", activeVersion);

            // Retire superseded versions once nothing depends on them; the
            // operator can then drop the legacy master key from the environment.
            if (remainingEntities == 0 && remainingUtilities == 0) {
                PreparedStatement ps = conn.prepareStatement("UPDATE vault_key_ring SET status = ? WHERE status = ?");
                ps.setString(1, KeyRing.STATUS_RETIRED);
                ps.setString(2, KeyRing.STATUS_DECRYPT_ONLY);
                retired = ps.executeUpdate() > 0;
                ps.close();
                if (retired) KeyRing.refresh();
            }
        } catch (Exception e) {
            logEvent(who, "REWRAP_DATA_KEYS:v" + activeVersion, ip, ua, "ERROR", e.getMessage());
            throw e;
        } finally {
            pool.cleanup(null, null, conn);
        }

        logEvent(who, "REWRAP_DATA_KEYS:v" + activeVersion + ":entities=" + rewrappedEntities
                + ":utilities=" + rewrappedUtilities, ip, ua, "SUCCESS", null);

        JSONObject out = new JSONObject();
        out.put("success", true);
        out.put("active_key_version", activeVersion);
        out.put("rewrapped_entities", rewrappedEntities);
        out.put("rewrapped_utilities", rewrappedUtilities);
        out.put("remaining_entities", remainingEntities);
        out.put("remaining_utilities", remainingUtilities);
        out.put("retired_old_versions", retired);
        OutputProcessor.send(res, HttpServletResponse.SC_OK, out);
    }

    /**
     * Re-wraps one batch of DEKs: unwrap with the version recorded on the row,
     * wrap under the ACTIVE anchor. Payload ciphertext (and payload_cipher) are
     * untouched - only the ~48-byte wrapped key changes. vault_utilities also
     * carries a hardware-anchor (machine_id) column; refresh it here too, since
     * a rewrap is exactly the moment the row's encryption context is recomputed
     * from the current node identity (see Utility.java's hardware anchor check).
     */
    private long rewrapBatch(Connection conn, KmsProvider kms, int activeVersion, int batchSize,
                             String table, String refColumn, String keyColumn) throws Exception {
        boolean hasMachineId = "vault_utilities".equals(table);
        String currentMachineId = hasMachineId ? ForensicEngine.getMachineIdentifier() : null;

        PreparedStatement select = null;
        PreparedStatement update = null;
        ResultSet rs = null;
        long count = 0;
        try {
            select = conn.prepareStatement(
                    "SELECT " + refColumn + ", " + keyColumn + ", key_version FROM " + table +
                    " WHERE key_version <> ? AND " + keyColumn + " IS NOT NULL LIMIT ?");
            select.setInt(1, activeVersion);
            select.setInt(2, batchSize);
            rs = select.executeQuery();

            update = conn.prepareStatement(hasMachineId
                    ? "UPDATE " + table + " SET " + keyColumn + " = ?, key_version = ?, machine_id = ? WHERE " + refColumn + " = ?"
                    : "UPDATE " + table + " SET " + keyColumn + " = ?, key_version = ? WHERE " + refColumn + " = ?");
            while (rs.next()) {
                UUID ref = (UUID) rs.getObject(refColumn);
                String wrapped = rs.getString(keyColumn);
                int rowVersion = rs.getInt("key_version");

                String plaintextKeyB64 = kms.decryptDataKey(wrapped, rowVersion);
                String rewrapped = kms.wrapDataKey(plaintextKeyB64);

                update.setString(1, rewrapped);
                update.setInt(2, activeVersion);
                if (hasMachineId) {
                    update.setString(3, currentMachineId);
                    update.setObject(4, ref);
                } else {
                    update.setObject(3, ref);
                }
                update.executeUpdate();
                count++;
            }
            return count;
        } finally {
            if (rs != null) rs.close();
            if (select != null) select.close();
            if (update != null) update.close();
        }
    }

    private long countPending(Connection conn, String table, String keyColumn, int activeVersion) throws SQLException {
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            ps = conn.prepareStatement("SELECT count(*) FROM " + table +
                    " WHERE key_version <> ? AND " + keyColumn + " IS NOT NULL");
            ps.setInt(1, activeVersion);
            rs = ps.executeQuery();
            rs.next();
            return rs.getLong(1);
        } finally {
            if (rs != null) rs.close();
            if (ps != null) ps.close();
        }
    }

    private void logEvent(String who, String op, String ip, String ua, String outcome, String failureReason) {
        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            ps = conn.prepareStatement("INSERT INTO event_log (who, operation_type, client_ip, user_agent, machine_id, outcome, failure_reason, log_datetime) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
            ps.setString(1, "ADMIN:" + who);
            ps.setString(2, op);
            ps.setString(3, ip);
            ps.setString(4, ua);
            ps.setString(5, ForensicEngine.getMachineIdentifier());
            ps.setString(6, outcome);
            ps.setString(7, failureReason);
            ps.setTimestamp(8, Timestamp.valueOf(LocalDateTime.now()));
            ps.executeUpdate();
        } catch (Exception e) {
            System.err.println("CRITICAL: Key Anchor Logging Failed: " + e.getMessage());
        } finally {
            if (pool != null) pool.cleanup(null, ps, conn);
        }
    }

    @Override public boolean validate(String m, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(m)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Use POST for key anchor operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }

    @Override public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "GET method not supported.", req.getRequestURI());
    }

    @Override public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT method not supported.", req.getRequestURI());
    }

    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE method not supported.", req.getRequestURI());
    }
}
