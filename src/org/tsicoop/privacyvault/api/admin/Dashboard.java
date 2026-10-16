package org.tsicoop.privacyvault.api.admin;

import org.tsicoop.privacyvault.framework.Action;
import org.tsicoop.privacyvault.framework.FileStoreFactory;
import org.tsicoop.privacyvault.framework.InputProcessor;
import org.tsicoop.privacyvault.framework.OutputProcessor;
import org.tsicoop.privacyvault.framework.PoolDB;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import java.sql.*;

public class Dashboard implements Action {

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            JSONObject input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing _func", req.getRequestURI());
                return;
            }

            if ("get_dashboard_stats".equalsIgnoreCase(func)) {
                OutputProcessor.send(res, 200, getDashboardStats());
            } else {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown function", req.getRequestURI());
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    private JSONObject getDashboardStats() throws SQLException {
        JSONObject data = new JSONObject();
        PoolDB pool = new PoolDB();
        Connection conn = null;

        try {
            conn = pool.getConnection();

            // 1. Total Records (Vault Registry)
            data.put("total_records", getSimpleCount(conn, pool, "SELECT COUNT(*) FROM vault_entities"));

            // 2. Active API Keys (Fixed: Now using your 'api_user' table)
            data.put("active_keys", getSimpleCount(conn, pool, "SELECT COUNT(*) FROM api_user WHERE active = true"));

            // 3. Entity Flavors (Fixed: Now using 'vault_entity_master')
            data.put("entity_flavors", getSimpleCount(conn, pool, "SELECT COUNT(*) FROM vault_entity_master WHERE active = true"));

            // 4. Auth Failures
            data.put("auth_failures", getSimpleCount(conn, pool, "SELECT COUNT(*) FROM event_log WHERE outcome = 'DENIED'"));

            // 5. Recent Logs
            data.put("recent_logs", getRecentAuditLogs(conn, pool));

            // 6. File storage backend (read-only: set with TSI_PRIVACY_VAULT_FILE_STORE)
            data.put("file_storage", getFileStorage(conn, pool));

            // 7. Erasure Register and legal holds (counts only, no principal ids)
            data.put("erasure", getErasure(conn));

            data.put("_success", true);
        } finally {
            if (pool != null && conn != null) pool.cleanup(null, null, conn);
        }
        return data;
    }

    /**
     * Active backend, its health, and how many live FILE records each backend holds. The counts
     * degrade to an error note instead of failing the dashboard, for example before
     * db/02_file_storage.sql has been applied.
     */
    private JSONObject getFileStorage(Connection conn, PoolDB pool) {
        JSONObject fs = FileStoreFactory.describeActive();
        fs.put("healthy", FileStoreFactory.isHealthy());
        fs.put("health_error", FileStoreFactory.getHealthError());

        JSONObject counts = new JSONObject();
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            pstmt = conn.prepareStatement(
                "SELECT storage_backend, COUNT(*) FROM vault_entities " +
                "WHERE entity_type = 'FILE' AND erased_at IS NULL GROUP BY storage_backend");
            rs = pstmt.executeQuery();
            while (rs.next()) {
                counts.put(rs.getString(1), rs.getLong(2));
            }
            fs.put("files_by_backend", counts);
        } catch (SQLException e) {
            fs.put("files_by_backend", null);
            fs.put("counts_error", "File counts unavailable. Apply db/02_file_storage.sql and db/03_erasure.sql.");
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException ignored) { }
            try { if (pstmt != null) pstmt.close(); } catch (SQLException ignored) { }
        }
        return fs;
    }

    /**
     * Erasure Register by state, shreds that look stuck, partial shreds whose retention has run
     * out, and open legal holds. Counts only: principal ids stay on the Erasure page. Degrades to
     * an error note when db/03_erasure.sql has not been applied.
     */
    private JSONObject getErasure(Connection conn) {
        JSONObject er = new JSONObject();
        JSONObject byState = new JSONObject();
        byState.put("SHREDDING", 0L);
        byState.put("PARTIAL", 0L);
        byState.put("SHREDDED", 0L);
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            pstmt = conn.prepareStatement("SELECT state, COUNT(*) FROM principal_erasures GROUP BY state");
            rs = pstmt.executeQuery();
            while (rs.next()) byState.put(rs.getString(1), rs.getLong(2));
            rs.close(); pstmt.close();
            er.put("by_state", byState);

            pstmt = conn.prepareStatement(
                "SELECT " +
                "COUNT(*) FILTER (WHERE state = 'SHREDDING' AND requested_at < CURRENT_TIMESTAMP - INTERVAL '1 day'), " +
                "COUNT(*) FILTER (WHERE state = 'PARTIAL' AND next_due <= CURRENT_TIMESTAMP) " +
                "FROM principal_erasures");
            rs = pstmt.executeQuery();
            if (rs.next()) {
                er.put("stuck", rs.getLong(1));
                er.put("retention_elapsed", rs.getLong(2));
            }
            rs.close(); pstmt.close();

            pstmt = conn.prepareStatement(
                "SELECT COUNT(*), MIN(placed_at) FROM legal_holds WHERE released_at IS NULL");
            rs = pstmt.executeQuery();
            if (rs.next()) {
                er.put("open_legal_holds", rs.getLong(1));
                java.sql.Timestamp oldest = rs.getTimestamp(2);
                er.put("oldest_hold", oldest == null ? null : oldest.toInstant().toString());
            }
        } catch (SQLException e) {
            er.put("by_state", null);
            er.put("error", "Erasure stats unavailable. Apply db/03_erasure.sql.");
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException ignored) { }
            try { if (pstmt != null) pstmt.close(); } catch (SQLException ignored) { }
        }
        try {
            JSONObject job = org.tsicoop.privacyvault.framework.ErasureService.jobStatus(1);
            JSONObject j = new JSONObject();
            j.put("status", job.get("status"));
            j.put("last_run", job.get("last_run"));
            j.put("last_success", job.get("last_success"));
            er.put("job", j);
        } catch (Exception e) {
            er.put("job", null);
        }
        return er;
    }

    private int getSimpleCount(Connection conn, PoolDB pool, String sql) throws SQLException {
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();
            return rs.next() ? rs.getInt(1) : 0;
        } finally {
            if (pool != null) pool.cleanup(rs, pstmt, null);
        }
    }

    private JSONArray getRecentAuditLogs(Connection conn, PoolDB pool) throws SQLException {
        JSONArray logs = new JSONArray();
        // Fixed: Updated columns to match your 'event_log' schema
        String sql = "SELECT log_datetime, who, operation_type, outcome, machine_id " +
                     "FROM event_log ORDER BY log_datetime DESC LIMIT 5";
        
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject log = new JSONObject();
                log.put("timestamp", rs.getTimestamp("log_datetime").toInstant().toString());
                log.put("who", rs.getString("who")); // Principal
                log.put("operation_type", rs.getString("operation_type"));
                log.put("outcome", rs.getString("outcome"));
                log.put("machine_id", rs.getString("machine_id")); 
                logs.add(log);
            }
        } finally {
            if (pool != null) pool.cleanup(rs, pstmt, null);
        }
        return logs;
    }

    @Override public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) { 
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Use POST for login.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
}