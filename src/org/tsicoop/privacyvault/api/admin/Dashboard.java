package org.tsicoop.privacyvault.api.admin;

import org.tsicoop.privacyvault.framework.Action;
import org.tsicoop.privacyvault.framework.InputProcessor;
import org.tsicoop.privacyvault.framework.OutputProcessor;
import org.tsicoop.privacyvault.framework.PoolDB;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import java.sql.*;

/**
 * Dashboard service aligned with vault_registry schema.
 */
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

            switch (func.toLowerCase()) {
                case "get_dashboard_stats":
                    OutputProcessor.send(res, 200, getDashboardStats());
                    break;
                default:
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

            // 1. Total Records (From vault_registry)
            data.put("total_records", getSimpleCount(conn, pool, "SELECT COUNT(*) FROM vault_registry"));

            // 2. Active API Keys (Assuming api_user_permissions handles key status)
            data.put("active_keys", getSimpleCount(conn, pool, "SELECT COUNT(*) FROM api_user_permissions WHERE can_read = true OR can_write = true"));

            // 3. Entity Flavors (Distinct entity types in registry: ID or FILE)
            data.put("entity_flavors", getSimpleCount(conn, pool, "SELECT COUNT(DISTINCT entity_type) FROM vault_registry"));

            // 4. Auth Failures (From forensic event log)
            data.put("auth_failures", getSimpleCount(conn, pool, "SELECT COUNT(*) FROM event_log WHERE outcome = 'DENIED'"));

            // 5. Recent Logs (For dashboard live stream)
            data.put("recent_logs", getRecentAuditLogs(conn, pool));

            data.put("_success", true);
        } finally {
            if (pool != null && conn != null) pool.cleanup(null, null, conn);
        }
        return data;
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
        // Selecting forensic metadata including machine_id for BSA compliance
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
                log.put("who", rs.getString("who"));
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

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method);
    }

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'get'");
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'delete'");
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'put'");
    }
}