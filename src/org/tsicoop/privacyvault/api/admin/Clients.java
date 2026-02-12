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
 * Unified API Management with Post-Transaction Forensic Logging.
 * Consolidates Admin logic and records all lifecycle events to event_log.
 */
public class Clients implements REST {

    private static final String FUNCTION = "_func";

    // Operations
    private static final String GET_ALL_CLIENTS = "get_all_clients";
    private static final String GET_CLIENT_DETAILS = "get_client_details";
    private static final String UPDATE_CLIENT_STATUS = "update_client_status";
    private static final String ROTATE_SECRET = "generate_new_client_secret";
    private static final String REGISTER_CLIENT = "register_new_client";
    private static final String UPDATE_PERMISSIONS = "update_client_permissions";
    private static final String GET_PERMISSIONS = "get_client_permissions";

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = new JSONObject();
        JSONArray outputArray = null;
        
        // Context for logging
        String apiKey = req.getHeader("X-API-Key"); 
        String clientIp = req.getRemoteAddr();
        String userAgent = req.getHeader("User-Agent");
        String func = null;

        try {
            input = InputProcessor.getInput(req);
            func = (String) input.get(FUNCTION);

            if (func != null) {
                if (func.equalsIgnoreCase(GET_ALL_CLIENTS)) {
                    outputArray = getAllClients();
                } else if (func.equalsIgnoreCase(REGISTER_CLIENT)) {
                    output = registerClient(input);
                } else if (func.equalsIgnoreCase(GET_CLIENT_DETAILS)) {
                    output = getClientDetails((String) input.get("api_key"));
                } else if (func.equalsIgnoreCase(UPDATE_CLIENT_STATUS)) {
                    output = updateClientStatus((String) input.get("api_key"), (Boolean) input.get("active"));
                } else if (func.equalsIgnoreCase(ROTATE_SECRET)) {
                    output = rotateSecret((String) input.get("api_key"));
                } else if (func.equalsIgnoreCase(UPDATE_PERMISSIONS)) {
                    output = updatePermissions(input);
                } else if (func.equalsIgnoreCase(GET_PERMISSIONS)) {
                    outputArray = getPermissions((String) input.get("api_key"));
                }
            }
        } catch (Exception e) {
            OutputProcessor.sendError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Management error: " + e.getMessage());
            e.printStackTrace();
            // Log the error case after cleanup
        } finally {
            // Ensure resource cleanup happens BEFORE logging
        }

        // --- POST-FINALLY FORENSIC LOGGING ---
        if (func != null && !func.equalsIgnoreCase(GET_ALL_CLIENTS) && !func.equalsIgnoreCase(GET_PERMISSIONS)) {
            String targetKey = (input != null) ? (String) input.get("api_key") : null;
            String outcome = (output != null && !output.isEmpty()) ? "SUCCESS" : "ERROR";
            logAdminEvent(apiKey, func.toUpperCase(), targetKey, clientIp, userAgent, outcome);
        }

        if (outputArray != null) {
            OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
        } else {
            OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
        }
    }

    private JSONObject updatePermissions(JSONObject input) throws Exception {
        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "INSERT INTO api_user_permissions (api_key, entity_code, can_read, can_write) " +
                         "VALUES (?, ?, ?, ?) ON CONFLICT (api_key, entity_code) " +
                         "DO UPDATE SET can_read = EXCLUDED.can_read, can_write = EXCLUDED.can_write";
            ps = conn.prepareStatement(sql);
            ps.setString(1, (String) input.get("api_key"));
            ps.setString(2, (String) input.get("entity_code"));
            ps.setBoolean(3, (Boolean) input.get("can_read"));
            ps.setBoolean(4, (Boolean) input.get("can_write"));
            ps.executeUpdate();
            return input;
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    private JSONObject registerClient(JSONObject input) throws Exception {
        String name = (String) input.get("clientName");
        if (name == null || isClientNamePresent(name)) throw new Exception("Invalid client name.");
        
        String apiKey = "ext-" + UUID.randomUUID().toString();
        String apiSecret = UUID.randomUUID().toString();
        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("INSERT INTO api_user (api_key, api_secret, client_name, active, created_datetime) VALUES (?, ?, ?, TRUE, ?)");
            ps.setString(1, apiKey); ps.setString(2, apiSecret); ps.setString(3, name);
            ps.setTimestamp(4, Timestamp.valueOf(LocalDateTime.now()));
            ps.executeUpdate();
            JSONObject out = new JSONObject();
            out.put("apiKey", apiKey); out.put("apiSecret", apiSecret); out.put("clientName", name);
            return out;
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    private JSONObject updateClientStatus(String apiKey, boolean status) throws Exception {
        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("UPDATE api_user SET active = ? WHERE api_key = ?");
            ps.setBoolean(1, status); ps.setString(2, apiKey);
            ps.executeUpdate();
            JSONObject out = new JSONObject();
            out.put("apiKey", apiKey); out.put("active", status);
            return out;
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    private JSONObject rotateSecret(String apiKey) throws Exception {
        String newSecret = UUID.randomUUID().toString();
        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("UPDATE api_user SET api_secret = ? WHERE api_key = ?");
            ps.setString(1, newSecret); ps.setString(2, apiKey);
            ps.executeUpdate();
            JSONObject out = new JSONObject();
            out.put("apiKey", apiKey); out.put("apiSecret", newSecret);
            return out;
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    /**
     * Internal helper to record forensic logs to the event_log table.
     */
    private void logAdminEvent(String actorKey, String op, String target, String ip, String ua, String outcome) {
        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = null;
        String machineId = null;
        try {
            pool = new PoolDB();
            machineId = ForensicEngine.getMachineIdentifier();
            conn = pool.getConnection();
            String sql = "INSERT INTO event_log (api_key, operation_type, client_ip, user_agent, machine_id, outcome, log_datetime) VALUES (?, ?, ?, ?, ?, ?, ?)";
            ps = conn.prepareStatement(sql);
            ps.setString(1, actorKey);
            ps.setString(2, "ADMIN_" + op);
            ps.setString(3, ip);
            ps.setString(4, ua);
            ps.setString(5, machineId);
            ps.setString(6, outcome);
            ps.setTimestamp(7, Timestamp.valueOf(LocalDateTime.now()));
            ps.executeUpdate();
        } catch (Exception e) {
            System.err.println("CRITICAL: Admin Audit Failed: " + e.getMessage());
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    // --- HELPER QUERIES ---
    private JSONArray getPermissions(String apiKey) throws Exception {
        JSONArray list = new JSONArray();
        Connection conn = null; PreparedStatement ps = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT entity_code, can_read, can_write FROM api_user_permissions WHERE api_key = ?");
            ps.setString(1, apiKey); rs = ps.executeQuery();
            while (rs.next()) {
                JSONObject obj = new JSONObject();
                obj.put("entity_code", rs.getString("entity_code"));
                obj.put("can_read", rs.getBoolean("can_read"));
                obj.put("can_write", rs.getBoolean("can_write"));
                list.add(obj);
            }
            return list;
        } finally { pool.cleanup(rs, ps, conn); }
    }

    private JSONArray getAllClients() throws Exception {
        JSONArray array = new JSONArray();
        Connection conn = null; PreparedStatement ps = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT api_key, client_name, active, created_datetime FROM api_user ORDER BY created_datetime DESC");
            rs = ps.executeQuery();
            while (rs.next()) {
                JSONObject obj = new JSONObject();
                obj.put("apiKey", rs.getString("api_key")); obj.put("clientName", rs.getString("client_name"));
                obj.put("active", rs.getBoolean("active")); obj.put("createdDatetime", rs.getTimestamp("created_datetime").toString());
                array.add(obj);
            }
            return array;
        } finally { pool.cleanup(rs, ps, conn); }
    }

    private JSONObject getClientDetails(String apiKey) throws Exception {
        Connection conn = null; PreparedStatement ps = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT * FROM api_user WHERE api_key = ?");
            ps.setString(1, apiKey); rs = ps.executeQuery();
            JSONObject obj = new JSONObject();
            if (rs.next()) {
                obj.put("apiKey", rs.getString("api_key")); obj.put("apiSecret", rs.getString("api_secret"));
                obj.put("clientName", rs.getString("client_name")); obj.put("active", rs.getBoolean("active"));
            }
            return obj;
        } finally { pool.cleanup(rs, ps, conn); }
    }

    private boolean isClientNamePresent(String name) throws SQLException {
        PoolDB pool = new PoolDB();
        try (Connection conn = pool.getConnection(); PreparedStatement ps = conn.prepareStatement("SELECT 1 FROM api_user WHERE client_name = ?")) {
            ps.setString(1, name); try (ResultSet rs = ps.executeQuery()) { return rs.next(); }
        }
    }

    @Override public boolean validate(String m, HttpServletRequest req, HttpServletResponse res) { return true; }

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