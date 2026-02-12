package org.tsicoop.privacyvault.api.admin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.tsicoop.privacyvault.framework.*;
import java.sql.*;
import java.time.LocalDateTime;

public class VaultEntityMaster implements REST {

    private static final String FUNCTION = "_func";
    private static final String GET_ALL_ENTITIES = "get_all_entities";
    private static final String UPDATE_ENTITY = "update_entity";

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONArray outputArray = null;
        JSONObject output = null;

        // Context for forensic logging
        String apiKey = req.getHeader("X-API-Key");
        String clientIp = req.getRemoteAddr();
        String userAgent = req.getHeader("User-Agent");
        String func = null;
        String outcome = "DENIED";
        String failureReason = null;

        try {
            input = InputProcessor.getInput(req);
            func = (String) input.get(FUNCTION);

            if (func != null) {
                if (func.equalsIgnoreCase(GET_ALL_ENTITIES)) {
                    outputArray = getAllEntities();
                    outcome = "SUCCESS";
                } else if (func.equalsIgnoreCase(UPDATE_ENTITY)) {
                    output = updateEntity(input);
                    outcome = "SUCCESS";
                }
            }
            
        } catch (Exception e) {
            outcome = "ERROR";
            failureReason = e.getMessage();
            OutputProcessor.sendError(res, 500, "Server Error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Resource cleanup happens here before logging
        }

        // --- POST-FINALLY FORENSIC LOGGING ---
        if (func != null && apiKey != null) {
            String entityCode = (input != null) ? (String) input.get("entityCode") : null;
            logMasterEvent(apiKey, func.toUpperCase(), entityCode, clientIp, userAgent, outcome, failureReason);
        }

        if (outputArray != null) OutputProcessor.send(res, 200, outputArray);
        else if (output != null) OutputProcessor.send(res, 200, output);
    }

    private void logMasterEvent(String key, String op, String entity, String ip, String ua, String outcome, String reason) {
        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = null;
        String machineId = null;
        try {
            pool = new PoolDB();
            machineId = ForensicEngine.getMachineIdentifier();
            conn = pool.getConnection();
            String sql = "INSERT INTO event_log (api_key, operation_type, entity_code, client_ip, user_agent, machine_id, outcome, failure_reason, log_datetime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
            ps = conn.prepareStatement(sql);
            ps.setString(1, key);
            ps.setString(2, "ADMIN_" + op);
            ps.setString(3, entity);
            ps.setString(4, ip);
            ps.setString(5, ua);
            ps.setString(6, machineId);
            ps.setString(7, outcome);
            ps.setString(8, reason);
            ps.setTimestamp(9, Timestamp.valueOf(LocalDateTime.now()));
            ps.executeUpdate();
        } catch (Exception e) {
            System.err.println("CRITICAL: Master Audit Failed: " + e.getMessage());
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    private JSONArray getAllEntities() throws Exception {
        JSONArray list = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        // Expanded query to include flavor and forensic metadata
        String sql = "SELECT * FROM vault_entity_master ORDER BY entity_name";
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement(sql);
            rs = ps.executeQuery();
            while (rs.next()) {
                JSONObject obj = new JSONObject();
                obj.put("entityCode", rs.getString("entity_code"));
                obj.put("entityName", rs.getString("entity_name"));
                obj.put("flavor", rs.getString("flavor"));
                obj.put("validationRegex", rs.getString("validation_regex"));
                obj.put("mimeTypes", rs.getString("mime_types"));
                obj.put("hashingAlgorithm", rs.getString("hashing_algorithm"));
                obj.put("active", rs.getBoolean("active"));
                list.add(obj);
            }
        } finally {
            pool.cleanup(rs, ps, conn);
        }
        return list;
    }

    private JSONObject updateEntity(JSONObject input) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement ps = null;
        try {
            String code = (String) input.get("entityCode");
            String sql = isPresent(code) 
                ? "UPDATE vault_entity_master SET entity_name=?, flavor=?, validation_regex=?, mime_types=?, active=? WHERE entity_code=?"
                : "INSERT INTO vault_entity_master (entity_name, flavor, validation_regex, mime_types, active, entity_code) VALUES (?,?,?,?,?,?)";

            conn = pool.getConnection();
            ps = conn.prepareStatement(sql);
            ps.setString(1, (String) input.get("entityName"));
            ps.setString(2, (String) input.get("flavor")); // ID, DATA, or FILE
            ps.setString(3, (String) input.get("validationRegex"));
            ps.setString(4, (String) input.get("mimeTypes")); // New field for FILE flavor
            ps.setBoolean(5, (Boolean) input.get("active"));
            ps.setString(6, code);

            ps.executeUpdate();
            return input;
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    private boolean isPresent(String code) throws SQLException {
        PoolDB pool = new PoolDB();
        try (Connection conn = pool.getConnection();
             PreparedStatement ps = conn.prepareStatement("SELECT 1 FROM vault_entity_master WHERE entity_code=?")) {
            ps.setString(1, code);
            try (ResultSet rs = ps.executeQuery()) { return rs.next(); }
        }
    }

    // Standard REST Method Stubs
    @Override public void get(HttpServletRequest req, HttpServletResponse res) { /* Error Response */ }
    @Override public void put(HttpServletRequest req, HttpServletResponse res) { /* Error Response */ }
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) { /* Error Response */ }
    @Override public boolean validate(String m, HttpServletRequest req, HttpServletResponse res) { return true; }
}