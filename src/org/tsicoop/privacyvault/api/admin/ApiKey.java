package org.tsicoop.privacyvault.api.admin;

import org.tsicoop.privacyvault.framework.Action;
import org.tsicoop.privacyvault.framework.PoolDB;
import org.tsicoop.privacyvault.framework.InputProcessor;
import org.tsicoop.privacyvault.framework.OutputProcessor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import java.sql.*;
import java.util.UUID;

/**
 * Manages API credentials for the TSI Privacy Vault.
 * Fully aligned with the 'api_user' schema.
 */
public class ApiKey implements Action {

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
                case "get_all_keys":
                    OutputProcessor.send(res, 200, getAllKeys());
                    break;
                case "create_key":
                    OutputProcessor.send(res, 201, createApiKey(input));
                    break;
                case "update_key":
                    OutputProcessor.send(res, 200, updateApiKey(input));
                    break;
                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown function", req.getRequestURI());
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Lists all machine users from the api_user table.
     */
    private JSONObject getAllKeys() throws SQLException {
        JSONObject result = new JSONObject();
        JSONArray keys = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            // Using your schema: api_key, client_name, active
            String sql = "SELECT api_key, client_name, active, created_datetime FROM api_user ORDER BY created_datetime DESC";
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject key = new JSONObject();
                key.put("api_key_id", rs.getString("api_key")); // JSON key for UI
                key.put("label", rs.getString("client_name"));  // Maps to client_name
                key.put("active", rs.getBoolean("active"));
                // Note: Schema currently doesn't have permissions columns; defaulting to false or add them to DDL
                key.put("can_read", true); 
                key.put("can_write", true);
                keys.add(key);
            }
            result.put("keys", keys);
            result.put("_success", true);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

    /**
     * Generates a new api_key and api_secret pair.
     */
    private JSONObject createApiKey(JSONObject input) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;

        String newKey = "PV-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        String newSecret = UUID.randomUUID().toString().replace("-", ""); // Secure random secret
        
        String sql = "INSERT INTO api_user (api_key, api_secret, client_name, active) VALUES (?, ?, ?, ?)";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, newKey);
            pstmt.setString(2, newSecret);
            pstmt.setString(3, (String) input.get("label")); // client_name
            pstmt.setBoolean(4, (Boolean) input.get("active"));

            pstmt.executeUpdate();

            JSONObject res = new JSONObject();
            res.put("api_key_id", newKey);
            res.put("api_secret", newSecret); // Shared only once
            res.put("_created", true);
            return res;
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    /**
     * Updates status or name of the machine user.
     */
    private JSONObject updateApiKey(JSONObject input) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;

        String sql = "UPDATE api_user SET client_name = ?, active = ? WHERE api_key = ?";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, (String) input.get("label"));
            pstmt.setBoolean(2, (Boolean) input.get("active"));
            pstmt.setString(3, (String) input.get("api_key_id"));

            int rows = pstmt.executeUpdate();
            JSONObject res = new JSONObject();
            res.put("_updated", rows > 0);
            res.put("_success", true);
            return res;
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
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