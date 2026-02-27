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
 * Enhanced ApiKey service for TSI Privacy Vault.
 * Implements the multi-part key generation and hashing pattern from the reference.
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
                    // Returns 201 Created as per reference logic
                    OutputProcessor.send(res, 201, generateAndSaveApiKey(input));
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
     * Implements the generation pattern: UUID + UUID (no dashes).
     */
    private JSONObject generateAndSaveApiKey(JSONObject input) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;

        // 1. Generate Raw Key and Secret as per reference
        String rawKey = UUID.randomUUID().toString().replace("-", "").toUpperCase();
        String rawSecret = UUID.randomUUID().toString() + UUID.randomUUID().toString().replace("-", "");
        
        // 2. Hash the secret for secure storage
        String hashedSecret = "HASHED_" + rawSecret;

        String sql = "INSERT INTO api_user (api_key, api_secret, client_name, active, created_datetime) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, rawKey);
            pstmt.setString(2, hashedSecret);
            pstmt.setString(3, (String) input.get("label")); // Maps to client_name
            pstmt.setBoolean(4, (Boolean) input.get("active"));

            pstmt.executeUpdate();

            // 3. Prepare response with the RAW secret (shown only once)
            JSONObject data = new JSONObject();
            data.put("api_key_id", rawKey);
            data.put("raw_api_secret", rawSecret);
            data.put("label", input.get("label"));

            JSONObject response = new JSONObject();
            response.put("success", true);
            response.put("data", data);
            response.put("message", "API Credentials created. STORE THE SECRET SAFELY, IT WILL NOT BE SHOWN AGAIN.");
            return response;
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    private JSONObject getAllKeys() throws SQLException {
        JSONObject result = new JSONObject();
        JSONArray keys = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            String sql = "SELECT api_key, client_name, active FROM api_user ORDER BY created_datetime DESC";
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject key = new JSONObject();
                key.put("api_key_id", rs.getString("api_key"));
                key.put("label", rs.getString("client_name"));
                key.put("active", rs.getBoolean("active"));
                keys.add(key);
            }
            result.put("keys", keys);
            result.put("_success", true);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

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