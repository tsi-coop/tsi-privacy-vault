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

public class Permission implements Action {

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            JSONObject input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            switch (func.toLowerCase()) {
                case "get_permissions_by_key":
                    OutputProcessor.send(res, 200, getPermissionsByKey((String) input.get("api_key")));
                    break;
                case "create_permission":
                    OutputProcessor.send(res, 201, createPermission(input));
                    break;
                case "delete_permission":
                    OutputProcessor.send(res, 200, deletePermission(input));
                    break;
                case "get_resource_list":
                    OutputProcessor.send(res, 200, getResourceList());
                    break;
                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown function", req.getRequestURI());
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * UPDATED: Pulls master metadata from vault_entity_master.
     */
    private JSONObject getResourceList() throws SQLException {
        JSONObject result = new JSONObject();
        JSONArray resources = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            // Pulling from the Master table for ENTITY and Utility table for UTILITY
            String sql = 
                "SELECT 'ENTITY' as type, entity_code as id, entity_name as label FROM vault_entity_master WHERE active = true " +
                "UNION ALL " +
                "SELECT 'UTILITY' as type, utility_id as id, label FROM vault_utilities WHERE active = true " +
                "ORDER BY type, label";
            
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject item = new JSONObject();
                item.put("type", rs.getString("type"));
                item.put("id", rs.getString("id"));
                item.put("label", rs.getString("label"));
                resources.add(item);
            }
            result.put("resources", resources);
            result.put("_success", true);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

    /**
     * Mechanism to maintain Read/Write flags at the API Key level.
     */
    private JSONObject createPermission(JSONObject input) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;

        // The UNIQUE(api_key, resource_type, resource_id) constraint in the DB 
        // ensures we only have one row per key-resource pair, managing R/W flags there.
        String sql = "INSERT INTO permissions (api_key, resource_type, resource_id, can_read, can_write, granted_by) " +
                     "VALUES (?, ?, ?, ?, ?, ?) " +
                     "ON CONFLICT (api_key, resource_type, resource_id) " +
                     "DO UPDATE SET can_read = EXCLUDED.can_read, can_write = EXCLUDED.can_write, granted_by = EXCLUDED.granted_by";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, (String) input.get("api_key"));
            pstmt.setString(2, (String) input.get("resource_type"));
            pstmt.setString(3, (String) input.get("resource_id"));
            pstmt.setBoolean(4, (Boolean) input.get("can_read"));
            pstmt.setBoolean(5, (Boolean) input.get("can_write"));
            pstmt.setString(6, (String) input.get("granted_by"));

            pstmt.executeUpdate();
            JSONObject res = new JSONObject();
            res.put("_success", true);
            return res;
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    private JSONObject getPermissionsByKey(String apiKey) throws SQLException {
        JSONObject result = new JSONObject();
        JSONArray permissions = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            String sql = "SELECT permission_id, resource_type, resource_id, can_read, can_write FROM permissions WHERE api_key = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, apiKey);
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject perm = new JSONObject();
                perm.put("permission_id", rs.getInt("permission_id"));
                perm.put("resource_type", rs.getString("resource_type"));
                perm.put("resource_id", rs.getString("resource_id"));
                perm.put("can_read", rs.getBoolean("can_read"));
                perm.put("can_write", rs.getBoolean("can_write"));
                permissions.add(perm);
            }
            result.put("permissions", permissions);
            result.put("_success", true);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

    private JSONObject deletePermission(JSONObject input) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("DELETE FROM permissions WHERE permission_id = ?");
            Object pid = input.get("permission_id");
            int id = (pid instanceof Number) ? ((Number) pid).intValue() : Integer.parseInt(pid.toString());
            pstmt.setInt(1, id);
            pstmt.executeUpdate();
            JSONObject res = new JSONObject();
            res.put("_success", true);
            return res;
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    @Override public boolean validate(String m, HttpServletRequest q, HttpServletResponse r) { return "POST".equalsIgnoreCase(m); }
    @Override public void get(HttpServletRequest q, HttpServletResponse r) {}
    @Override public void delete(HttpServletRequest q, HttpServletResponse r) {}
    @Override public void put(HttpServletRequest q, HttpServletResponse r) {}
}