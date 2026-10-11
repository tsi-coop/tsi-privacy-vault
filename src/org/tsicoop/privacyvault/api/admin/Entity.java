package org.tsicoop.privacyvault.api.admin;

import org.tsicoop.privacyvault.framework.Action;
import org.tsicoop.privacyvault.framework.EntityRules;
import org.tsicoop.privacyvault.framework.InputProcessor;
import org.tsicoop.privacyvault.framework.OutputProcessor;
import org.tsicoop.privacyvault.framework.PoolDB;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import java.sql.*;

/**
 * Entity service for managing Vault flavors (ID, DATA, FILE).
 * Supports listing, creating, and updating entity definitions.
 */
public class Entity implements Action {

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
                case "get_all_entities":
                    OutputProcessor.send(res, 200, getAllEntities());
                    break;
                case "create_entity":
                    handleSave(input, false, req, res);
                    break;
                case "update_entity":
                    handleSave(input, true, req, res);
                    break;
                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown function", req.getRequestURI());
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Validates the definition, then saves it. Invalid definitions get a 400 with the reason.
     */
    private void handleSave(JSONObject input, boolean isUpdate, HttpServletRequest req, HttpServletResponse res) throws Exception {
        Integer maxSizeKb;
        try {
            maxSizeKb = parseMaxSizeKb(input.get("max_size_kb"));
        } catch (NumberFormatException e) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "max_size_kb must be a whole number.", req.getRequestURI());
            return;
        }

        EntityRules.Definition def = EntityRules.validateDefinition(
                (String) input.get("entity_code"),
                (String) input.get("entity_name"),
                (String) input.get("flavor"),
                (String) input.get("validation_regex"),
                (String) input.get("mime_types"),
                maxSizeKb,
                !isUpdate);
        if (def.error != null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", def.error, req.getRequestURI());
            return;
        }

        // Persist the normalized values, not the raw input.
        input.put("flavor", def.flavor);
        input.put("validation_regex", def.validationRegex);
        input.put("mime_types", def.mimeTypes);
        input.put("max_size_kb", def.maxSizeKb);

        try {
            OutputProcessor.send(res, 200, saveEntity(input, isUpdate));
        } catch (SQLException e) {
            if ("23505".equals(e.getSQLState())) {
                OutputProcessor.errorResponse(res, 409, "Conflict", "An entity with this code already exists.", req.getRequestURI());
            } else {
                throw e;
            }
        }
    }

    private static Integer parseMaxSizeKb(Object raw) {
        if (raw == null) return null;
        if (raw instanceof Number) return ((Number) raw).intValue();
        String v = raw.toString().trim();
        return v.isEmpty() ? null : Integer.valueOf(v);
    }

    /**
     * Retrieves all master entity definitions.
     */
    private JSONObject getAllEntities() throws SQLException {
        JSONArray entities = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            String sql = "SELECT * FROM vault_entity_master ORDER BY entity_code ASC";
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject entity = new JSONObject();
                entity.put("entity_code", rs.getString("entity_code"));
                entity.put("entity_name", rs.getString("entity_name"));
                entity.put("flavor", rs.getString("flavor"));
                entity.put("validation_regex", rs.getString("validation_regex"));
                entity.put("mime_types", rs.getString("mime_types"));
                int maxKb = rs.getInt("max_size_kb");
                entity.put("max_size_kb", rs.wasNull() ? null : maxKb);
                entity.put("active", rs.getBoolean("active"));
                entities.add(entity);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        JSONObject response = new JSONObject();
        response.put("entities", entities);
        response.put("_success", true);
        return response;
    }

    /**
     * Handles both creation and updates for entity definitions.
     */
    private JSONObject saveEntity(JSONObject input, boolean isUpdate) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;

        String sql = isUpdate 
            ? "UPDATE vault_entity_master SET entity_name = ?, flavor = ?, validation_regex = ?, mime_types = ?, active = ?, max_size_kb = ? WHERE entity_code = ?"
            : "INSERT INTO vault_entity_master (entity_name, flavor, validation_regex, mime_types, active, max_size_kb, entity_code) VALUES (?, ?, ?, ?, ?, ?, ?)";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, (String) input.get("entity_name"));
            pstmt.setString(2, (String) input.get("flavor"));
            pstmt.setString(3, (String) input.get("validation_regex"));
            pstmt.setString(4, (String) input.get("mime_types"));
            pstmt.setBoolean(5, (Boolean) input.get("active"));
            Integer maxKb = (Integer) input.get("max_size_kb");
            if (maxKb == null) {
                pstmt.setNull(6, Types.INTEGER);
            } else {
                pstmt.setInt(6, maxKb);
            }
            pstmt.setString(7, (String) input.get("entity_code"));

            int rows = pstmt.executeUpdate();
            JSONObject res = new JSONObject();
            res.put("_created", !isUpdate && rows > 0);
            res.put("_updated", isUpdate && rows > 0);
            res.put("_success", rows > 0);
            return res;
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Use POST for login.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
       OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "GET method not supported.", req.getRequestURI());
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE method not supported.", req.getRequestURI());
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT method not supported.", req.getRequestURI());
    }
}