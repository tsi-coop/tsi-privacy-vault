package org.tsicoop.privacyvault.api.admin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.tsicoop.privacyvault.framework.Action;
import org.tsicoop.privacyvault.framework.BSACertificateGenerator;
import org.tsicoop.privacyvault.framework.InputProcessor;
import org.tsicoop.privacyvault.framework.OutputProcessor;
import org.tsicoop.privacyvault.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Handles Legal Evidence requirements under BSA 2023.
 * Specifically isolates transactions with forensic anchors (UUIDs).
 */
public class Legal implements Action {

    private static final String FUNCTION = "_func";
    private static final String GET_LEGAL_LEDGER = "get_legal_ledger";
     private final BSACertificateGenerator certGenerator = new BSACertificateGenerator();


    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "POST required for legal ledger.", req.getRequestURI());
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = new JSONObject();
        String func = null;
        try {
            input = InputProcessor.getInput(req);
            func = (String) input.get(FUNCTION);           
          
            switch (func.toLowerCase()) {            
                case "get_legal_ledger":
                    output = getLegalLedger(input);
                    break;
                case "generate_entity_bsa_certificate":
                    handleEntityCertGen((String) input.get("referenceKey"), res);
                    break;
                default:
                    OutputProcessor.sendError(res, 404, "Function not found.");
            }
        } catch (Exception e) {
            OutputProcessor.sendError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Forensic query failed");
            e.printStackTrace();
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
    }

    private void handleEntityCertGen(String ref, HttpServletResponse res) throws Exception {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        JSONObject forensicData = new JSONObject();
        
        try {
            conn = pool.getConnection();
            
            // SQL remains the same, pulling from event_log
            String sql = "SELECT v.hashed_value_sha256, e.machine_id, e.client_ip, e.log_datetime " +
                        "FROM vault_entities v " +
                        "JOIN event_log e ON v.entity_ref = e.entity_ref " +
                        "WHERE v.entity_ref = ? " + 
                        "ORDER BY e.log_datetime ASC LIMIT 1";
            
            ps = conn.prepareStatement(sql);
            ps.setObject(1, java.util.UUID.fromString(ref)); 
            rs = ps.executeQuery();
            
            if (rs.next()) {
                // MATCH THESE KEYS TO YOUR PDF TEMPLATE
                forensicData.put("sha256_hash", rs.getString("hashed_value_sha256")); // HASH (SHA256)
                
                // Map 'machine_id' to the 'Make & Model' and 'MAC/Cloud ID' fields
                forensicData.put("machine_model", rs.getString("machine_id")); // Fills Make & Model
                forensicData.put("mac_address", rs.getString("machine_id"));     // Fills MAC/Cloud ID
                
                // Map 'log_datetime' to the 'Timestamp' field
                forensicData.put("anchor_time", rs.getTimestamp("log_datetime").toString()); 
                
                // Map 'client_ip' or status to 'System Status' and 'Software Source'
                forensicData.put("health_status", "ACTIVE_SECURE_VAULT");
                forensicData.put("software_version", "TSI_PRIVACY_VAULT_V0.1");
            }
        } finally {
            pool.cleanup(rs, ps, conn);
        }

        if (forensicData.isEmpty()) {
            throw new Exception("Forensic metadata missing for reference: " + ref);
        }

        res.setContentType("application/pdf");
        res.setHeader("Content-Disposition", "attachment; filename=\"BSA_Certificate_" + ref + ".pdf\"");
        
        // This call will now find the data it needs because the keys match
        certGenerator.streamSection63Certificate(forensicData, res.getOutputStream());
    }


    /**
     * Retrieves only certifiable audit logs containing Reference Keys or Utility Refs.
     */
    private JSONObject getLegalLedger(JSONObject input) throws Exception {
        JSONArray outputArray = new JSONArray();
        JSONObject responseBody = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        String searchTerm = (String) input.get("search_term");
        int page = 0;
        int size = 20;

        try {
            if (input.get("page") != null) page = ((Long) input.get("page")).intValue();
            if (input.get("size") != null) size = ((Long) input.get("size")).intValue();

            // SQL specifically filters for entries that have a forensic anchor (UUID)
            // It excludes general logs that only have "SUCCESS" in the outcome field.
            StringBuilder sqlBuilder = new StringBuilder(
                "SELECT log_id, who, operation_type, entity_ref, utility_ref, client_ip, machine_id, log_datetime " +
                "FROM event_log WHERE (entity_ref IS NOT NULL)"
            );

            List<Object> sqlParams = new ArrayList<>();

            // Dynamic Search for UUIDs
            if (searchTerm != null && !searchTerm.trim().isEmpty()) {
                sqlBuilder.append(" AND (entity_ref::text LIKE ? OR utility_ref::text LIKE ? OR who LIKE ?)");
                String likePattern = "%" + searchTerm.trim() + "%";
                sqlParams.add(likePattern);
                sqlParams.add(likePattern);
                sqlParams.add(likePattern);
            }

            sqlBuilder.append(" ORDER BY log_datetime DESC LIMIT ? OFFSET ?");

            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());

            int idx = 1;
            for (Object param : sqlParams) pstmt.setObject(idx++, param);
            pstmt.setInt(idx++, size);
            pstmt.setInt(idx++, page * size);

            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject entry = new JSONObject();
                entry.put("logId", rs.getLong("log_id"));
                entry.put("apiKey", rs.getString("who"));
                entry.put("operationType", rs.getString("operation_type"));

                // Prioritize the UUID anchor for the frontend
                String ref = rs.getString("entity_ref");
                String util = rs.getString("utility_ref");
                entry.put("referenceKey", ref != null ? ref : util);
                entry.put("refType", ref != null ? "ENTITY" : "UTILITY");

                entry.put("clientIp", rs.getString("client_ip"));
                entry.put("machineId", rs.getString("machine_id"));
                entry.put("logDatetime", rs.getTimestamp("log_datetime").toLocalDateTime().toString());
                outputArray.add(entry);
            }

            responseBody.put("content", outputArray);
            responseBody.put("page", page);
            responseBody.put("size", size);

        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return responseBody;
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {}

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {}

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return InputProcessor.validate(req, res);
    }
}