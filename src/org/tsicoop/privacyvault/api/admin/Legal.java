package org.tsicoop.privacyvault.api.admin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.tsicoop.privacyvault.framework.Action;
import org.tsicoop.privacyvault.framework.BSACertificateGenerator;
import org.tsicoop.privacyvault.framework.BuildInfo;
import org.tsicoop.privacyvault.framework.CustodyService;
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
                case "get_principal_custody": {
                    int limit = input.get("limit") instanceof Number ? ((Number) input.get("limit")).intValue()
                            : CustodyService.DEFAULT_EVENT_LIMIT;
                    OutputProcessor.send(res, HttpServletResponse.SC_OK,
                            CustodyService.build((String) input.get("principal_id"), (String) input.get("reference_key"),
                                    Math.max(1, Math.min(limit, 1000))));
                    return;
                }
                case "generate_principal_certificate": {
                    JSONObject data = CustodyService.certificate((String) input.get("principal_id"),
                            (String) input.get("reference_key"));
                    JSONObject subj = (JSONObject) data.get("subject");
                    String name = subj.get("principal_id") != null ? String.valueOf(subj.get("principal_id"))
                            : String.valueOf(input.get("reference_key"));
                    res.setContentType("application/pdf");
                    res.setHeader("Content-Disposition", "attachment; filename=\"BSA_Custody_"
                            + name.replaceAll("[^A-Za-z0-9._-]", "_") + ".pdf\"");
                    certGenerator.streamCustodyCertificate(data, res.getOutputStream());
                    return;
                }
                case "generate_entity_bsa_certificate":
                    handleEntityCertGen((String) input.get("referenceKey"), res);
                    return; // the PDF or the error has been written; nothing more to send
                case "generate_utility_bsa_certificate":
                    OutputProcessor.sendError(res, 400, "Certificates are issued for stored records only. "
                            + "Utility events are in the audit log but are not certifiable.");
                    return;
                default:
                    OutputProcessor.sendError(res, 404, "Function not found.");
            }
        } catch (CustodyService.CustodyException e) {
            OutputProcessor.sendError(res, e.status, e.getMessage());
        } catch (Exception e) {
            if (e instanceof IllegalArgumentException) {
                OutputProcessor.sendError(res, 400, "Invalid reference key.");
            } else {
                OutputProcessor.sendError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Forensic query failed: " + e.getMessage());
            }
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
            // Certify the successful STORE event when there is one, else the earliest event.
            String sql = "SELECT v.hashed_value_sha256, e.machine_id, e.client_ip, e.log_datetime, " +
                        "e.chain_seq, e.row_hash " +
                        "FROM vault_entities v " +
                        "JOIN event_log e ON v.entity_ref = e.entity_ref " +
                        "WHERE v.entity_ref = ? " + 
                        "ORDER BY (e.operation_type LIKE 'STORE:%' AND e.outcome = 'SUCCESS') DESC, " +
                        "e.log_datetime ASC LIMIT 1";
            
            ps = conn.prepareStatement(sql);
            ps.setObject(1, java.util.UUID.fromString(ref)); 
            rs = ps.executeQuery();
            
            if (rs.next()) {
                // An erased record keeps no hash of its value, so there is nothing to certify.
                // The erasure certificate (get_erasure_certificate) covers it instead.
                if (rs.getString("hashed_value_sha256") == null) {
                    OutputProcessor.sendError(res, 410, "Record " + ref
                            + " has been erased, so there is no value to certify. Use the erasure certificate on the Erasure page.");
                    return;
                }
                // MATCH THESE KEYS TO YOUR PDF TEMPLATE
                forensicData.put("sha256_hash", rs.getString("hashed_value_sha256")); // HASH (SHA256)
                
                // Map 'machine_id' to the 'Make & Model' and 'MAC/Cloud ID' fields
                forensicData.put("machine_model", rs.getString("machine_id")); // Fills Make & Model
                forensicData.put("mac_address", rs.getString("machine_id"));     // Fills MAC/Cloud ID
                
                // Map 'log_datetime' to the 'Timestamp' field
                forensicData.put("anchor_time", rs.getTimestamp("log_datetime").toString()); 
                
                // Map 'client_ip' or status to 'System Status' and 'Software Source'
                forensicData.put("health_status", "ACTIVE_SECURE_VAULT");
                forensicData.put("software_version", "TSI_PRIVACY_VAULT_V" + BuildInfo.version());

                // Audit chain: cite the event row and the current head, after checking that
                // the chain from that event to the head is intact. A certificate over a log
                // known to be altered would be worse than none, so refuse.
                long eventSeq = rs.getLong("chain_seq");
                boolean chained = !rs.wasNull();
                String eventHash = rs.getString("row_hash");
                if (!chained) {
                    OutputProcessor.sendError(res, 409, "The audit event for " + ref
                            + " is not in the hash chain. Apply db/04_audit_chain.sql and retry.");
                    return;
                }
                PreparedStatement vps = null;
                ResultSet vrs = null;
                try {
                    vps = conn.prepareStatement("SELECT valid, first_bad_seq, reason, head_seq, head_hash "
                            + "FROM verify_event_log_chain(?)");
                    vps.setLong(1, eventSeq);
                    vrs = vps.executeQuery();
                    if (!vrs.next()) {
                        OutputProcessor.sendError(res, 409, "Audit chain verification returned no result, certificate not issued.");
                        return;
                    }
                    if (!vrs.getBoolean("valid")) {
                        OutputProcessor.sendError(res, 409, "Audit chain verification failed at sequence "
                                + vrs.getLong("first_bad_seq") + " (" + vrs.getString("reason")
                                + "), certificate not issued.");
                        return;
                    }
                    forensicData.put("chain_event_seq", eventSeq);
                    forensicData.put("chain_event_hash", eventHash);
                    forensicData.put("chain_head_seq", vrs.getLong("head_seq"));
                    forensicData.put("chain_head_hash", vrs.getString("head_hash"));
                    forensicData.put("chain_verified_at", java.time.ZonedDateTime.now(java.time.ZoneOffset.UTC).toString());
                } finally {
                    if (vrs != null) try { vrs.close(); } catch (Exception ignored) { }
                    if (vps != null) try { vps.close(); } catch (Exception ignored) { }
                }
            } else {
                OutputProcessor.sendError(res, 404, "No stored record with an audit event was found for " + ref
                        + ". A certificate can only be issued for a record that was stored.");
                return;
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
            StringBuilder sqlBuilder = new StringBuilder(
                "SELECT log_id, who, operation_type, entity_ref, utility_ref, client_ip, machine_id, log_datetime " +
                "FROM event_log WHERE (entity_ref IS NOT NULL OR utility_ref IS NOT NULL)"
            );

            // Dynamic Search for UUIDs or Identities
            if (searchTerm != null && !searchTerm.trim().isEmpty()) {
                // FIX: Added explicit column names and correct parameter placeholders
                sqlBuilder.append(" AND (entity_ref::text LIKE ? OR utility_ref::text LIKE ? OR who LIKE ?)");
            }

            sqlBuilder.append(" ORDER BY log_datetime DESC LIMIT ? OFFSET ?");

            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());

            int idx = 1;
            if (searchTerm != null && !searchTerm.trim().isEmpty()) {
                String likePattern = "%" + searchTerm.trim() + "%";
                pstmt.setString(idx++, likePattern); // For entity_ref::text
                pstmt.setString(idx++, likePattern); // For utility_ref::text
                pstmt.setString(idx++, likePattern); // For who
            }

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