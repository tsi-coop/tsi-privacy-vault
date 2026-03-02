package org.tsicoop.privacyvault.api.admin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.tsicoop.privacyvault.framework.*;
import java.sql.*;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

/**
 * Secret Management.
 * Implements hardware-anchored envelope encryption using LocalKmsProvider.
 */
public class Secret implements Action {

    private static final String FUNCTION = "_func";

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        String func = null;
        
        // Context for forensic logging
        String who = (String) req.getAttribute("authenticated_user_id"); 
        String clientIp = req.getRemoteAddr();
        String userAgent = req.getHeader("User-Agent");

        try {
            // Read JSON input body (matches Clients.java pattern)
            input = InputProcessor.getInput(req);
            if (input == null) throw new Exception("Invalid JSON payload.");

            func = (String) input.get(FUNCTION);

            if (func == null) {
                OutputProcessor.sendError(res, HttpServletResponse.SC_BAD_REQUEST, "Missing _func parameter.");
                return;
            }

            // Route operations
            if (func.equalsIgnoreCase("enroll")) {
                handleEnroll(input, who, clientIp, userAgent, res);
            } else if (func.equalsIgnoreCase("checkout")) {
                handleCheckout(input, who, clientIp, userAgent, res);
            } else if (func.equalsIgnoreCase("list")) {
                handleList(res);
            } else if (func.equalsIgnoreCase("rotate")) {
                handleRotate(input, who, clientIp, userAgent, res);
            } else {
                OutputProcessor.sendError(res, HttpServletResponse.SC_BAD_REQUEST, "Unknown function: " + func);
            }

        } catch (Exception e) {
            OutputProcessor.sendError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Vault Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void handleEnroll(JSONObject input, String who, String ip, String ua, HttpServletResponse res) throws Exception {
        String label = (String) input.get("label");
        String category = (String) input.get("category");
        String payload = (String) input.get("payload");

        if (label == null || payload == null) throw new Exception("Label and Payload are required.");

        String machineId = ForensicEngine.getMachineIdentifier();
        String utilityId = "UTL-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();

        // 1. Generate Data Key via LocalKmsProvider
        LocalKmsProvider kms = new LocalKmsProvider();
        Map<String, String> keys = kms.generateDataKey();
        byte[] plaintextKey = Base64.getDecoder().decode(keys.get("plaintextDataKey"));
        String encryptedKey = keys.get("encryptedDataKey");

        // 2. Encrypt Payload (Envelope Encryption)
        byte[] encryptedBlob = kms.aesEncrypt(payload.getBytes("UTF-8"), plaintextKey);
        String encryptedPayload = Base64.getEncoder().encodeToString(encryptedBlob);

        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "INSERT INTO vault_utilities (utility_id, flavor, label, payload, encrypted_key, machine_id, active) VALUES (?, ?, ?, ?, ?, ?, TRUE)";
            ps = conn.prepareStatement(sql);
            ps.setString(1, utilityId);
            ps.setString(2, category);
            ps.setString(3, label);
            ps.setString(4, encryptedPayload);
            ps.setString(5, encryptedKey);
            ps.setString(6, machineId);
            ps.executeUpdate();

            logEvent(who, "ENROLL", utilityId, ip, ua, machineId, "SUCCESS", null);
            
            JSONObject out = new JSONObject();
            out.put("utility_id", utilityId);
            OutputProcessor.send(res, HttpServletResponse.SC_OK, out);
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    private void handleCheckout(JSONObject input, String who, String ip, String ua, HttpServletResponse res) throws Exception {
        String utilityId = (String) input.get("utility_id");
        if (utilityId == null) throw new Exception("utility_id is required.");

        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT payload, encrypted_key, machine_id FROM vault_utilities WHERE utility_id = ? AND active = TRUE");
            ps.setString(1, utilityId);
            rs = ps.executeQuery();

            if (rs.next()) {
                String encryptedPayload = rs.getString("payload");
                String encryptedKey = rs.getString("encrypted_key");
                String storedMachineId = rs.getString("machine_id");
                String currentMachineId = ForensicEngine.getMachineIdentifier();

                // Hardware Anchor Validation
                if (!storedMachineId.equals(currentMachineId)) {
                    logEvent(who, "CHECKOUT", utilityId, ip, ua, currentMachineId, "DENIED", "Hardware mismatch");
                    OutputProcessor.sendError(res, HttpServletResponse.SC_FORBIDDEN, "Hardware anchor mismatch.");
                    return;
                }

                // 1. Decrypt the Data Key
                LocalKmsProvider kms = new LocalKmsProvider();
                String plaintextKeyB64 = kms.decryptDataKey(encryptedKey);
                byte[] plaintextKey = Base64.getDecoder().decode(plaintextKeyB64);

                // 2. Decrypt the Payload
                byte[] encryptedBlob = Base64.getDecoder().decode(encryptedPayload);
                byte[] cleartextBytes = kms.aesDecrypt(encryptedBlob, plaintextKey);
                String cleartext = new String(cleartextBytes, "UTF-8");

                logEvent(who, "CHECKOUT", utilityId, ip, ua, currentMachineId, "SUCCESS", null);
                
                res.setContentType("text/plain");
                res.getWriter().write(cleartext);
            } else {
                OutputProcessor.sendError(res, HttpServletResponse.SC_NOT_FOUND, "Utility not found.");
            }
        } finally {
            pool.cleanup(rs, ps, conn);
        }
    }

    private void handleList(HttpServletResponse res) throws Exception {
        JSONArray array = new JSONArray();
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT utility_id, flavor, label FROM vault_utilities WHERE active = TRUE ORDER BY created_at DESC");
            rs = ps.executeQuery();
            while (rs.next()) {
                JSONObject obj = new JSONObject();
                obj.put("id", rs.getString("utility_id"));
                obj.put("category", rs.getString("flavor"));
                obj.put("label", rs.getString("label"));
                array.add(obj);
            }
            OutputProcessor.send(res, HttpServletResponse.SC_OK, array);
        } finally {
            pool.cleanup(rs, ps, conn);
        }
    }

    private void handleRotate(JSONObject input, String who, String ip, String ua, HttpServletResponse res) throws Exception {
        String utilityId = (String) input.get("utility_id");
        String newPayload = (String) input.get("payload");
        String machineId = ForensicEngine.getMachineIdentifier();

        // 1. Generate New Data Key
        LocalKmsProvider kms = new LocalKmsProvider();
        Map<String, String> keys = kms.generateDataKey();
        byte[] plaintextKey = Base64.getDecoder().decode(keys.get("plaintextDataKey"));
        String encryptedKey = keys.get("encryptedDataKey");

        // 2. Re-encrypt with new key
        byte[] encryptedBlob = kms.aesEncrypt(newPayload.getBytes("UTF-8"), plaintextKey);
        String encryptedPayload = Base64.getEncoder().encodeToString(encryptedBlob);

        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("UPDATE vault_utilities SET payload = ?, encrypted_key = ?, machine_id = ? WHERE utility_id = ?");
            ps.setString(1, encryptedPayload);
            ps.setString(2, encryptedKey);
            ps.setString(3, machineId);
            ps.setString(4, utilityId);
            ps.executeUpdate();

            logEvent(who, "ROTATE", utilityId, ip, ua, machineId, "SUCCESS", null);
            OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject());
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    private void logEvent(String who, String op, String utl, String ip, String ua, String mid, String outcome, String reason) {
        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            String sql = "INSERT INTO event_log (who, operation_type, utility_ref, client_ip, user_agent, machine_id, outcome, failure_reason, log_datetime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
            ps = conn.prepareStatement(sql);
            ps.setString(1, who);
            ps.setString(2, op);
            ps.setString(3, utl);
            ps.setString(4, ip);
            ps.setString(5, ua);
            ps.setString(6, mid);
            ps.setString(7, outcome);
            ps.setString(8, reason);
            ps.setTimestamp(9, Timestamp.valueOf(LocalDateTime.now()));
            ps.executeUpdate();
        } catch (Exception e) {
            System.err.println("Audit Failure: " + e.getMessage());
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    @Override public boolean validate(String m, HttpServletRequest req, HttpServletResponse res) { return true; }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
}