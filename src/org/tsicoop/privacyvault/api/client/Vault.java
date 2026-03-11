package org.tsicoop.privacyvault.api.client;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.sql.*;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.security.MessageDigest;
import org.json.simple.JSONObject;
import org.json.simple.JSONArray;
import org.tsicoop.privacyvault.framework.*;

public class Vault implements Action {

    private final KmsProvider kms; 
    private final BSACertificateGenerator certGenerator = new BSACertificateGenerator();

    public Vault() {
        String providerType = System.getProperty("vault.provider", "LOCAL");
        this.kms = "AWS".equalsIgnoreCase(providerType) ? new AwsKmsProvider() : new LocalKmsProvider();
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            JSONObject input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");
            String apiKey = req.getHeader("X-API-Key");
            String clientIp = req.getRemoteAddr();
            String userAgent = req.getHeader("User-Agent");

            if (func == null || apiKey == null) throw new Exception("Missing function code or API Key.");
          
            switch (func.toLowerCase()) {
                case "get_authorized_entities":
                    handleGetAuthorizedEntities(apiKey, res);
                    break;
                case "store_data":
                    handleStore(input, apiKey, clientIp, userAgent, res);
                    break;
                case "fetch_id_by_reference":
                case "fetch_file_by_reference":
                    handleFetch(input, apiKey, clientIp, userAgent, res);
                    break;
                case "generate_bsa_certificate":
                    handleCertGen((String) input.get("reference_key"), res);
                    break;
                default:
                    OutputProcessor.sendError(res, 404, "Function not found.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.sendError(res, 500, "Vault processing error: " + e.getMessage());
        }
    }

    private void handleGetAuthorizedEntities(String apiKey, HttpServletResponse res) throws Exception {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        
        String sql = "SELECT p.resource_id as entity_code, p.can_read, p.can_write, m.flavor " +
                     "FROM permissions p " +
                     "JOIN vault_entity_master m ON p.resource_id = m.entity_code " +
                     "WHERE p.api_key = ? AND p.resource_type = 'ENTITY' AND m.active = true";
                     
        JSONArray entities = new JSONArray();
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement(sql);
            ps.setString(1, apiKey);
            rs = ps.executeQuery();
            while (rs.next()) {
                JSONObject ent = new JSONObject();
                ent.put("entity_code", rs.getString("entity_code"));
                ent.put("flavor", rs.getString("flavor"));
                ent.put("can_read", rs.getBoolean("can_read"));
                ent.put("can_write", rs.getBoolean("can_write"));
                entities.add(ent);
            }
            JSONObject output = new JSONObject();
            output.put("success", true);
            output.put("entities", entities);
            OutputProcessor.send(res, 200, output);
        } finally {
            pool.cleanup(rs, ps, conn);
        }
    }

    private void handleStore(JSONObject input, String apiKey, String ip, String ua, HttpServletResponse res) throws Exception {
        String entityType = (String) input.get("entityType");
        String entityCode = (String) input.get("entityName");
        String plainValue = (String) input.get("content");

        if (!isAuthorized(apiKey, entityCode, "WRITE")) {
            OutputProcessor.sendError(res, 403, "Write access denied.");
            return;
        }

        // 1. Generate unique Data Key for this record via KMS
        Map<String, String> dataKeyPack = kms.generateDataKey();
        byte[] rawPlaintextKey = Base64.getDecoder().decode(dataKeyPack.get("plaintextDataKey"));
        String encryptedDataKey = dataKeyPack.get("encryptedDataKey");

        // 2. Encrypt value with the plaintext Data Key
        byte[] ciphertext = kms.aesEncrypt(plainValue.getBytes("UTF-8"), rawPlaintextKey);
        String ciphertextB64 = Base64.getEncoder().encodeToString(ciphertext);

        UUID referenceKey = UUID.randomUUID();
        
        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        
        try {
            conn = pool.getConnection();
            // Store the ciphertext AND the encrypted data key (the envelope)
            String sql = "INSERT INTO vault_entities (entity_type, id_type_code, reference_key, encrypted_content, encrypted_data_key, hashed_value_sha256) VALUES (?, ?, ?, ?, ?, ?)";
            ps = conn.prepareStatement(sql);
            ps.setString(1, entityType);
            ps.setString(2, entityCode);
            ps.setObject(3, referenceKey);
            ps.setString(4, ciphertextB64);
            ps.setString(5, encryptedDataKey); // Using kms_id column to store the encrypted data key
            ps.setString(6, computeHash(plainValue));
            ps.executeUpdate();
            
            //logAudit(conn, apiKey, "STORE", entityCode, referenceKey, ip, ua);
            
            JSONObject out = new JSONObject();
            out.put("success", true);
            out.put("reference_key", referenceKey.toString());
            OutputProcessor.send(res, 201, out);
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    private void handleFetch(JSONObject input, String apiKey, String ip, String ua, HttpServletResponse res) throws Exception {
        String ref = (String) input.get("reference_key");
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT entity_code, encrypted_value, kms_id FROM vault_entities WHERE reference_key = ?");
            ps.setString(1, ref);
            rs = ps.executeQuery();
            
            if (rs.next()) {
                String entityCode = rs.getString("entity_code");
                if (!isAuthorized(apiKey, entityCode, "READ")) {
                    OutputProcessor.sendError(res, 403, "Read access denied.");
                    return;
                }
                
                String ciphertextB64 = rs.getString("encrypted_value");
                String encryptedDataKey = rs.getString("kms_id");

                // 1. Decrypt the Data Key using the Master Key (KMS internal logic)
                String plaintextDataKeyB64 = kms.decryptDataKey(encryptedDataKey);
                byte[] rawPlaintextKey = Base64.getDecoder().decode(plaintextDataKeyB64);

                // 2. Decrypt value with the retrieved plaintext Data Key
                byte[] ciphertext = Base64.getDecoder().decode(ciphertextB64);
                byte[] decryptedBytes = kms.aesDecrypt(ciphertext, rawPlaintextKey);
                String decrypted = new String(decryptedBytes, "UTF-8");

                logAudit(conn, apiKey, "FETCH", entityCode, ref, ip, ua);
                
                JSONObject out = new JSONObject();
                out.put("success", true);
                out.put("value", decrypted);
                OutputProcessor.send(res, 200, out);
            } else {
                OutputProcessor.sendError(res, 404, "Reference not found.");
            }
        } finally {
            pool.cleanup(rs, ps, conn);
        }
    }

    private void handleCertGen(String ref, HttpServletResponse res) throws Exception {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        JSONObject forensicData = new JSONObject();
        try {
            conn = pool.getConnection();
            String sql = "SELECT v.hashed_value_sha256, f.* FROM vault_entities v " +
                         "JOIN bsa_forensic_logs f ON v.reference_key = f.reference_key " +
                         "WHERE v.reference_key = ?";
            ps = conn.prepareStatement(sql);
            ps.setString(1, ref);
            rs = ps.executeQuery();
            if (rs.next()) {
                forensicData.put("sha256_hash", rs.getString("hashed_value_sha256"));
                forensicData.put("machine_model", rs.getString("device_make_model"));
                forensicData.put("health_status", rs.getString("system_status"));
            }
        } finally {
            pool.cleanup(rs, ps, conn);
        }
        
        if (forensicData.isEmpty()) throw new Exception("Forensic metadata missing.");
        res.setContentType("application/pdf");
        certGenerator.streamSection63Certificate(forensicData, res.getOutputStream());
    }

    private void logAudit(Connection conn, String apiKey, String action, String entity, String ref, String ip, String ua) throws SQLException {
        String sql = "INSERT INTO vault_audit_logs (api_key, action_type, entity_code, reference_key, client_ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, apiKey);
            ps.setString(2, action);
            ps.setString(3, entity);
            ps.setString(4, ref);
            ps.setString(5, ip);
            ps.setString(6, ua);
            ps.executeUpdate();
        }
    }

    private String computeHash(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes("UTF-8"));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public boolean isAuthorized(String apiKey, String entityCode, String action) throws SQLException {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String col = action.equalsIgnoreCase("WRITE") ? "can_write" : "can_read";
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT " + col + " FROM permissions WHERE api_key = ? AND resource_id = ? AND resource_type = 'ENTITY'");
            ps.setString(1, apiKey);
            ps.setString(2, entityCode);
            rs = ps.executeQuery();
            return rs.next() && rs.getBoolean(col);
        } finally {
            pool.cleanup(rs, ps, conn);
        }
    }

    @Override public boolean validate(String m, HttpServletRequest q, HttpServletResponse s) { return true; }
    @Override public void get(HttpServletRequest q, HttpServletResponse s) {}
    @Override public void put(HttpServletRequest q, HttpServletResponse s) {}
    @Override public void delete(HttpServletRequest q, HttpServletResponse s) {}
}