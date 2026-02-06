package org.tsicoop.privacyvault.api.client;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.sql.*;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import org.json.simple.JSONObject;
import org.tsicoop.privacyvault.framework.*;

/**
 * Consolidated BSA 2023 Vault Service.
 * Features: Unified Registry, Forensic Metadata, and Standard Audit Logging.
 */
public class Vault implements REST {

    private final KmsProvider kms; 
    private final BSACertificateGenerator certGenerator = new BSACertificateGenerator();

    public Vault() {
        // FIX: Instantiate a concrete class, not the interface
        String providerType = System.getProperty("vault.provider", "LOCAL");
        
        if ("AWS".equalsIgnoreCase(providerType)) {
            this.kms = new AwsKmsProvider(); 
        } else {
            this.kms = new LocalKmsProvider(); 
        }
    }

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Resource not found for GET request.", req.getRequestURI());
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            JSONObject input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");
            String apiKey = req.getHeader("X-API-Key");
            String clientIp = req.getRemoteAddr();

            if (func == null) throw new Exception("Missing function code.");

            switch (func.toLowerCase()) {
                case "store_data":
                    byte[] content = Base64.getDecoder().decode((String) input.get("content"));
                    String entityName = (String) input.get("entityName");
                    String entityType = (String) input.get("entityType");
                    OutputProcessor.send(res, 200, storeInVault(content, entityName, entityType, apiKey, clientIp));
                    break;

                case "fetch_id_by_reference":
                case "fetch_file_by_reference":
                    UUID refKey = UUID.fromString((String) input.get("reference-key"));
                    OutputProcessor.send(res, 200, fetchByReference(apiKey, refKey, clientIp));
                    break;

                case "generate_bsa_certificate":
                    UUID certRef = UUID.fromString((String) input.get("reference-key"));
                    generateCertificateResponse(res, certRef);
                    break;

                default:
                    OutputProcessor.sendError(res, 404, "Function not found.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.sendError(res, 500, "Vault processing error: " + e.getMessage());
        }
    }

    private JSONObject storeInVault(byte[] content, String name, String type, String apiKey, String ip) throws Exception {
        String forensicHash = ForensicEngine.calculateSHA256(content); // Using corrected framework method
        JSONObject bsaMetadata = ForensicEngine.captureBSAMetadata(); // Renamed to ForensicEngine

        Map<String, String> keys = kms.generateDataKey();
        byte[] encrypted = kms.aesEncrypt(content, Base64.getDecoder().decode(keys.get("plaintextDataKey")));

        UUID refKey = UUID.randomUUID();
        saveToRegistry(refKey, type, name, encrypted, keys.get("encryptedDataKey"), forensicHash, bsaMetadata);
        
        logEvent(apiKey, "STORE", type, refKey.toString(), ip);

        JSONObject output = new JSONObject();
        output.put("referenceKey", refKey.toString());
        output.put("forensicStatus", bsaMetadata.get("systemStatus"));
        return output;
    }

    private JSONObject fetchByReference(String apiKey, UUID ref, String ip) throws Exception {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection(); // Instance call to fix static context error
            String sql = "SELECT entity_type, file_name, encrypted_content, encrypted_data_key FROM vault_registry WHERE reference_key = ?";
            ps = conn.prepareStatement(sql);
            ps.setObject(1, ref);
            rs = ps.executeQuery();

            if (rs.next()) {
                String type = rs.getString("entity_type");
                String plainKey = kms.decryptDataKey(rs.getString("encrypted_data_key"));
                byte[] decrypted = kms.aesDecrypt(Base64.getDecoder().decode(rs.getString("encrypted_content")), Base64.getDecoder().decode(plainKey));

                logEvent(apiKey, "FETCH", type, ref.toString(), ip);

                JSONObject out = new JSONObject();
                out.put("entityType", type);
                out.put("content", "ID".equalsIgnoreCase(type) ? new String(decrypted, "UTF-8") : Base64.getEncoder().encodeToString(decrypted));
                return out;
            }
        } finally {
            pool.cleanup(rs, ps, conn);
        }
        return null;
    }

    private void logEvent(String apiKey, String action, String type, String ref, String ip) {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = null;
        String sql = "INSERT INTO vault_audit_trail (actor_id, action_type, entity_type, reference_key, source_ip, action_timestamp) VALUES (?, ?, ?, ?, ?, ?)";

        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, apiKey);
            pstmt.setString(2, action);
            pstmt.setString(3, type);
            pstmt.setObject(4, ref != null ? UUID.fromString(ref) : null);
            pstmt.setString(5, ip);
            pstmt.setTimestamp(6, Timestamp.valueOf(LocalDateTime.now()));
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("CRITICAL: Audit log failed - " + e.getMessage());
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    private void saveToRegistry(UUID ref, String type, String name, byte[] data, String key, String hash, JSONObject bsa) throws SQLException {
        Connection conn = null;
        PreparedStatement psReg = null;
        PreparedStatement psLog = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);
            
            String sqlReg = "INSERT INTO vault_registry (reference_key, entity_type, file_name, encrypted_content, encrypted_data_key, hashed_value_sha256) VALUES (?, ?, ?, ?, ?, ?)";
            psReg = conn.prepareStatement(sqlReg);
            psReg.setObject(1, ref); psReg.setString(2, type); psReg.setString(3, name);
            psReg.setString(4, Base64.getEncoder().encodeToString(data));
            psReg.setString(5, key); psReg.setString(6, hash);
            psReg.executeUpdate();

            String sqlLog = "INSERT INTO bsa_forensic_logs (reference_key, device_make_model, system_status) VALUES (?, ?, ?)";
            psLog = conn.prepareStatement(sqlLog);
            psLog.setObject(1, ref); psLog.setString(2, (String) bsa.get("makeModel"));
            psLog.setString(3, (String) bsa.get("systemStatus"));
            psLog.executeUpdate();

            conn.commit();
        } catch (SQLException e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            if (psLog != null) pool.cleanup(null, psLog, null);
            pool.cleanup(null, psReg, conn);
        }
    }

    private void generateCertificateResponse(HttpServletResponse res, UUID ref) throws Exception {
        JSONObject data = fetchForensicData(ref);
        if (data == null) throw new Exception("Forensic anchor missing.");
        res.setContentType("application/pdf");
        res.setHeader("Content-Disposition", "attachment; filename=\"BSA_Cert_" + ref + ".pdf\"");
        certGenerator.streamSection63Certificate(data, res.getOutputStream());
    }

    private JSONObject fetchForensicData(UUID refKey) throws Exception {
        JSONObject data = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            String sql = "SELECT v.hashed_value_sha256, f.device_make_model, f.device_mac_address, " +
                         "f.system_status, f.captured_at FROM vault_registry v " +
                         "JOIN bsa_forensic_logs f ON v.reference_key = f.reference_key WHERE v.reference_key = ?";
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, refKey);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                data = new JSONObject();
                data.put("sha256_hash", rs.getString("hashed_value_sha256"));
                data.put("machine_model", rs.getString("device_make_model"));
                data.put("health_status", rs.getString("system_status"));
                data.put("anchor_time", rs.getTimestamp("captured_at").toString());
                data.put("software_version", "TSI-Privacy-Vault-v2.0");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return data;
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        String apiKey = req.getHeader("X-API-Key");
        String apiSecret = req.getHeader("X-API-Secret");
        if (apiKey == null || apiSecret == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Missing API Key or Secret.", req.getRequestURI());
            return false;
        }
        try {
            if (!isValidApiClient(apiKey, apiSecret)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid or inactive API Key/Secret.", req.getRequestURI());
                return false;
            }
        } catch (SQLException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "Authentication failed.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }

    private boolean isValidApiClient(String apiKey, String apiSecret) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT active FROM api_user WHERE api_key = ? AND api_secret = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, apiKey);
            pstmt.setString(2, apiSecret);
            rs = pstmt.executeQuery();
            return rs.next() && rs.getBoolean("active");
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE not supported.", req.getRequestURI());
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT not supported.", req.getRequestURI());
    }
}