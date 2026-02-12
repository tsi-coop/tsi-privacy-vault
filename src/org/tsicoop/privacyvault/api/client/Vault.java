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

public class Vault implements REST {

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
                case "store_data":
                    handleStore(input, apiKey, clientIp, userAgent, res);
                    break;
                case "fetch_id_by_reference":
                case "fetch_file_by_reference":
                    handleFetch(input, apiKey, clientIp, userAgent, res);
                    break;
                case "fetch_reference_by_id_value":
                    handleLookup(input, apiKey, clientIp, userAgent, res);
                    break;
                case "generate_bsa_certificate":
                    handleCertGen(input, apiKey, clientIp, userAgent, res);
                    break;
                default:
                    OutputProcessor.sendError(res, 404, "Function not found.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.sendError(res, 500, "Vault processing error: " + e.getMessage());
        }
    }

    // --- RBAC & Gatekeeping ---

    public boolean isAuthorized(String apiKey, String entityCode, String action) throws SQLException {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String col = action.equalsIgnoreCase("WRITE") ? "can_write" : "can_read";
        String sql = "SELECT " + col + " FROM api_user_permissions WHERE api_key = ? AND entity_code = ?";
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement(sql);
            ps.setString(1, apiKey);
            ps.setString(2, entityCode);
            rs = ps.executeQuery();
            return rs.next() && rs.getBoolean(col);
        } catch (SQLException e) {
            throw e;
        } finally {
            pool.cleanup(rs, ps, conn);
        }
    }

    private String getEntityCodeFromRef(UUID ref) throws SQLException {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT entity_type FROM vault_registry WHERE reference_key = ?");
            ps.setObject(1, ref);
            rs = ps.executeQuery();
            return rs.next() ? rs.getString("entity_type") : "UNKNOWN";
        } catch (SQLException e) {
            throw e;
        } finally {
            pool.cleanup(rs, ps, conn);
        }
    }

    // --- Core Forensic Handlers ---

    private JSONObject storeInVault(byte[] content, String name, String type, String key, String ip, String ua) throws Exception {
        String hash = ForensicEngine.calculateSHA256(content);
        JSONObject bsa = ForensicEngine.captureBSAMetadata();
        Map<String, String> dataKeys = kms.generateDataKey();
        byte[] encrypted = kms.aesEncrypt(content, Base64.getDecoder().decode(dataKeys.get("plaintextDataKey")));
        
        UUID ref = UUID.randomUUID();
        saveToRegistry(ref, type, name, encrypted, dataKeys.get("encryptedDataKey"), hash, bsa);
        logEvent(key, "STORE", type, ref.toString(), ip, ua, "SUCCESS", null);
        
        JSONObject out = new JSONObject();
        out.put("referenceKey", ref.toString());
        return out;
    }

    private JSONObject fetchByReference(String apiKey, UUID ref, String ip, String ua) throws Exception {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        JSONObject out = new JSONObject(); // Initialize empty instead of null
        String type = null;
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT * FROM vault_registry WHERE reference_key = ?");
            ps.setObject(1, ref);
            rs = ps.executeQuery();
            if (rs.next()) {
                type = rs.getString("entity_type");
                String plainKey = kms.decryptDataKey(rs.getString("encrypted_data_key"));
                byte[] decrypted = kms.aesDecrypt(Base64.getDecoder().decode(rs.getString("encrypted_content")), Base64.getDecoder().decode(plainKey));
                out.put("content", "FILE".equalsIgnoreCase(type) ? Base64.getEncoder().encodeToString(decrypted) : new String(decrypted, "UTF-8"));
            }
        } catch (Exception e) {
            throw e;
        } finally {
            pool.cleanup(rs, ps, conn);
        }
        if(out.get("content")!=null){
            logEvent(apiKey, "FETCH", type, ref.toString(), ip, ua, "SUCCESS", null);
        }
        return out; 
    }

    private JSONObject fetchReferenceByHash(String apiKey, JSONObject input, String ip, String ua) throws Exception {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        JSONObject out = new JSONObject(); // Initialize empty instead of null
        String val = (String) input.get("content");
        String type = (String) input.get("entityType");
        String ref = null;
        try {
            String hash = ForensicEngine.calculateSHA256(val.getBytes("UTF-8"));
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT reference_key FROM vault_registry WHERE hashed_value_sha256 = ?");
            ps.setString(1, hash);
            rs = ps.executeQuery();
            if (rs.next()) {
                ref = rs.getObject("reference_key").toString();
                out.put("reference-key", ref);                
            }
        } catch (Exception e) {
            throw e;
        } finally {
            pool.cleanup(rs, ps, conn);
        }
        if(out.get("reference-key")!=null){
            logEvent(apiKey, "LOOKUP", type, ref, ip, ua, "SUCCESS", null);
        }
        return out;
    }

    // --- Logging & Registry Management ---

    private void logEvent(String key, String op, String type, String ref, String ip, String ua, String outcome, String reason) {
        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = null;
        String machineId = ForensicEngine.getMachineIdentifier(); 
        String sql = "INSERT INTO event_log (api_key, operation_type, entity_code, reference_key, client_ip, user_agent, machine_id, outcome, failure_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            ps = conn.prepareStatement(sql);
            ps.setString(1, key); ps.setString(2, op); ps.setString(3, type);
            ps.setObject(4, ref != null ? UUID.fromString(ref) : null);
            ps.setString(5, ip); ps.setString(6, ua); ps.setString(7, machineId);
            ps.setString(8, outcome); ps.setString(9, reason);
            ps.executeUpdate();
        } catch (Exception e) {
            System.err.println("Audit Failure: " + e.getMessage());
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    private void saveToRegistry(UUID ref, String type, String name, byte[] data, String key, String hash, JSONObject bsa) throws SQLException {
        Connection conn = null;
        PreparedStatement pReg = null;
        PreparedStatement pBsa = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);
            pReg = conn.prepareStatement("INSERT INTO vault_registry (reference_key, entity_type, file_name, encrypted_content, encrypted_data_key, hashed_value_sha256) VALUES (?, ?, ?, ?, ?, ?)");
            pReg.setObject(1, ref); pReg.setString(2, type); pReg.setString(3, name);
            pReg.setString(4, Base64.getEncoder().encodeToString(data)); pReg.setString(5, key); pReg.setString(6, hash);
            pReg.executeUpdate();

            pBsa = conn.prepareStatement("INSERT INTO bsa_forensic_logs (reference_key, device_make_model, system_status, device_mac_address, device_serial_number, hash_algorithm) VALUES (?, ?, ?, ?, ?, ?)");
            pBsa.setObject(1, ref); pBsa.setString(2, (String) bsa.get("makeModel"));
            pBsa.setString(3, (String) bsa.get("systemStatus")); pBsa.setString(4, (String) bsa.get("macAddress"));
            pBsa.setString(5, (String) bsa.get("serialNumber")); pBsa.setString(6, "SHA-256");
            pBsa.executeUpdate();
            
            conn.commit();
        } catch (SQLException e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            if (pBsa != null) pool.cleanup(null, pBsa, null);
            pool.cleanup(null, pReg, conn);
        }
    }

    // --- RBAC Handlers & Wrappers ---

    private void handleStore(JSONObject input, String key, String ip, String ua, HttpServletResponse res) throws Exception {
        String type = (String) input.get("entityType");
        if (!isAuthorized(key, type, "WRITE")) {
            logEvent(key, "STORE", type, null, ip, ua, "DENIED", "RBAC Violation: No WRITE access");
            OutputProcessor.sendError(res, 403, "Forbidden: No WRITE access for " + type);
            return;
        }
        byte[] content = Base64.getDecoder().decode((String) input.get("content"));
        String name = (String) input.get("entityName");
        OutputProcessor.send(res, 200, storeInVault(content, name, type, key, ip, ua));
    }

    private void handleFetch(JSONObject input, String key, String ip, String ua, HttpServletResponse res) throws Exception {
        UUID ref = UUID.fromString((String) input.get("reference-key"));
        String type = getEntityCodeFromRef(ref);
        if (!isAuthorized(key, type, "READ")) {
            logEvent(key, "FETCH", type, ref.toString(), ip, ua, "DENIED", "RBAC Violation: No READ access");
            OutputProcessor.sendError(res, 403, "Forbidden: No READ access for " + type);
            return;
        }
        OutputProcessor.send(res, 200, fetchByReference(key, ref, ip, ua));
    }

    private void handleLookup(JSONObject input, String key, String ip, String ua, HttpServletResponse res) throws Exception {
        String type = (String) input.get("entityType");
        if (!isAuthorized(key, type, "READ")) {
            logEvent(key, "LOOKUP", type, null, ip, ua, "DENIED", "RBAC Violation");
            OutputProcessor.sendError(res, 403, "Forbidden: No READ access for " + type);
            return;
        }
        OutputProcessor.send(res, 200, fetchReferenceByHash(key, input, ip, ua));
    }

    private void handleCertGen(JSONObject input, String key, String ip, String ua, HttpServletResponse res) throws Exception {
        UUID ref = UUID.fromString((String) input.get("reference-key"));
        String type = getEntityCodeFromRef(ref);
        if (!isAuthorized(key, type, "READ")) {
            OutputProcessor.sendError(res, 403, "Forbidden: No READ access for " + type);
            return;
        }
        generateCertificateResponse(res, ref);
    }

    private void generateCertificateResponse(HttpServletResponse res, UUID ref) throws Exception {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        JSONObject forensicData = new JSONObject(); // Initialize empty
        try {
            conn = pool.getConnection();
            String sql = "SELECT v.hashed_value_sha256, f.* FROM vault_registry v JOIN bsa_forensic_logs f ON v.reference_key = f.reference_key WHERE v.reference_key = ?";
            ps = conn.prepareStatement(sql);
            ps.setObject(1, ref);
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

    @Override public boolean validate(String m, HttpServletRequest q, HttpServletResponse s) { return true; }
    @Override public void get(HttpServletRequest q, HttpServletResponse s) {}
    @Override public void put(HttpServletRequest q, HttpServletResponse s) {}
    @Override public void delete(HttpServletRequest q, HttpServletResponse s) {}
}