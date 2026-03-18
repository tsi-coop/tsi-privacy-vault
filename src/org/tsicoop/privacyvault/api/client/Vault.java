package org.tsicoop.privacyvault.api.client;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.sql.*;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.security.MessageDigest;
import org.json.simple.JSONObject;
import org.json.simple.JSONArray;
import org.tsicoop.privacyvault.framework.*;

public class Vault implements Action {

    private final KmsProvider kms; 
   
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
                case "get_authorized_utilities":
                    handleGetAuthorizedUtilities(apiKey, res);
                    break;
                case "resolve_utility":
                    handleResolveUtility(req, res, clientIp, userAgent, input);
                    break;
                case "store_data":
                    handleStore(input, apiKey, clientIp, userAgent, res);
                    break;
                case "fetch_data":
                case "fetch_id_by_reference":
                case "fetch_data_by_reference":
                case "fetch_file_by_reference":
                    handleFetch(input, apiKey, clientIp, userAgent, res);
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

    /**
     * Discovery Protocol: Fetches authorized utilities from the vault_utilities table.
     * Uses the vault_utilities table schema and joins with permissions for the API Key.
     */    
    private void handleGetAuthorizedUtilities(String apiKey, HttpServletResponse res) throws Exception {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        
        // SQL updated to include can_read and can_write from the permissions table
        String sql = "SELECT u.utility_ref, u.flavor, u.label, p.can_read, p.can_write " +
                     "FROM permissions p " +
                     "JOIN vault_utilities u ON p.resource_id = u.label " +
                     "WHERE p.api_key = ? AND p.resource_type = 'UTILITY' AND u.active = true";
                     
        JSONArray utilities = new JSONArray();
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement(sql);
            ps.setString(1, apiKey);
            rs = ps.executeQuery();
            
            while (rs.next()) {
                JSONObject util = new JSONObject();
                // Core utility data
                util.put("id", rs.getString("label"));
                util.put("flavor", rs.getString("flavor"));
                util.put("label", rs.getString("label"));
                
                // Permission flags extracted from the JOIN
                // These are used by the HTML client to show READ/WRITE buttons
                util.put("can_read", rs.getBoolean("can_read"));
                util.put("can_write", rs.getBoolean("can_write"));
                
                utilities.add(util);
            }
            
            JSONObject output = new JSONObject();
            output.put("success", true);
            output.put("utilities", utilities);
            
            OutputProcessor.send(res, 200, output);
            
        } catch (Exception e) {
            OutputProcessor.sendError(res, 500, "Discovery Error: " + e.getMessage());
        } finally {
            pool.cleanup(rs, ps, conn);
        }
    }

    /**
     * Resolution Protocol: Validates READ permissions and returns the utility secret.
     * This function corresponds to the "READ" button in the Utility Client.
     */
    private void handleResolveUtility(HttpServletRequest req, HttpServletResponse res, String ip, String ua, JSONObject payload) throws Exception {
        String apiKey = req.getHeader("X-API-Key");
        String utilityId = (String) payload.get("utility_id");

        if (utilityId == null || utilityId.isEmpty()) {
            OutputProcessor.sendError(res, 400, "Missing utility_id");
            return;
        }

        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        UUID utilityRef = null;

        // SQL joins permissions and vault_utilities to verify access and fetch the secret
        String sql = "SELECT u.utility_ref,u.payload, u.encrypted_key, u.flavor " +
                     "FROM permissions p " +
                     "JOIN vault_utilities u ON p.resource_id = u.label " +
                     "WHERE p.api_key = ? AND u.label = ? " +
                     "AND p.resource_type = 'UTILITY' AND p.can_read = true AND u.active = true";

        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement(sql);
            ps.setString(1, apiKey);
            ps.setString(2, utilityId);
            rs = ps.executeQuery();

            if (rs.next()) {
                String encryptedPayload = rs.getString("payload");
                String encryptedKey = rs.getString("encrypted_key");
                
                String resolvedValue = decryptUtilityPayload(encryptedKey, encryptedPayload);
                utilityRef = (UUID) rs.getObject("utility_ref");

                JSONObject output = new JSONObject();
                output.put("success", true);
                output.put("value", resolvedValue);
                output.put("id", utilityId);

                // Log to event_log table
                logVaultEvent(
                    conn,
                    apiKey, 
                    "RESOLVE", 
                    utilityId, 
                    ip, 
                    ua, 
                    "SUCCESS",
                    null,
                    utilityRef
                );
                
                OutputProcessor.send(res, 200, output);
            } else {
                // If no record is found, it means either the utility doesn't exist 
                // OR the api_key does not have can_read = true.
                  // Log to event_log table
                logVaultEvent(
                    conn,
                    apiKey, 
                    "RESOLVE", 
                    utilityId, 
                    ip, 
                    ua, 
                    "FAILURE",
                    null,
                    utilityRef
                );
                OutputProcessor.sendError(res, 403, "Access Denied: Insufficient permissions to read this utility.");
            }
        } catch (Exception e) {
            OutputProcessor.sendError(res, 500, "Resolution Error: " + e.getMessage());
        } finally {
            pool.cleanup(rs, ps, conn);
        }
    }

    /**
     * Placeholder for the Vault's internal decryption logic.
     */
    private String decryptUtilityPayload(String encryptedKey, String encryptedData) throws Exception {
        LocalKmsProvider kms = new LocalKmsProvider();
        String plaintextKeyB64 = kms.decryptDataKey(encryptedKey);
        byte[] plaintextKey = Base64.getDecoder().decode(plaintextKeyB64);

        // 2. Decrypt the Payload
        byte[] encryptedBlob = Base64.getDecoder().decode(encryptedData);
        byte[] cleartextBytes = kms.aesDecrypt(encryptedBlob, plaintextKey);
        String cleartext = new String(cleartextBytes, "UTF-8");
        return cleartext; 
    }

    private void handleStore(JSONObject input, String apiKey, String ip, String ua, HttpServletResponse res) throws Exception {
        String entityType = (String) input.get("entityType");
        String entityCode = (String) input.get("entityName");
        String plainValue = (String) input.get("content");
        String originalFileName = (String) input.get("fileName"); // Extracting the filename

        if (!isAuthorized(apiKey, entityCode, "WRITE")) {
            OutputProcessor.sendError(res, 403, "Write access denied.");
            return;
        }

        // Generate Data Key and Encrypt
        Map<String, String> dataKeyPack = kms.generateDataKey();
        byte[] rawPlaintextKey = Base64.getDecoder().decode(dataKeyPack.get("plaintextDataKey"));
        String encryptedDataKey = dataKeyPack.get("encryptedDataKey");
        byte[] ciphertext = kms.aesEncrypt(plainValue.getBytes("UTF-8"), rawPlaintextKey);
        String ciphertextB64 = Base64.getEncoder().encodeToString(ciphertext);

        UUID referenceKey = UUID.randomUUID();
        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        
        try {
            conn = pool.getConnection();
            // SQL updated to include the file_name column
            String sql = "INSERT INTO vault_entities (entity_type, id_type_code, entity_ref, encrypted_content, encrypted_data_key, hashed_value_sha256, file_name) VALUES (?, ?, ?, ?, ?, ?, ?)";
            ps = conn.prepareStatement(sql);
            ps.setString(1, entityType);
            ps.setString(2, entityCode);
            ps.setObject(3, referenceKey);
            ps.setString(4, ciphertextB64);
            ps.setString(5, encryptedDataKey);
            ps.setString(6, computeHash(plainValue));
            ps.setString(7, originalFileName); // Preserving the original extension
            ps.executeUpdate();
            
            logVaultEvent(conn, apiKey, "STORE", entityType+":"+entityCode+":"+referenceKey, ip, ua, "SUCCESS", referenceKey, null);
            
            JSONObject out = new JSONObject();
            out.put("success", true);
            out.put("reference_key", referenceKey.toString());
            OutputProcessor.send(res, 201, out);
        } catch(Exception e){
            logVaultEvent(conn, apiKey, "STORE", entityType+":"+entityCode+":"+referenceKey, ip, ua, "FAILURE", referenceKey, null);
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    private void handleFetch(JSONObject input, String apiKey, String ip, String ua, HttpServletResponse res) throws Exception {
        String ref = (String) input.get("reference-key");
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = null;
        
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            // SELECT now includes the file_name
            ps = conn.prepareStatement("SELECT entity_type, id_type_code, encrypted_content, encrypted_data_key, file_name FROM vault_entities WHERE entity_ref = ?");
            ps.setObject(1, UUID.fromString(ref));
            rs = ps.executeQuery();
            
            if (rs.next()) {
                String entityType = rs.getString("entity_type");
                String entityCode = rs.getString("id_type_code");
                String fileName = rs.getString("file_name"); // Retrieving preserved name

                if (!isAuthorized(apiKey, entityCode, "READ")) {
                    OutputProcessor.sendError(res, 403, "Read access denied.");
                    return;
                }
                
                // Decryption Logic
                String ciphertextB64 = rs.getString("encrypted_content");
                String encryptedDataKey = rs.getString("encrypted_data_key");
                String plaintextDataKeyB64 = kms.decryptDataKey(encryptedDataKey);
                byte[] rawPlaintextKey = Base64.getDecoder().decode(plaintextDataKeyB64);
                byte[] ciphertext = Base64.getDecoder().decode(ciphertextB64);
                byte[] decryptedBytes = kms.aesDecrypt(ciphertext, rawPlaintextKey);
                String decrypted = new String(decryptedBytes, "UTF-8");

                logVaultEvent(conn, apiKey, "FETCH", entityType+":"+entityCode+":"+ref, ip, ua, "SUCCESS", UUID.fromString(ref), null);
                
                // Restore the original extension via headers
                if (fileName != null && !fileName.isEmpty()) {
                    res.setHeader("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
                }

                JSONObject out = new JSONObject();
                out.put("success", true);
                out.put("value", decrypted);
                out.put("flavor", entityType);
                out.put("fileName", fileName); // Return filename in JSON for UI flexibility
                OutputProcessor.send(res, 200, out);
            } else {
                logVaultEvent(conn, apiKey, "FETCH", ref, ip, ua, "FAILURE", UUID.fromString(ref), null);
                OutputProcessor.sendError(res, 404, "Reference not found.");
            }
        } finally {
            pool.cleanup(rs, ps, conn);
        }
    }

   
    private void logVaultEvent(Connection conn, String actorKey, String op, String target, String ip, String ua, String outcome, UUID referenceKey, UUID utilityRef) {
        PreparedStatement ps = null;
        String machineId = null;
        try {
            // Hardware anchor for BSA 2023 compliance
            machineId = ForensicEngine.getMachineIdentifier(); 
            
            String sql = "INSERT INTO event_log (who, operation_type, client_ip, user_agent, machine_id, outcome, entity_ref, utility_ref, log_datetime) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
            
            ps = conn.prepareStatement(sql);
            
            ps.setString(1, "VAULT:" + actorKey);
            ps.setString(2, op + ":" + target); 
            ps.setString(3, ip);
            ps.setString(4, ua);
            ps.setString(5, machineId);
            ps.setString(6, outcome); // e.g., "SUCCESS" or "DECRYPTED"

            // Pass UUIDs directly
            ps.setObject(7, referenceKey); // If null, JDBC handles it
            ps.setObject(8, utilityRef);   // If null, JDBC handles it
            
            ps.setTimestamp(9, Timestamp.valueOf(LocalDateTime.now()));
            
            ps.executeUpdate();
        } catch (Exception e) {
            System.err.println("CRITICAL: Vault Access Logging Failed: " + e.getMessage());
        } finally {
            try { if (ps != null) ps.close(); } catch (Exception ignored) {}
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

    @Override public boolean validate(String m, HttpServletRequest q, HttpServletResponse s) { 
        if (!"POST".equalsIgnoreCase(m)) {
            OutputProcessor.errorResponse(s, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Use POST for login.", q.getRequestURI());
            return false;
        }
        return InputProcessor.validate(q, s);
    }
    @Override public void get(HttpServletRequest q, HttpServletResponse s) {}
    @Override public void put(HttpServletRequest q, HttpServletResponse s) {}
    @Override public void delete(HttpServletRequest q, HttpServletResponse s) {}
}