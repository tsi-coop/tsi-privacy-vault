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
        this.kms = KmsProviderFactory.getProvider();
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
                case "search_data":
                    handleSearch(input, apiKey, res);
                    break;              
                default:
                    OutputProcessor.sendError(res, 404, "Function not found.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.sendError(res, 500, "Vault processing error: " + e.getMessage());
        }
    }

    private void handleSearch(JSONObject input, String apiKey, HttpServletResponse res) throws Exception {
        String searchTerm = (String) input.get("searchTerm");
        if (searchTerm == null || searchTerm.trim().isEmpty()) {
            OutputProcessor.sendError(res, 400, "Missing search term.");
            return;
        }

        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        try {
            // 1. Generate the deterministic hash for the query
            String indexSecret = System.getenv("TSI_PRIVACY_VAULT_INDEX_SECRET");
            String queryHash = computeSecureHash(searchTerm.toUpperCase().trim(), indexSecret);

            conn = pool.getConnection();
            // 2. Query the inverted index joined with the master for authorization
            String sql = "SELECT s.entity_ref, m.flavor, m.entity_code " +
                         "FROM vault_search_index s " +
                         "JOIN vault_entities e ON s.entity_ref = e.entity_ref " +
                         "JOIN vault_entity_master m ON e.id_type_code = m.entity_code " +
                         "WHERE s.index_hash = ? AND m.active = true";
            
            ps = conn.prepareStatement(sql);
            ps.setString(1, queryHash);
            rs = ps.executeQuery();

            JSONArray results = new JSONArray();
            while (rs.next()) {
                String entityCode = rs.getString("entity_code");
                // 3. Filter results based on API Key authorization
                if (isAuthorized(apiKey, entityCode, "READ")) {
                    JSONObject match = new JSONObject();
                    match.put("reference_key", rs.getString("entity_ref"));
                    match.put("flavor", rs.getString("flavor"));
                    results.add(match);
                }
            }

            JSONObject out = new JSONObject();
            out.put("success", true);
            out.put("results", results);
            OutputProcessor.send(res, 200, out);
        } finally {
            pool.cleanup(rs, ps, conn);
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
        String sql = "SELECT u.utility_ref,u.payload, u.encrypted_key, u.flavor, u.key_version, u.payload_cipher " +
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
                int keyVersion = rs.getInt("key_version");
                String payloadCipher = rs.getString("payload_cipher");

                String resolvedValue = decryptUtilityPayload(encryptedKey, encryptedPayload, keyVersion, payloadCipher);
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
    private String decryptUtilityPayload(String encryptedKey, String encryptedData, int keyVersion, String payloadCipher) throws Exception {
        String plaintextKeyB64 = this.kms.decryptDataKey(encryptedKey, keyVersion);
        byte[] plaintextKey = Base64.getDecoder().decode(plaintextKeyB64);

        // 2. Decrypt the Payload
        byte[] encryptedBlob = Base64.getDecoder().decode(encryptedData);
        byte[] cleartextBytes = this.kms.aesDecrypt(encryptedBlob, plaintextKey, payloadCipher);
        String cleartext = new String(cleartextBytes, "UTF-8");
        return cleartext;
    }

    private void handleStore(JSONObject input, String apiKey, String ip, String ua, HttpServletResponse res) throws Exception {
        String requestedType = (String) input.get("entityType");
        String entityCode = (String) input.get("entityName");
        String plainValue = (String) input.get("content");
        String originalFileName = (String) input.get("fileName");

        if (entityCode == null || plainValue == null) {
            OutputProcessor.sendError(res, 400, "entityName and content are required.");
            return;
        }

        if (!isAuthorized(apiKey, entityCode, "WRITE")) {
            OutputProcessor.sendError(res, 403, "Write access denied.");
            return;
        }

        // --- ENTITY RULES ---
        // The entity definition is the source of truth. The client's entityType is only checked against it.
        EntityDefinition def = loadEntityDefinition(entityCode);
        if (def == null || !def.active) {
            OutputProcessor.sendError(res, 404, "Unknown or inactive entity.");
            return;
        }
        if (requestedType != null && !requestedType.trim().equalsIgnoreCase(def.flavor)) {
            rejectStore(apiKey, def.flavor, entityCode, ip, ua);
            OutputProcessor.sendError(res, 400, "entityType does not match the flavor of this entity (" + def.flavor + ").");
            return;
        }
        final String entityType = def.flavor;
        boolean isFile = "FILE".equals(entityType);

        // Size: reject oversized transmissions before decoding, then check the decoded size.
        long maxKb = EntityRules.effectiveMaxKb(def.maxSizeKb);
        long maxBytes = maxKb * 1024L;
        long maxEncodedChars = (maxBytes / 3 + 1) * 4 + 8; // Base64 of maxBytes, plus padding
        if (plainValue.length() > maxEncodedChars && plainValue.getBytes("UTF-8").length > maxBytes) {
            rejectStore(apiKey, entityType, entityCode, ip, ua);
            OutputProcessor.sendError(res, 413, "Payload Too Large: limit for this entity is " + maxKb + " KB.");
            return;
        }

        String indexText = null;      // decoded value used for DATA/ID validation and indexing
        String safeFileName = null;   // sanitized file name for FILE

        if (isFile) {
            safeFileName = EntityRules.sanitizeFileName(originalFileName);
            if (safeFileName == null) {
                rejectStore(apiKey, entityType, entityCode, ip, ua);
                OutputProcessor.sendError(res, 400, "fileName is required for FILE entities.");
                return;
            }
            byte[] fileBytes;
            try {
                fileBytes = Base64.getDecoder().decode(plainValue);
            } catch (IllegalArgumentException e) {
                rejectStore(apiKey, entityType, entityCode, ip, ua);
                OutputProcessor.sendError(res, 400, "content must be Base64 encoded for FILE entities.");
                return;
            }
            if (fileBytes.length > maxBytes) {
                rejectStore(apiKey, entityType, entityCode, ip, ua);
                OutputProcessor.sendError(res, 413, "Payload Too Large: limit for this entity is " + maxKb + " KB.");
                return;
            }
            String fileError = EntityRules.checkFile(fileBytes, safeFileName, def.mimeTypes);
            if (fileError != null) {
                rejectStore(apiKey, entityType, entityCode, ip, ua);
                OutputProcessor.sendError(res, 415, fileError);
                return;
            }
        } else {
            // The documented contract is Base64. Plain text is accepted as well, and a plain value
            // such as 345235503650 is also valid Base64, so with a rule set both readings are tried.
            String decoded = null;
            try {
                decoded = EntityRules.decodeUtf8(Base64.getDecoder().decode(plainValue));
            } catch (IllegalArgumentException ignored) {
                // not Base64
            }
            String rule = def.validationRegex;
            if (rule != null && !rule.isEmpty()) {
                if (decoded != null && EntityRules.checkValue(rule, decoded) == null) {
                    indexText = decoded;
                } else {
                    String valueError = EntityRules.checkValue(rule, plainValue);
                    if (valueError != null) {
                        rejectStore(apiKey, entityType, entityCode, ip, ua);
                        OutputProcessor.sendError(res, 422, valueError);
                        return;
                    }
                    indexText = plainValue;
                }
            } else {
                indexText = (decoded != null) ? decoded : plainValue;
            }
            if (indexText.getBytes("UTF-8").length > maxBytes) {
                rejectStore(apiKey, entityType, entityCode, ip, ua);
                OutputProcessor.sendError(res, 413, "Payload Too Large: limit for this entity is " + maxKb + " KB.");
                return;
            }
        }
        // --- END ENTITY RULES ---

        // Generate Data Key and Encrypt
        Map<String, String> dataKeyPack = kms.generateDataKey();
        byte[] rawPlaintextKey = Base64.getDecoder().decode(dataKeyPack.get("plaintextDataKey"));
        String encryptedDataKey = dataKeyPack.get("encryptedDataKey");
        int keyVersion = Integer.parseInt(dataKeyPack.getOrDefault("keyVersion", "1"));
        String payloadCipher = dataKeyPack.getOrDefault("payloadCipher", CipherUtil.AES_CBC_PKCS5);
        byte[] ciphertext = kms.aesEncrypt(plainValue.getBytes("UTF-8"), rawPlaintextKey);
        String ciphertextB64 = Base64.getEncoder().encodeToString(ciphertext);

        UUID referenceKey = UUID.randomUUID();
        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();

        try {
            conn = pool.getConnection();
            String sql = "INSERT INTO vault_entities (entity_type, id_type_code, entity_ref, encrypted_content, encrypted_data_key, hashed_value_sha256, file_name, key_version, payload_cipher) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
            ps = conn.prepareStatement(sql);
            ps.setString(1, entityType);
            ps.setString(2, entityCode);
            ps.setObject(3, referenceKey);
            ps.setString(4, ciphertextB64);
            ps.setString(5, encryptedDataKey);
            ps.setString(6, computeHash(plainValue));
            ps.setString(7, safeFileName); // Sanitized name, null for non-file entities
            ps.setInt(8, keyVersion);
            ps.setString(9, payloadCipher);
            ps.executeUpdate();

            // --- INVERTED INDEXING ---
            if (isFile) {
                // Index the full filename
                updateSearchIndex(conn, referenceKey, safeFileName, "FILE_NAME");

                // Index the extension for type-based filtering
                if (safeFileName.contains(".")) {
                    String extension = safeFileName.substring(safeFileName.lastIndexOf(".") + 1);
                    updateSearchIndex(conn, referenceKey, extension, "FILE_EXT");

                    String baseName = safeFileName.substring(0, safeFileName.lastIndexOf("."));
                    updateSearchIndex(conn, referenceKey, baseName, "FILE_BASE");
                }
            } else {
                // Generate indices for the full value, and shards for partial search
                updateSearchIndex(conn, referenceKey, indexText, "FULL");

                // Multi-part search: Index individual words (e.g., First/Last names)
                String[] parts = indexText.split("\\s+");
                if (parts.length > 1) {
                    for (String part : parts) {
                        updateSearchIndex(conn, referenceKey, part, "PART");
                    }
                }

                // Partial search: Index first 3 characters (e.g., Mobile Prefix)
                if (indexText.length() >= 3) {
                    updateSearchIndex(conn, referenceKey, indexText.substring(0, 3), "PREFIX");
                }
            }
            // --- END INDEXING ---

            logVaultEvent(conn, apiKey, "STORE", entityType+":"+entityCode+":"+referenceKey, ip, ua, "SUCCESS", referenceKey, null);

            JSONObject out = new JSONObject();
            out.put("success", true);
            out.put("reference_key", referenceKey.toString());
            OutputProcessor.send(res, 201, out);
        } catch (Exception e) {
            e.printStackTrace();
            if (conn != null) {
                logVaultEvent(conn, apiKey, "STORE", entityType+":"+entityCode+":"+referenceKey, ip, ua, "ERROR", referenceKey, null);
            }
            OutputProcessor.sendError(res, 500, "Store failed.");
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    /** Entity rules loaded from vault_entity_master. */
    private static final class EntityDefinition {
        String flavor;
        String validationRegex;
        String mimeTypes;
        Integer maxSizeKb;
        boolean active;
    }

    private EntityDefinition loadEntityDefinition(String entityCode) throws SQLException {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT flavor, validation_regex, mime_types, max_size_kb, active FROM vault_entity_master WHERE entity_code = ?");
            ps.setString(1, entityCode);
            rs = ps.executeQuery();
            if (!rs.next()) return null;
            EntityDefinition d = new EntityDefinition();
            d.flavor = rs.getString("flavor");
            d.validationRegex = rs.getString("validation_regex");
            d.mimeTypes = rs.getString("mime_types");
            int kb = rs.getInt("max_size_kb");
            d.maxSizeKb = rs.wasNull() ? null : kb;
            d.active = rs.getBoolean("active");
            return d;
        } finally {
            pool.cleanup(rs, ps, conn);
        }
    }

    /** Records a rejected store in the forensic log. Never throws. */
    private void rejectStore(String apiKey, String entityType, String entityCode, String ip, String ua) {
        Connection conn = null;
        PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            logVaultEvent(conn, apiKey, "STORE", entityType + ":" + entityCode, ip, ua, "DENIED", null, null);
        } catch (Exception ignored) {
            // the rejection response must still be sent
        } finally {
            try {
                if (pool != null) pool.cleanup(null, null, conn);
            } catch (Exception ignored) {
                // nothing more to do
            }
        }
    }

    private void updateSearchIndex(Connection conn, UUID entityRef, String value, String type) throws Exception {
        PreparedStatement ps = null;
        try {
            String indexSecret = System.getenv("TSI_PRIVACY_VAULT_INDEX_SECRET");
            
            // Generate deterministic SHA-256 hash
            String deterministicHash = computeSecureHash(value.toUpperCase().trim(), indexSecret);

            String sql = "INSERT INTO vault_search_index (index_hash, entity_ref, attribute_type) VALUES (?, ?, ?)";
            ps = conn.prepareStatement(sql);
            ps.setString(1, deterministicHash);
            ps.setObject(2, entityRef);
            ps.setString(3, type);
            ps.executeUpdate();
        } catch (Exception e) {
            System.err.println("Indexing failed for " + type + ": " + e.getMessage());
        } finally {
            if (ps != null) ps.close();
        }
    }

    private String computeSecureHash(String input, String salt) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest((salt + input).getBytes("UTF-8"));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
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
            ps = conn.prepareStatement("SELECT entity_type, id_type_code, encrypted_content, encrypted_data_key, file_name, key_version, payload_cipher FROM vault_entities WHERE entity_ref = ?");
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
                int keyVersion = rs.getInt("key_version");
                String payloadCipher = rs.getString("payload_cipher");
                String plaintextDataKeyB64 = kms.decryptDataKey(encryptedDataKey, keyVersion);
                byte[] rawPlaintextKey = Base64.getDecoder().decode(plaintextDataKeyB64);
                byte[] ciphertext = Base64.getDecoder().decode(ciphertextB64);
                byte[] decryptedBytes = kms.aesDecrypt(ciphertext, rawPlaintextKey, payloadCipher);
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
        
        try {
            conn = pool.getConnection();
            
            // FIX: Use a 100% static SQL string to eliminate concatenation and SAST warnings.
            String sql = "SELECT can_read, can_write FROM permissions WHERE api_key = ? AND resource_id = ? AND resource_type = 'ENTITY'";
            ps = conn.prepareStatement(sql);
            ps.setString(1, apiKey);
            ps.setString(2, entityCode);
            rs = ps.executeQuery();
            
            if (rs.next()) {
                // Evaluate the requested action against the fetched boolean values in Java
                if ("WRITE".equalsIgnoreCase(action)) {
                    return rs.getBoolean("can_write");
                } else {
                    return rs.getBoolean("can_read");
                }
            }
            return false;
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