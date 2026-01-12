package org.tsicoop.privacyvault.api.client;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.tsicoop.aadhaarvault.framework.*;
import org.tsicoop.privacyvault.framework.*;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;


public class Vault implements REST {

    private static final String FUNCTION = "_func";

    private static final String STORE_ID = "store_id";
    private static final String FETCH_ID_BY_REFERENCE = "fetch_id_by_reference";

    private static final String FETCH_REFERENCE_BY_ID_VALUE = "fetch_reference_by_id_value";

    // IMPORTANT: In a real application, KmsService should be injected via DI framework.
    // For now, we'll instantiate it directly.
    private final KmsService kmsService; // Manages KMS operations AND client-side AES crypto
    private final LookupHasher lookupHasher = new LookupHasher(); // For hashing IDs for reverse lookup

    // Hardcoded for example. In production, load from config.

    public Vault() {
        this.kmsService = new KmsService(   SystemConfig.getAppConfig().getProperty("aws.region"),
                                            SystemConfig.getAppConfig().getProperty("aws.kms.identifier"));
    }

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Resource not found for GET request.", req.getRequestURI());
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = null;
        JSONArray outputArray = null;
        String func = null;
        String referenceKey = null;
        String apiKey = null;
        try{
            input = InputProcessor.getInput(req);
            func = (String) input.get(FUNCTION);
            apiKey = req.getHeader("X-API-Key");

            if(func != null){
                if(func.equalsIgnoreCase(STORE_ID)){
                    output = storeId(apiKey,input);
                } else if (func.equalsIgnoreCase(FETCH_ID_BY_REFERENCE)) {
                    referenceKey = (String) input.get("reference-key");
                    UUID referenceKeyID = UUID.fromString(referenceKey);
                    output = fetchIdByReference(apiKey, referenceKeyID);
                } else if (func.equalsIgnoreCase(FETCH_REFERENCE_BY_ID_VALUE)) {
                    output = fetchReferenceByIdValue(apiKey, input);
                }else {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Resource not found for POST request.", req.getRequestURI());
                }
            }

            if(outputArray != null){
                OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
            }else {
                OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
            }
        }catch(Exception e){
            OutputProcessor.sendError(res,HttpServletResponse.SC_INTERNAL_SERVER_ERROR,"Unknown server error");
            e.printStackTrace();
        }

    }

    private JSONObject storeId(String apiKey, JSONObject input) throws Exception {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = null;

        try {
            pool = new PoolDB();
            String idType = (String) input.get("idType");
            String idNumber = (String) input.get("idNumber");

            if (idType == null || idType.trim().isEmpty() || idNumber == null || idNumber.trim().isEmpty()) {
                throw new Exception("Missing required fields (idType, idNumber).");
            }

            // 1. Validate ID Type
            JSONObject idTypeDetails = getIdTypeDetails(idType);
            if (idTypeDetails == null || !(boolean) idTypeDetails.get("active")) {
                throw new Exception("Invalid or inactive ID type: " + idType);
            }

            // 2. Validate ID Number format using regex from id_type_master
            /*String validationRegex = (String) idTypeDetails.get("validationRegex");
            if (validationRegex != null && !validationRegex.trim().isEmpty()) {
                try {
                    if (!Pattern.compile(validationRegex).matcher(idNumber).matches()) {
                        throw new Exception("ID number format invalid for type: " + idType);
                    }
                } catch (PatternSyntaxException e) {
                    throw new Exception("Invalid regex in DB for ID type " + idType);
                }
            }*/

            // Encrypt ID Number
            Map<String, String> dataKeyMap = kmsService.generateDataKey();
            byte[] plaintextDataKey = Base64.getDecoder().decode(dataKeyMap.get("plaintextDataKey"));
            String encryptedDataKeyBase64 = dataKeyMap.get("encryptedDataKey");

            // Encrypt ID Number using the plaintextDataKey
            byte[] encryptedIdData = kmsService.aesEncrypt(idNumber.getBytes("UTF-8"), plaintextDataKey);

            // --- Base64 encode before storing into TEXT column ---
            String encryptedIdDataBase64 = Base64.getEncoder().encodeToString(encryptedIdData); // <<--- NEW LINE
            System.out.println("DEBUG_ENCRYPT: Final blob length (IV+Ciphertext): " + encryptedIdData.length); // Still useful debug
            System.out.println("DEBUG_STORE: Encrypted Data BEFORE DB Write (Base64): " + encryptedIdDataBase64); // <<--- NEW DEBUG

            //  Hash ID Number for reverse lookup
            String hashedIdNumber = lookupHasher.hashData(idNumber); // Using password hasher for simple hashing

            String refKey = getReferenceKeyIfIdPresent(idType, hashedIdNumber);
            if(refKey == null) {
                // 5. Generate Reference Key
                UUID referenceKeyID = UUID.randomUUID();
                refKey = referenceKeyID.toString();

                // 6. Save to id_vault table
                String sql = "INSERT INTO id_vault (reference_key, id_type_code, encrypted_id_number, encrypted_data_key, hashed_id_number, created_at) VALUES (?, ?, ?, ?, ?,?)";
                conn = pool.getConnection();
                pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
                pstmt.setObject(1, referenceKeyID); // Set UUID directly
                pstmt.setString(2, idType);
                pstmt.setString(3, encryptedIdDataBase64);
                pstmt.setString(4, encryptedDataKeyBase64);
                pstmt.setString(5, hashedIdNumber);
                pstmt.setTimestamp(6, Timestamp.valueOf(LocalDateTime.now()));
                pstmt.executeUpdate();

                // Log the 'STORE' event (conceptual call, implement in separate logging class)
                logEvent(apiKey, "STORE", idType, referenceKeyID.toString());
            }

            output.put("referenceKey", refKey);
            output.put("idType", idType);

        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return output;
    }

    private String getReferenceKeyIfIdPresent(String idTypeCode, String hashedIdNumber) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        String referenceKey = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT reference_key FROM id_vault WHERE id_type_code = ? AND hashed_id_number = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, idTypeCode);
            pstmt.setString(2, hashedIdNumber);
            rs = pstmt.executeQuery();
            if(rs.next())
                referenceKey = rs.getString("reference_key");
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return referenceKey;
    }

    private JSONObject fetchIdByReference(String apiKey, UUID referenceKey) throws Exception {
        JSONObject output = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = null;

        try {
            pool = new PoolDB();
            // 1. Retrieve encrypted data and ID type from id_vault
            String sql = "SELECT iv.encrypted_id_number, iv.encrypted_data_key, iv.id_type_code, idtm.id_type_name FROM id_vault iv JOIN id_type_master idtm ON iv.id_type_code = idtm.id_type_code WHERE iv.reference_key = ?";
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, referenceKey); // Set UUID directly
            rs = pstmt.executeQuery();

            if (rs.next()) {
                String encryptedIdNumberBase64 = rs.getString("encrypted_id_number");
                byte[] encryptedIdNumberBytes = Base64.getDecoder().decode(encryptedIdNumberBase64); // This is the actual ID ciphertext

                String idTypeCode = rs.getString("id_type_code");
                String idTypeName = rs.getString("id_type_name"); // For richer response if desired
                String storedEncryptedDataKeyBase64 = rs.getString("encrypted_data_key"); // <<--- RETRIEVE THIS FROM DB
                // Debugging the input to KMS decryption
                System.out.println("DEBUG_KMS_DECRYPT: Encrypted Data Key (Base64): " + storedEncryptedDataKeyBase64);

                // Call KMS to decrypt the DATA KEY
                // Pass the correct context (e.g., referenceKey.toString())
                String plaintextDataKeyBase64 = kmsService.decryptDataKey(storedEncryptedDataKeyBase64); // <<--- Pass THIS to kmsService
                byte[] plaintextDataKey = Base64.getDecoder().decode(plaintextDataKeyBase64);

                // Use the decrypted PLAINTEXT DATA KEY to decrypt the actual ID
                byte[] decryptedBytes = kmsService.aesDecrypt(encryptedIdNumberBytes, plaintextDataKey);
                String decryptedId = new String(decryptedBytes, "UTF-8");

                // Log the 'FETCH' event
                logEvent(apiKey, "FETCH", idTypeCode, referenceKey.toString());

                output = new JSONObject();
                output.put("idType", idTypeCode);
                output.put("idNumber", decryptedId);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return output;
    }

    private JSONObject fetchReferenceByIdValue(String apiKey, JSONObject input) throws Exception {
        JSONObject output = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = null;

        try {
            pool = new PoolDB();
            String idType = (String) input.get("idType");
            String idNumber = (String) input.get("idNumber");

            // 1. Validate ID Type
            JSONObject idTypeDetails = getIdTypeDetails(idType);
            if (idTypeDetails == null || !(boolean) idTypeDetails.get("active")) {
                throw new Exception("Invalid or inactive ID type: " + idType);
            }

            // 2. Hash the provided ID Number
            String hashedIdNumber = lookupHasher.hashData(idNumber); // Using same hasher as during storage

            // 3. Query id_vault for reference_key using id_type_code and hashed_id_number
            String sql = "SELECT reference_key FROM id_vault WHERE id_type_code = ? AND hashed_id_number = ?";
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, idType);
            pstmt.setString(2, hashedIdNumber);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                UUID referenceKey = (UUID) rs.getObject("reference_key");

                // Log the 'FETCH' event
                logEvent(apiKey, "FETCH", idType, referenceKey.toString());

                output = new JSONObject();
                output.put("reference-key", referenceKey.toString());
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return output;
    }


    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE method not supported for vault operations.", req.getRequestURI());
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT method not supported for vault operations.", req.getRequestURI());
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        // All vault operations require X-API-Key and X-API-Secret authentication
        String apiKey = req.getHeader("X-API-Key");
        String apiSecret = req.getHeader("X-API-Secret");

        if (apiKey == null || apiSecret == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Missing API Key or Secret.", req.getRequestURI());
            return false;
        }

        // Validate API Key and Secret against the api_user table
        try {
            if (!isValidApiClient(apiKey, apiSecret)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid or inactive API Key/Secret.", req.getRequestURI());
                return false;
            }
        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "Authentication failed due to database error.", req.getRequestURI());
            return false;
        }

        // Call framework's basic input validation
        return InputProcessor.validate(req, res);
    }

    // --- Helper Methods (Database access and Logging) ---

    /**
     * Validates if the provided API Key and Secret belong to an active client.
     * @param apiKey The API Key.
     * @param apiSecret The API Secret.
     * @return true if valid and active, false otherwise.
     * @throws SQLException if a database access error occurs.
     */
    private boolean isValidApiClient(String apiKey, String apiSecret) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT active FROM api_user WHERE api_key = ? AND api_secret = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, apiKey);
            pstmt.setString(2, apiSecret);
            rs = pstmt.executeQuery();
            return rs.next() && rs.getBoolean("active"); // Client exists and is active
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Retrieves details for a given ID type from id_type_master.
     * @param idTypeCode The code of the ID type.
     * @return A JSONObject containing ID type details, or null if not found.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject getIdTypeDetails(String idTypeCode) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT id_type_name, description, validation_regex, active FROM id_type_master WHERE id_type_code = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, idTypeCode);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject details = new JSONObject();
                details.put("idTypeName", rs.getString("id_type_name"));
                details.put("description", rs.getString("description"));
                details.put("validationRegex", rs.getString("validation_regex"));
                details.put("active", rs.getBoolean("active"));
                return details;
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return null; // ID type not found
    }

    /**
     * Logs an event to the event_log table.
     * @param operationType The type of operation ('STORE', 'FETCH').
     * @param idTypeCode The code of the ID type involved.
     * @param referenceKey The reference key associated with the operation (can be null for some operations).
     */
    private void logEvent(String apiKey, String operationType, String idTypeCode, String referenceKey) {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = null;
        String sql = "INSERT INTO event_log (api_key, operation_type, id_type_code, reference_key, log_datetime) VALUES (?, ?, ?, ?, ?)";

        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, apiKey);
            pstmt.setString(2, operationType);
            pstmt.setString(3, idTypeCode);
            pstmt.setObject(4, referenceKey != null ? UUID.fromString(referenceKey) : null); // Convert string to UUID for DB
            pstmt.setTimestamp(5, Timestamp.valueOf(LocalDateTime.now()));
            pstmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace(); // Log the error, but don't prevent the main operation from completing
            System.err.println("Error logging event: " + e.getMessage());
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }
}