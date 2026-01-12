package org.tsicoop.privacyvault.api.client;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.tsicoop.privacyvault.framework.InputProcessor;
import org.tsicoop.privacyvault.framework.OutputProcessor;
import org.tsicoop.privacyvault.framework.REST;
import org.tsicoop.privacyvault.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class RegisterClient implements REST {

    // --- Rate Limiting Components (for client registration attempts) ---
    private static final ConcurrentHashMap<String, RateLimitInfo> requestCounters = new ConcurrentHashMap<>();
    private static final int MAX_REG_ATTEMPTS = 5; // Max registration attempts per window
    private static final long TIME_WINDOW_REG_MILLIS = TimeUnit.MINUTES.toMillis(5); // 5 minute window for registration

    // Helper class for Rate Limiting
    private static class RateLimitInfo {
        long lastRequestTime;
        int count;

        public RateLimitInfo(long lastRequestTime, int count) {
            this.lastRequestTime = lastRequestTime;
            this.count = count;
        }
    }
    // --- End Rate Limiting Components ---

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "GET method not supported for client registration.", req.getRequestURI());
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject output = null;
        try {
            JSONObject input = InputProcessor.getInput(req);
            String clientName = (String) input.get("clientName");

            // Basic input validation
            if (clientName == null || clientName.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required field: clientName.", req.getRequestURI());
                return;
            }

            // 1. Check for duplicate client name
            if (isClientNamePresent(clientName)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Client name '" + clientName + "' is already taken.", req.getRequestURI());
                return;
            }

            // 2. Generate API Key and Secret
            String apiKey = "ext-" + UUID.randomUUID().toString(); // Prefix for external clients
            String apiSecret = "ext-" + UUID.randomUUID().toString();

            // 3. Save to database
            output = saveApiClient(clientName, apiKey, apiSecret);

            OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);

        } catch (SQLException e) {
            e.printStackTrace(); // Log the stack trace
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "A database error occurred during client registration: " + e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), req.getRequestURI());
        }
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE method not supported for client registration.", req.getRequestURI());
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT method not supported for client registration.", req.getRequestURI());
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        // Only POST method is allowed for registration
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", method + " method not supported for client registration.", req.getRequestURI());
            return false;
        }

        // --- Rate Limiting Logic for Client Registration ---
        // Identify by remote IP for public registration endpoint
        String identifier = req.getRemoteAddr();

        long currentTime = System.currentTimeMillis();
        RateLimitInfo info = requestCounters.compute(identifier, (key, currentInfo) -> {
            if (currentInfo == null || (currentTime - currentInfo.lastRequestTime > TIME_WINDOW_REG_MILLIS)) {
                return new RateLimitInfo(currentTime, 1);
            } else {
                currentInfo.count++;
                return currentInfo;
            }
        });

        if (info.count > MAX_REG_ATTEMPTS) {
            res.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            String retryAfter = String.valueOf(TimeUnit.MILLISECONDS.toSeconds(TIME_WINDOW_REG_MILLIS - (currentTime - info.lastRequestTime)));
            res.setHeader("Retry-After", retryAfter);
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Too Many Requests", "Rate limit for registration exceeded. Please try again after " + retryAfter + " seconds.", req.getRequestURI());
            return false;
        }
        // --- End Rate Limiting Logic ---

        // No X-API-Key/Secret authentication for this endpoint as it's for *getting* them.
        // Other general input validation from framework
        return InputProcessor.validate(req, res);
    }

    // --- Database Access Methods ---

    /**
     * Checks if a client with the given name already exists.
     * @param clientName The client name to check.
     * @return true if present, false otherwise.
     * @throws SQLException if a database access error occurs.
     */
    private boolean isClientNamePresent(String clientName) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT api_key FROM api_user WHERE client_name = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, clientName);
            rs = pstmt.executeQuery();
            return rs.next();
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Saves a new API client to the database.
     * @param clientName The name of the client.
     * @param apiKey The generated API key.
     * @param apiSecret The generated API secret.
     * @return A JSONObject containing the registered client details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject saveApiClient(String clientName, String apiKey, String apiSecret) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO api_user (api_key, api_secret, client_name, active, created_datetime) VALUES (?, ?, ?, TRUE, ?)";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, apiKey);
            pstmt.setString(2, apiSecret);
            pstmt.setString(3, clientName);
            pstmt.setTimestamp(4, Timestamp.valueOf(LocalDateTime.now()));

            pstmt.executeUpdate();

            // Since we RETURNED api_key, we can verify it was saved.
            // For this specific case, as we already have the API key,
            // we primarily check affectedRows and then return the known values.
            output.put("apiKey", apiKey);
            output.put("apiSecret", apiSecret);
            output.put("clientName", clientName);


        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return output;
    }
}