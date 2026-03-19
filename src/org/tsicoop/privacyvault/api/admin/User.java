package org.tsicoop.privacyvault.api.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.UUID;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.tsicoop.privacyvault.framework.*;

public class User implements Action {

    private final PasswordHasher passwordHasher = new PasswordHasher();

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "GET method not supported for admin registration.", req.getRequestURI());
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = new JSONObject();

        // Context for forensic logging
        String clientIp = req.getRemoteAddr();
        String userAgent = req.getHeader("User-Agent");
        String username = null;
        String outcome = "DENIED";
        String failureReason = null;

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func"); //

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing _func parameter", req.getRequestURI());
                return;
            }
          
            switch (func.toLowerCase()) {
                case "list_users": //
                    output = listUsers();
                    outcome = "SUCCESS";
                    break;

                case "create_user": //
                    username = (String) input.get("username");
                    String password = (String) input.get("password");
                    String role = (String) input.get("role");

                    if (username == null || password == null || role == null) {
                        failureReason = "Missing required fields for creation.";
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", failureReason, req.getRequestURI());
                        return;
                    }

                    // Prevent multiple SYSTEM_ADMIN accounts
                    if ("SYSTEM_ADMIN".equalsIgnoreCase(role)) {
                        if (isSystemAdminPresent()) {
                            failureReason = "Setup Phase Expired: A SYSTEM_ADMIN already exists.";
                            OutputProcessor.sendError(res, HttpServletResponse.SC_FORBIDDEN, failureReason);
                            return;
                        }
                    }

                    if (isUserPresent(username)) {
                        failureReason = "Username '" + username + "' is already taken.";
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", failureReason, req.getRequestURI());
                        return;
                    }

                    String hashedPassword = passwordHasher.hashPassword(password);
                    output = saveAdminUser(input, hashedPassword);
                    outcome = "SUCCESS";
                    logRegistrationEvent(username, clientIp, userAgent, outcome, null); //
                    break;

                case "generate_master_recovery_key":
                    // Only allow generation if the actor is an authenticated SYSTEM_ADMIN
                    String targetEmail = (String) input.get("email");
                    if (targetEmail == null) {
                        OutputProcessor.sendError(res, 400, "Target email required.");
                        return;
                    }
                    output = generateMasterRecoveryKey(targetEmail);
                    outcome = "SUCCESS";
                    break;

                case "break_glass_reset":
                    // This route should be accessible via InterceptingFilter bypass if the MRK is valid
                    String resetEmail = (String) input.get("email");
                    String providedMRK = (String) input.get("recovery_key");
                    String newPassword = (String) input.get("new_password");

                    if (resetEmail == null || providedMRK == null || newPassword == null) {
                        OutputProcessor.sendError(res, 400, "Missing email, recovery key, or new password.");
                        return;
                    }
                    output = breakGlassReset(resetEmail, providedMRK, newPassword);
                    outcome = "SUCCESS";
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown function: " + func, req.getRequestURI());
                    return;
            }

        } catch (Exception e) {
            outcome = "ERROR";
            failureReason = e.getMessage();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Error", failureReason, req.getRequestURI());
            return;
        }

        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
    }

    public JSONObject generateMasterRecoveryKey(String email) throws Exception {
        // 1. Generate a 24-character high-entropy alphanumeric key
        String rawMRK = "MRK-" + UUID.randomUUID().toString().substring(0, 18).toUpperCase();
        String salt = UUID.randomUUID().toString().substring(0, 8);
      
        // 2. Hash it using the same secure logic as API Keys
        String hashedMRK = computeSecureHash(rawMRK, salt);

        System.out.println("While storing - rawMRK"+rawMRK);
        System.out.println("While storing - salt"+salt);
        System.out.println("While storing - hashedMRK"+hashedMRK);


        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB(); // Uses thread-safe init

        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("UPDATE admin_user SET recovery_hash = ?, recovery_salt = ? WHERE email = ?");
            ps.setString(1, hashedMRK);
            ps.setString(2, salt);
            ps.setString(3, email);
            ps.executeUpdate();

            JSONObject result = new JSONObject();
            result.put("email", email);
            result.put("raw_recovery_key", rawMRK); // DISPLAY ONLY ONCE
            return result;
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    public JSONObject breakGlassReset(String email, String providedMRK, String newPassword) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            // 1. Fetch the stored recovery hash and salt
            ps = conn.prepareStatement("SELECT recovery_hash, recovery_salt FROM admin_user WHERE email = ? AND active = true");
            ps.setString(1, email);
            rs = ps.executeQuery();

            if (rs.next()) {
                String storedHash = rs.getString("recovery_hash");
                String salt = rs.getString("recovery_salt");

                System.out.println("While fetching - provided MRK"+providedMRK);
                System.out.println("While fetching - salt"+salt);
                System.out.println("While fetching - storedHash"+storedHash);


                 // 2. Verify the provided MRK
                if (computeSecureHash(providedMRK, salt).equals(storedHash)) {
                    // 3. Success: Update the password with a new hash
                    String newPasswordHash = passwordHasher.hashPassword(newPassword);
                    PreparedStatement psUpdate = conn.prepareStatement(
                        "UPDATE admin_user SET password_hash = ? WHERE email = ?"
                    );
                    psUpdate.setString(1, newPasswordHash);
                    psUpdate.setString(2, email);
                    psUpdate.executeUpdate();
                    psUpdate.close();

                    // 4. Forensic Logging for BSA 2023 compliance
                    logRegistrationEvent(email, "SYSTEM", "BREAK_GLASS_RESET", "SUCCESS", null);

                    JSONObject res = new JSONObject();
                    res.put("success", true);
                    res.put("message", "Password reset successful via Master Recovery Key.");
                    return res;
                }
            }
            throw new Exception("Invalid Recovery Key or Username.");
        } finally {
            pool.cleanup(rs, ps, conn);
        }
    }

    /**
     * Generates a secure SHA-256 hash for Master Recovery Keys or API Secrets.
     * Addresses feedback regarding plaintext storage of credentials.
     */
    private String computeSecureHash(String providedMRK, String salt) throws Exception {
        // 1. Combine the salt and the raw key to prevent rainbow table attacks
        String saltedInput = salt + providedMRK;
        
        // 2. Initialize SHA-256 digest
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        
        // 3. Compute the hash bytes
        byte[] encodedHash = digest.digest(saltedInput.getBytes(StandardCharsets.UTF_8));
        
        // 4. Convert byte array into a readable Hexadecimal string
        StringBuilder hexString = new StringBuilder();
        for (byte b : encodedHash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
  

    /**
     * Checks if at least one active SYSTEM_ADMIN is already registered.
     */
    private boolean isSystemAdminPresent() throws SQLException {
        boolean present = false;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT 1 FROM admin_user WHERE role = 'SYSTEM_ADMIN' AND active = true LIMIT 1";
        
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                present = true;
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return present;
    }

    /**
     * Retrieves all administrative users from the registry.
     */
    private JSONObject listUsers() throws SQLException {
        JSONObject result = new JSONObject();
        JSONArray usersArray = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            String sql = "SELECT username, email, role, active FROM admin_user ORDER BY username ASC";
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject user = new JSONObject();
                user.put("username", rs.getString("username"));
                user.put("email", rs.getString("email"));
                user.put("role", rs.getString("role"));
                user.put("active", rs.getBoolean("active"));
                usersArray.add(user);
            }
            result.put("users", usersArray);
            result.put("_success", true);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

    private void logRegistrationEvent(String username, String ip, String ua, String outcome, String reason) {
        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = null;
        String machineId = ForensicEngine.getMachineIdentifier();
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            String sql = "INSERT INTO event_log (who, operation_type, client_ip, user_agent, machine_id, outcome, failure_reason, log_datetime) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
            ps = conn.prepareStatement(sql);
            ps.setString(1, "ADMIN:" + username);
            ps.setString(2, "USER_CREATE");
            ps.setString(3, ip);
            ps.setString(4, ua);
            ps.setString(5, machineId);
            ps.setString(6, outcome);
            ps.setString(7, reason);
            ps.setTimestamp(8, Timestamp.valueOf(LocalDateTime.now()));
            ps.executeUpdate();
        } catch (Exception e) {
            System.err.println("Audit Failed: " + e.getMessage());
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    private boolean isUserPresent(String username) throws SQLException {
        boolean present = false;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT username FROM admin_user WHERE username = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, username);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                present = true;
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return present;
    }

    private JSONObject saveAdminUser(JSONObject input, String hashedPassword) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO admin_user (username, password_hash, email, role, active) VALUES (?, ?, ?, ?, ?) RETURNING user_id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, (String) input.get("username"));
            pstmt.setString(2, hashedPassword);
            pstmt.setString(3, (String) input.get("email"));
            pstmt.setString(4, (String) input.get("role"));
            pstmt.setBoolean(5, (Boolean) input.get("active"));

            rs = pstmt.executeQuery();
            if (rs.next()) {
                output.put("_created", true);
                output.put("userid", rs.getInt(1));
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return output;
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE method not supported.", req.getRequestURI());
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT method not supported.", req.getRequestURI());
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Use POST for login.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }
}