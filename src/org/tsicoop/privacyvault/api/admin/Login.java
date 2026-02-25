package org.tsicoop.privacyvault.api.admin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Optional;
import org.json.simple.JSONObject;
import org.tsicoop.privacyvault.framework.*;

public class Login implements Action {

    private final PasswordHasher passwordHasher = new PasswordHasher();

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "GET method not supported for admin login.", req.getRequestURI());
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject output = new JSONObject();
        String email = null; // Changed from username
        String clientIp = req.getRemoteAddr();
        String userAgent = req.getHeader("User-Agent");
        String outcome = "DENIED";
        String failureReason = null;

        try {
            JSONObject input = InputProcessor.getInput(req);
            email = (String) input.get("email"); // Now extracting email
            String password = (String) input.get("password");

            // Basic input validation
            if (email == null || email.trim().isEmpty() ||
                    password == null || password.trim().isEmpty()) {
                failureReason = "Missing required fields: email and password";
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", failureReason, req.getRequestURI());
                return;
            }

            // 1. Get user details from DB by Email and validate password
            Optional<JSONObject> userDetailsOptional = getUserDetailsByEmail(email);

            if (userDetailsOptional.isEmpty()) {
                failureReason = "Invalid email or password";
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", failureReason, req.getRequestURI());
                return;
            }

            JSONObject userDetails = userDetailsOptional.get();
            String storedPasswordHash = (String) userDetails.get("passwordHash");
            boolean isActive = (boolean) userDetails.get("active");
            String username = (String) userDetails.get("username");

            if (!isActive) {
                failureReason = "User account is inactive";
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", failureReason, req.getRequestURI());
                return;
            }

            if (!passwordHasher.checkPassword(password, storedPasswordHash)) {
                failureReason = "Invalid email or password";
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", failureReason, req.getRequestURI());
                return;
            }

            // 2. Success path
            updateLastLogin(email);
            String generatedToken = JWTUtil.generateToken(email, username, (String) userDetails.get("role"));

            output.put("_success", true);
            output.put("message", "Login successful");
            output.put("username", username);
            output.put("token", generatedToken);
            output.put("role", userDetails.get("role"));
            output.put("email", email);
            
            outcome = "SUCCESS";
            OutputProcessor.send(res, HttpServletResponse.SC_OK, output);

        } catch (SQLException e) {
            outcome = "ERROR";
            failureReason = "Database Error: " + e.getMessage();
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", failureReason, req.getRequestURI());
        } catch (Exception e) {
            outcome = "ERROR";
            failureReason = "Internal Error: " + e.getMessage();
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", failureReason, req.getRequestURI());
        } finally {
            // Resource cleanup happens here before logging
        }

        // --- POST-FINALLY FORENSIC LOGGING ---
        if (email != null) {
            logLoginEvent(email, clientIp, userAgent, outcome, failureReason);
        }
    }

    /**
     * Records administrative login attempts using email as the identifier.
     */
    private void logLoginEvent(String email, String ip, String ua, String outcome, String reason) {
        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = null;
        String machineId = org.tsicoop.privacyvault.framework.ForensicEngine.getMachineIdentifier();
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            String sql = "INSERT INTO event_log (who, operation_type, client_ip, user_agent, machine_id, outcome, failure_reason, log_datetime) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
            ps = conn.prepareStatement(sql);
            ps.setString(1, "ADMIN:" + email); 
            ps.setString(2, "ADMIN_LOGIN");
            ps.setString(3, ip);
            ps.setString(4, ua);
            ps.setString(5, machineId);
            ps.setString(6, outcome);
            ps.setString(7, reason);
            ps.setTimestamp(8, Timestamp.valueOf(LocalDateTime.now()));
            ps.executeUpdate();
        } catch (Exception e) {
            System.err.println("CRITICAL: Login Audit Failed: " + e.getMessage());
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    /**
     * Modified to query by email instead of username.
     */
    private Optional<JSONObject> getUserDetailsByEmail(String email) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT user_id, username, password_hash, email, role, active FROM admin_user WHERE email = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, email);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject user = new JSONObject();
                user.put("userId", rs.getInt("user_id"));
                user.put("username", rs.getString("username"));
                user.put("passwordHash", rs.getString("password_hash"));
                user.put("email", rs.getString("email"));
                user.put("role", rs.getString("role"));
                user.put("active", rs.getBoolean("active"));
                return Optional.of(user);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    private void updateLastLogin(String email) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE admin_user SET last_login_at = ? WHERE email = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            pstmt.setString(2, email);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
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