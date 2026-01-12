package org.tsicoop.privacyvault.api.admin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.tsicoop.aadhaarvault.framework.*;
import org.tsicoop.privacyvault.framework.*;


import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp; // For last_login_at
import java.time.LocalDateTime;
import java.util.Optional; // For Optional return types

public class Login implements REST {

    private final PasswordHasher passwordHasher = new PasswordHasher();

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "GET method not supported for admin login.", req.getRequestURI());
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject output = null;
        try {
            JSONObject input = InputProcessor.getInput(req);
            String username = (String) input.get("username");
            String password = (String) input.get("password");

            // Basic input validation
            if (username == null || username.trim().isEmpty() ||
                    password == null || password.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (username, password).", req.getRequestURI());
                return;
            }

            // 1. Get user details from DB and validate password
            Optional<JSONObject> userDetailsOptional = getUserDetails(username);

            if (userDetailsOptional.isEmpty()) {
                // User not found or inactive
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid username or password.", req.getRequestURI());
                return;
            }

            JSONObject userDetails = userDetailsOptional.get();
            String storedPasswordHash = (String) userDetails.get("passwordHash");
            boolean isActive = (boolean) userDetails.get("active");

            if (!isActive) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "User account is inactive.", req.getRequestURI());
                return;
            }

            if (!passwordHasher.checkPassword(password, storedPasswordHash)) {
                // Password mismatch
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid username or password.", req.getRequestURI());
                return;
            }

            // 2. If valid, update last login time and generate a token (conceptual)
            updateLastLogin(username);

            String generatedToken = JWTUtil.generateToken((String)userDetails.get("email"),username,(String) userDetails.get("role"));

            // 3. Prepare success response
            output = new JSONObject();
            output.put("_success", true);
            output.put("message", "Login successful");
            output.put("username", username);
            output.put("token", generatedToken);
            output.put("role", userDetails.get("role"));
            output.put("email", userDetails.get("email"));

            OutputProcessor.send(res, HttpServletResponse.SC_OK, output);

        } catch (SQLException e) {
            e.printStackTrace(); // Log the stack trace
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "A database error occurred during login: " + e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), req.getRequestURI());
        }
    }

    private Optional<JSONObject> getUserDetails(String username) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT user_id, username, password_hash, email, role, active FROM admin_user WHERE username = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, username);
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

    private void updateLastLogin(String username) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE admin_user SET last_login_at = ? WHERE username = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            pstmt.setString(2, username);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn); // No ResultSet for update
        }
    }


    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE method not supported for this resource.", req.getRequestURI());
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT method not supported for this resource.", req.getRequestURI());
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", method + " method not supported for admin login.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }
}