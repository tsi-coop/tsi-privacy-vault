package org.tsicoop.privacyvault.api.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.LocalDateTime;
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
            System.out.println(input);

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
        return "POST".equalsIgnoreCase(method);
    }
}