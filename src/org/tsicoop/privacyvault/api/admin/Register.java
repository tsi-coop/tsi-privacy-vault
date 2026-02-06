package org.tsicoop.privacyvault.api.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.tsicoop.privacyvault.framework.*;



public class Register implements REST {

   private final ObjectMapper objectMapper = new ObjectMapper();
    private final PasswordHasher passwordHasher = new PasswordHasher();

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "GET method not supported for admin registration.", req.getRequestURI());
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = null;
        JSONArray outputArray = null;
        try {
            input = InputProcessor.getInput(req);
            String username = (String) input.get("username");
            String password = (String) input.get("password");
            String email = (String) input.get("email");
            String role = (String) input.get("role");

            // Basic input validation
            if (username == null || username.trim().isEmpty() ||
                    password == null || password.trim().isEmpty() ||
                    role == null || role.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (username, password, role).", req.getRequestURI());
                return;
            }

            // --- Business Logic & DB Calls ---
            // 1. Check for duplicate username
            if (isUserPresent(username)) {
                res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                OutputProcessor.errorResponse(res,HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Username '" + username + "' is already taken.", req.getRequestURI());
                return;
            }

            // 2. Hash the password
            String hashedPassword = passwordHasher.hashPassword(password);

            // 3. Save to database directly using a method in this class
            output = saveAdminUser(input,hashedPassword);

        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res,HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), req.getRequestURI());
        }
        if(outputArray != null){
            OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
        }else {
            OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
        }
    }

    private boolean isUserPresent(String username) throws SQLException {
        boolean present = false;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT user_id, username FROM admin_user WHERE username = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, username);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                present = true;
            }
        }finally{
            pool.cleanup(rs,pstmt,conn);
        }
        return present;
    }

    private JSONObject saveAdminUser(JSONObject input, String hashedPassword) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO admin_user (username, password_hash, email, role) VALUES (?, ?, ?, ?) RETURNING user_id";

        String username = (String) input.get("username");
        String email = (String) input.get("email");
        String role = (String) input.get("role");

        try {
            conn = pool.getConnection();
            // Use Statement.RETURN_GENERATED_KEYS if not using RETURNING clause in SQL
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setString(1, username);
            pstmt.setString(2, hashedPassword);
            pstmt.setString(3, email);
            pstmt.setString(4, role);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating user failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                output.put("_created",true);
                output.put("userid",rs.getInt(1)); // Get the first generated key (user_id)
            } else {
                throw new SQLException("Creating user failed, no ID obtained.");
            }
        }finally{
                pool.cleanup(rs,pstmt,conn);
        }
        return output;
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
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res){
        return InputProcessor.validate( req,
                res);
    }
}