package org.tsicoop.privacyvault.api.admin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.tsicoop.privacyvault.framework.InputProcessor;
import org.tsicoop.privacyvault.framework.OutputProcessor;
import org.tsicoop.privacyvault.framework.REST;
import org.tsicoop.privacyvault.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.UUID; // For generating new API secrets

public class Clients implements REST {

    private static final String FUNCTION = "_func";

    private static final String GET_ALL_CLIENTS = "get_all_clients";
    private static final String GET_CLIENT_DETAILS = "get_client_details";
    private static final String UPDATE_CLIENT_STATUS = "update_client_status";
    private static final String GENERATE_NEW_CLIENT_SECRET = "generate_new_client_secret";

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Resource not found.", req.getRequestURI());
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = null;
        JSONArray outputArray = null;
        String func = null;
        try{
            input = InputProcessor.getInput(req);
            func = (String) input.get(FUNCTION);

            if(func != null) {
                if (func.equalsIgnoreCase(GET_ALL_CLIENTS)) {
                    outputArray = getAllClients();
                } else if (func.equalsIgnoreCase(GET_CLIENT_DETAILS)) {
                    String apiKey = (String) input.get("api_key");
                    output = getClientDetails(apiKey);
                } else if (func.equalsIgnoreCase(UPDATE_CLIENT_STATUS)) {
                    String apiKey =(String) input.get("api_key");
                    Boolean activeStatus = (Boolean) input.get("active"); // Expecting "active": true/false
                    output = updateClientStatus(apiKey, activeStatus);
                } else if (func.equalsIgnoreCase(GENERATE_NEW_CLIENT_SECRET)) {
                    String apiKey = (String) input.get("api_key");
                    output = generateNewClientSecret(apiKey);
                }
            }
        }catch(Exception e){
            OutputProcessor.sendError(res,HttpServletResponse.SC_INTERNAL_SERVER_ERROR,"Unknown server error");
            e.printStackTrace();
        }
        if(outputArray != null){
            OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
        }else {
            OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
        }
    }

    private JSONArray getAllClients() throws Exception {
        JSONArray outputArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = null;
        String sql = "SELECT api_key, client_name, active, created_datetime FROM api_user";

        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject client = new JSONObject();
                client.put("apiKey", rs.getString("api_key"));
                client.put("clientName", rs.getString("client_name"));
                client.put("active", rs.getBoolean("active"));
                client.put("createdDatetime", rs.getTimestamp("created_datetime").toLocalDateTime().toString());
                outputArray.add(client);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        System.out.println(outputArray);
        return outputArray;
    }

    private JSONObject getClientDetails(String apiKey) throws Exception {
        JSONObject output = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = null;
        String sql = "SELECT api_key, api_secret, client_name, active, created_datetime FROM api_user WHERE api_key = ?";

        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, apiKey);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                output = new JSONObject();
                output.put("apiKey", rs.getString("api_key"));
                output.put("apiSecret", rs.getString("api_secret")); // Admin portal can see secret
                output.put("clientName", rs.getString("client_name"));
                output.put("active", rs.getBoolean("active"));
                output.put("createdDatetime", rs.getTimestamp("created_datetime").toLocalDateTime().toString());
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return output;
    }

    private JSONObject generateNewClientSecret(String apiKey){
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = null;
        String newApiSecret = UUID.randomUUID().toString(); // Generate new secret
        String sql = "UPDATE api_user SET api_secret = ? WHERE api_key = ?";

        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, newApiSecret);
            pstmt.setString(2, apiKey);

            pstmt.executeUpdate();
            output.put("apiKey", apiKey);
            output.put("apiSecret", newApiSecret);
        } catch(Exception e){
            e.printStackTrace();
        }finally {
            pool.cleanup(null, pstmt, conn);
        }
        return output;
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
       OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT method not supported for this specific path.", req.getRequestURI());
    }

    private JSONObject updateClientStatus(String apiKey, boolean activeStatus) throws Exception{
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = null;
        JSONObject updatedClient = new JSONObject();
        try {
            pool = new PoolDB();
            String sql = "UPDATE api_user SET active = ? WHERE api_key = ?";
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setBoolean(1, activeStatus);
            pstmt.setString(2, apiKey);
            pstmt.executeUpdate();
            updatedClient.put("apiKey", apiKey);
            updatedClient.put("active", activeStatus);
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return updatedClient;
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE method not supported for this resource.", req.getRequestURI());
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        // This is where Admin Portal authentication and authorization would happen.
        // It's assumed the admin would have logged in and possess a valid token.
        // This 'validate' method would check for the 'Authorization: Bearer <token>' header,
        // validate the token, and ensure the admin user has the necessary roles/permissions
        // to perform client management operations.

        // Placeholder for real authentication/authorization logic
        String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Missing or invalid Authorization header.", req.getRequestURI());
            return false;
        }

        // Example: Validate the token (e.g., JWT validation) and check admin role
        // For actual implementation, integrate with your token validation utility
        // and role-based access control (RBAC) logic.
        /*
        String token = authHeader.substring(7); // Remove "Bearer " prefix
        if (!JwtUtil.validateToken(token)) { // Assuming a JwtUtil class
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid or expired token.", req.getRequestURI());
            return false;
        }
        // Further check roles: e.g., if(JwtUtil.getRoles(token).contains("CLIENT_MANAGER") == false) ...
        */

        // Call framework's basic input validation
        return InputProcessor.validate(req, res);
    }
}
