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
import java.sql.SQLException;

public class IDTypes implements REST {

    private static final String FUNCTION = "_func";

    private static final String GET_ALL_ID_TYPES = "get_all_id_types";
    private static final String UPDATE_ID_TYPE = "update_id_type";


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
        try{
            input = InputProcessor.getInput(req);
            func = (String) input.get(FUNCTION);

            if(func != null) {
                if (func.equalsIgnoreCase(GET_ALL_ID_TYPES)) {
                    outputArray =  getAllIdTypes();
                } else if (func.equalsIgnoreCase(UPDATE_ID_TYPE)) {
                    output = updateIdType(input);
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

    private JSONArray getAllIdTypes() throws Exception {
        JSONArray outputArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = null;
        String sql = "SELECT id_type_code, id_type_name, description, validation_regex, active FROM id_type_master ORDER BY id_type_name";
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject idType = new JSONObject();
                idType.put("idTypeCode", rs.getString("id_type_code"));
                idType.put("idTypeName", rs.getString("id_type_name"));
                idType.put("description", rs.getString("description"));
                idType.put("validationRegex", rs.getString("validation_regex"));
                idType.put("active", rs.getBoolean("active"));
                outputArray.add(idType);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return outputArray;
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid URI for PUT operation. Expected /id-types/{idTypeCode}.", req.getRequestURI());
    }

    private JSONObject updateIdType(JSONObject input) throws Exception {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = null;
        JSONObject updatedIdType = new JSONObject();

        try {
            pool = new PoolDB();
            String idTypeCode = (String) input.get("idTypeCode");
            String idTypeName = (String) input.get("idTypeName");
            String description = (String) input.get("description");
            String validationRegex = (String) input.get("validationRegex");
            Boolean activeStatus = (Boolean) input.get("active"); // Expecting "active": true/false
            String sql = null;
            if (isIdTypePresent(idTypeCode)) {
                sql = "UPDATE id_type_master SET id_type_name = ?, description = ?, validation_regex = ?, active = ? WHERE id_type_code = ?";
            }
            else{
                sql = "insert into id_type_master (id_type_name,description,validation_regex,active,id_type_code) values (?,?,?,?,?)";
            }
            //System.out.println(sql);
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, idTypeName);
            pstmt.setString(2, description);
            pstmt.setString(3, validationRegex);
            pstmt.setBoolean(4, activeStatus);
            pstmt.setString(5, idTypeCode);

            pstmt.executeUpdate();
            updatedIdType.put("idTypeCode", idTypeCode);
            updatedIdType.put("idTypeName", idTypeName);
            updatedIdType.put("description", description);
            updatedIdType.put("validationRegex", validationRegex);
            updatedIdType.put("active", activeStatus);
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return updatedIdType;
    }

    private boolean isIdTypePresent(String idTypeCode) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT id_type_code FROM id_type_master WHERE id_type_code = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, idTypeCode);
            rs = pstmt.executeQuery();
            return rs.next(); // Returns true if a row is found
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE method not supported for ID type management.", req.getRequestURI());
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        // This is where Admin Portal authentication and authorization would happen.
        // It's assumed the admin would have logged in and possess a valid token.
        // This 'validate' method would check for the 'Authorization: Bearer <token>' header,
        // validate the token, and ensure the admin user has the necessary roles/permissions
        // to perform ID type management operations (e.g., 'SYSTEM_ADMIN').

        String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Missing or invalid Authorization header.", req.getRequestURI());
            return false;
        }

        // --- CONCEPTUAL AUTHENTICATION/AUTHORIZATION ---
        // Placeholder: Replace with actual token validation and RBAC logic.
        // For example:
        /*
        String token = authHeader.substring(7); // Remove "Bearer " prefix
        if (!JwtUtil.validateToken(token)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid or expired token.", req.getRequestURI());
            return false;
        }
        // Assuming your JWT contains roles, check if the admin has the necessary role
        // e.g., if (!JwtUtil.hasRole(token, "SYSTEM_ADMIN")) {
        //     OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Insufficient privileges.", req.getRequestURI());
        //     return false;
        // }
        */

        // Call framework's basic input validation
        return InputProcessor.validate(req, res);
    }
}