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
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class Audit implements REST {

    private static final String FUNCTION = "_func";

    private static final String GET_AUDIT_LOGS = "get_audit_logs";

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "POST method not supported for audit logs.", req.getRequestURI());
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
            if(func != null){
                if(func.equalsIgnoreCase(GET_AUDIT_LOGS)){
                    output = getAuditLogs(input);
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

    private JSONObject getAuditLogs(JSONObject input) throws Exception{
        JSONArray outputArray = new JSONArray();
        JSONObject responseBody = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = null;
        PreparedStatement countPstmt = null;
        ResultSet countRs = null;

        // Pagination parameters
        int page = 0; // default page number
        int size = 20; // default page size

        try {
            pool = new PoolDB();

            String startDateStr = (String) input.get("startDate");
            String endDateStr = (String) input.get("endDate");
            String apiKey = (String) input.get("apiKey");
            String operationType = (String) input.get("operationType");
            String idType = (String) input.get("idType");
            String referenceKey = (String) input.get("referenceKey");
            long pageNum = (long) input.get("page");
            if(pageNum > 0){
                try {
                    page = (int)pageNum;
                    if (page < 0) page = 0;
                } catch (NumberFormatException e) { }
            }
            long pageSize = (long) input.get("size");
            if(pageSize > 0){
                try {
                    size = (int)pageSize;
                    if (size <= 0) size = 20; // Ensure positive page size
                } catch (NumberFormatException e) { /* Ignore, use default */ }
            }

            // Build SQL dynamically based on filters
            StringBuilder sqlBuilder = new StringBuilder("SELECT el.log_id, el.api_key, au.client_name, el.operation_type, " +
                    "idtm.id_type_code, el.reference_key, el.log_datetime FROM event_log el " +
                    "LEFT JOIN api_user au ON el.api_key = au.api_key " +
                    "LEFT JOIN id_type_master idtm ON el.id_type_code = idtm.id_type_code WHERE 1=1");

            List<Object> sqlParams = new ArrayList<>();

            if (startDateStr != null && !startDateStr.trim().isEmpty()) {
                sqlBuilder.append(" AND el.log_datetime >= ?");
                sqlParams.add(Timestamp.valueOf(LocalDateTime.parse(startDateStr)));
            }
            if (endDateStr != null && !endDateStr.trim().isEmpty()) {
                sqlBuilder.append(" AND el.log_datetime <= ?");
                sqlParams.add(Timestamp.valueOf(LocalDateTime.parse(endDateStr)));
            }
            if (apiKey != null && !apiKey.trim().isEmpty()) {
                sqlBuilder.append(" AND el.api_key = ?");
                sqlParams.add(apiKey);
            }
            if (operationType != null && !operationType.trim().isEmpty()) {
                sqlBuilder.append(" AND el.operation_type = ?");
                sqlParams.add(operationType);
            }
            if (idType != null && !idType.trim().isEmpty()) {
                sqlBuilder.append(" AND idtm.id_type_code = ?");
                sqlParams.add(idType);
            }
            if (referenceKey != null && !referenceKey.trim().isEmpty()) {
                sqlBuilder.append(" AND el.reference_key = ?::uuid"); // Cast to UUID in PostgreSQL
                sqlParams.add(referenceKey);
            }

            sqlBuilder.append(" ORDER BY el.log_datetime DESC"); // Latest logs first

            // Add pagination
            //sqlBuilder.append(" LIMIT ? OFFSET ?");
            //sqlParams.add(size);
            //sqlParams.add(page * size);

            System.out.println(sqlBuilder.toString());

            String countSql = "SELECT COUNT(*) FROM event_log el LEFT JOIN id_type_master idtm ON el.id_type_code = idtm.id_type_code WHERE 1=1";
            // Re-use filters for count query
            StringBuilder countSqlBuilder = new StringBuilder(countSql);
            if (startDateStr != null && !startDateStr.trim().isEmpty()) { countSqlBuilder.append(" AND el.log_datetime >= ?"); }
            if (endDateStr != null && !endDateStr.trim().isEmpty()) { countSqlBuilder.append(" AND el.log_datetime <= ?"); }
            if (apiKey != null && !apiKey.trim().isEmpty()) { countSqlBuilder.append(" AND el.api_key = ?"); }
            if (operationType != null && !operationType.trim().isEmpty()) { countSqlBuilder.append(" AND el.operation_type = ?"); }
            if (idType != null && !idType.trim().isEmpty()) { countSqlBuilder.append(" AND idtm.id_type_code = ?"); }
            if (referenceKey != null && !referenceKey.trim().isEmpty()) { countSqlBuilder.append(" AND el.reference_key = ?::uuid"); }


            conn = pool.getConnection();

            // First, get total count for pagination metadata
            countPstmt = conn.prepareStatement(countSqlBuilder.toString());
            int paramIndex = 1;
            for (int i = 0; i < sqlParams.size() - 2; i++) { // Exclude LIMIT/OFFSET params
                Object param = sqlParams.get(i);
                if (param instanceof Timestamp) {
                    countPstmt.setTimestamp(paramIndex++, (Timestamp) param);
                } else if (param instanceof String) {
                    countPstmt.setString(paramIndex++, (String) param);
                }
            }
            countRs = countPstmt.executeQuery();
            long totalElements = 0;
            if (countRs.next()) {
                totalElements = countRs.getLong(1);
            }


            // Now, get the actual paginated logs
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            paramIndex = 1;
            for (Object param : sqlParams) {
                if (param instanceof Timestamp) {
                    pstmt.setTimestamp(paramIndex++, (Timestamp) param);
                } else if (param instanceof String) {
                    pstmt.setString(paramIndex++, (String) param);
                } else if (param instanceof Integer) { // For LIMIT/OFFSET
                    pstmt.setInt(paramIndex++, (Integer) param);
                }
            }

            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject logEntry = new JSONObject();
                logEntry.put("logId", rs.getLong("log_id"));
                logEntry.put("apiKey", rs.getString("api_key"));
                logEntry.put("clientName", rs.getString("client_name")); // client_name from api_user join
                logEntry.put("operationType", rs.getString("operation_type"));
                logEntry.put("idType", rs.getString("id_type_code")); // id_type_code from id_type_master join
                logEntry.put("referenceKey", rs.getString("reference_key")); // UUID will be stringified
                logEntry.put("logDatetime", rs.getTimestamp("log_datetime").toLocalDateTime().toString());
                outputArray.add(logEntry);
            }

            responseBody.put("content", outputArray);

            JSONObject pageable = new JSONObject();
            pageable.put("pageNumber", page);
            pageable.put("pageSize", size);
            // Add other pageable fields as needed based on your framework's typical response
            responseBody.put("pageable", pageable);

            responseBody.put("totalPages", (totalElements + size - 1) / size);
            responseBody.put("totalElements", totalElements);
            responseBody.put("last", (page * size + outputArray.size()) >= totalElements);
            responseBody.put("first", page == 0);
            responseBody.put("numberOfElements", outputArray.size());
            responseBody.put("size", size);
            responseBody.put("number", page);
            responseBody.put("empty", outputArray.isEmpty());

        } finally {
            pool.cleanup(countRs, countPstmt, null);
            pool.cleanup(rs, pstmt, conn);
        }
        return responseBody;
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT method not supported for audit logs.", req.getRequestURI());
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE method not supported for audit logs.", req.getRequestURI());
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        // Validation for audit log retrieval:
        // 1. Check method (should be GET)
        // 2. Perform authentication (Bearer token)
        // 3. Perform authorization (Admin user must have AUDIT_VIEWER or SYSTEM_ADMIN role)

        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", method + " method not supported for audit logs.", req.getRequestURI());
            return false;
        }

        // --- Authentication/Authorization Logic ---
        String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Missing or invalid Authorization header.", req.getRequestURI());
            return false;
        }

        // Placeholder: Replace with actual token validation and RBAC logic.
        // Assuming your framework (or JWT utility) provides a way to validate the token
        // and extract user roles/permissions.
        /*
        String token = authHeader.substring(7); // Remove "Bearer " prefix
        try {
            // Example:
            // if (!JwtUtil.validateToken(token)) {
            //     OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid or expired token.", req.getRequestURI());
            //     return false;
            // }
            // String userRole = JwtUtil.getRole(token); // Or List<String> roles = JwtUtil.getRoles(token);
            // if (!"SYSTEM_ADMIN".equals(userRole) && !"AUDIT_VIEWER".equals(userRole)) { // Example RBAC check
            //     OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Insufficient privileges to view audit logs.", req.getRequestURI());
            //     return false;
            // }
        } catch (Exception e) { // Catch token parsing/validation errors
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid token format: " + e.getMessage(), req.getRequestURI());
            return false;
        }
        */

        // Call framework's basic input validation if any
        return InputProcessor.validate(req, res);
    }
}