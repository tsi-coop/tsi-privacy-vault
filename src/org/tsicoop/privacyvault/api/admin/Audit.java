package org.tsicoop.privacyvault.api.admin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.tsicoop.privacyvault.framework.InputProcessor;
import org.tsicoop.privacyvault.framework.OutputProcessor;
import org.tsicoop.privacyvault.framework.Action;
import org.tsicoop.privacyvault.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class Audit implements Action {

    private static final String FUNCTION = "_func";
    private static final String GET_AUDIT_LOGS = "get_audit_logs";
    private static final String VERIFY_AUDIT_CHAIN = "verify_audit_chain";

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "POST method not supported for audit logs.", req.getRequestURI());
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = new JSONObject();
        String func = null;
        try {
            input = InputProcessor.getInput(req);
            func = (String) input.get(FUNCTION);
            if (func != null && func.equalsIgnoreCase(GET_AUDIT_LOGS)) {
                output = getAuditLogs(input);
            } else if (func != null && func.equalsIgnoreCase(VERIFY_AUDIT_CHAIN)) {
                output = verifyAuditChain(input);
            }
        } catch (Exception e) {
            OutputProcessor.sendError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Unknown server error");
            e.printStackTrace();
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
    }

    /**
     * Walks the event_log hash chain (db/04_audit_chain.sql). Optional input:
     *   from_seq           start the walk here instead of at the first row
     *   expected_head_seq  } a head recorded earlier outside the database; the chain must still
     *   expected_head_hash } contain that row with that hash, which exposes tail truncation
     */
    private JSONObject verifyAuditChain(JSONObject input) throws Exception {
        Long fromSeq = input.get("from_seq") == null ? null : ((Number) input.get("from_seq")).longValue();
        Long expSeq = input.get("expected_head_seq") == null ? null : ((Number) input.get("expected_head_seq")).longValue();
        String expHash = (String) input.get("expected_head_hash");
        if ((expSeq == null) != (expHash == null)) {
            throw new Exception("expected_head_seq and expected_head_hash must be supplied together.");
        }

        JSONObject out = new JSONObject();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT valid, rows_checked, first_bad_seq, reason, head_seq, head_hash FROM verify_event_log_chain(?)");
            if (fromSeq == null) ps.setNull(1, java.sql.Types.BIGINT); else ps.setLong(1, fromSeq);
            rs = ps.executeQuery();
            if (!rs.next()) throw new Exception("Verification returned no result.");

            boolean valid = rs.getBoolean("valid");
            String reason = rs.getString("reason");
            long badSeq = rs.getLong("first_bad_seq");
            boolean hasBad = !rs.wasNull();
            out.put("rows_checked", rs.getLong("rows_checked"));
            long headSeq = rs.getLong("head_seq");
            boolean hasHead = !rs.wasNull();
            String headHash = rs.getString("head_hash");
            rs.close();
            ps.close();

            if (valid && expSeq != null) {
                ps = conn.prepareStatement("SELECT row_hash FROM event_log WHERE chain_seq = ?");
                ps.setLong(1, expSeq);
                rs = ps.executeQuery();
                if (!rs.next()) {
                    valid = false;
                    badSeq = expSeq;
                    hasBad = true;
                    reason = "recorded head row is missing (the log was truncated)";
                } else if (!expHash.equalsIgnoreCase(rs.getString(1))) {
                    valid = false;
                    badSeq = expSeq;
                    hasBad = true;
                    reason = "recorded head hash does not match";
                }
            }

            out.put("valid", valid);
            if (hasBad) out.put("first_bad_seq", badSeq);
            if (reason != null) out.put("reason", reason);
            if (hasHead) {
                out.put("head_seq", headSeq);
                out.put("head_hash", headHash);
            }
        } finally {
            pool.cleanup(rs, ps, conn);
        }
        return out;
    }

    private JSONObject getAuditLogs(JSONObject input) throws Exception {
        JSONArray outputArray = new JSONArray();
        JSONObject responseBody = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        PreparedStatement countPstmt = null;
        ResultSet countRs = null;

        int page = 0;
        int size = 20;

        try {
            // Extract pagination and filters
            if (input.get("page") != null) page = ((Long) input.get("page")).intValue();
            if (input.get("size") != null) size = ((Long) input.get("size")).intValue();

            String startDateStr = (String) input.get("startDate");
            String endDateStr = (String) input.get("endDate");
            String apiKey = (String) input.get("apiKey");
            String operationType = (String) input.get("operationType");
            String entityCode = (String) input.get("entityCode"); // Renamed from idType
            String referenceKey = (String) input.get("referenceKey");
            String outcome = (String) input.get("outcome");

            // Revised SQL joining with vault_entity_master
            StringBuilder sqlBuilder = new StringBuilder("SELECT el.log_id, el.who,  el.operation_type, " +
                    "el.entity_code, el.entity_ref,el.utility_ref, el.client_ip, el.user_agent, el.machine_id, el.outcome, " +
                    "el.failure_reason, el.log_datetime FROM event_log el " +
                    "LEFT JOIN vault_entity_master vem ON el.entity_code = vem.entity_code WHERE 1=1");

            List<Object> sqlParams = new ArrayList<>();

            // Dynamic filter building
            if (startDateStr != null && !startDateStr.trim().isEmpty()) {
                sqlBuilder.append(" AND el.log_datetime >= ?");
                sqlParams.add(Timestamp.valueOf(LocalDateTime.parse(startDateStr)));
            }
            if (endDateStr != null && !endDateStr.trim().isEmpty()) {
                sqlBuilder.append(" AND el.log_datetime <= ?");
                sqlParams.add(Timestamp.valueOf(LocalDateTime.parse(endDateStr)));
            }
            if (apiKey != null && !apiKey.trim().isEmpty()) {
                sqlBuilder.append(" AND el.who = ?");
                sqlParams.add(apiKey);
            }
            if (operationType != null && !operationType.trim().isEmpty()) {
                sqlBuilder.append(" AND el.operation_type = ?");
                sqlParams.add(operationType);
            }
            // Prefix match for operations whose name carries a variable suffix, such as
            // ERASURE_SHRED:<principal>:condemned=<n>. Any one prefix may match.
            Object prefixes = input.get("operationPrefixes");
            if (prefixes instanceof JSONArray && !((JSONArray) prefixes).isEmpty()) {
                sqlBuilder.append(" AND (");
                boolean first = true;
                for (Object o : (JSONArray) prefixes) {
                    if (!first) sqlBuilder.append(" OR ");
                    first = false;
                    sqlBuilder.append("el.operation_type LIKE ? ESCAPE '\\'");
                    sqlParams.add(String.valueOf(o).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%");
                }
                sqlBuilder.append(")");
            }
            if (entityCode != null && !entityCode.trim().isEmpty()) {
                sqlBuilder.append(" AND el.entity_code = ?");
                sqlParams.add(entityCode);
            }
            if (referenceKey != null && !referenceKey.trim().isEmpty()) {
                sqlBuilder.append(" AND el.reference_key = ?::uuid");
                sqlParams.add(referenceKey);
            }
            if (outcome != null && !outcome.trim().isEmpty()) {
                sqlBuilder.append(" AND el.outcome = ?");
                sqlParams.add(outcome);
            }

            // Total Count for Pagination
            String countSql = "SELECT COUNT(*) FROM (" + sqlBuilder.toString() + ") AS total";
            conn = pool.getConnection();
            countPstmt = conn.prepareStatement(countSql);
            for (int i = 0; i < sqlParams.size(); i++) {
                countPstmt.setObject(i + 1, sqlParams.get(i));
            }
            countRs = countPstmt.executeQuery();
            long totalElements = 0;
            if (countRs.next()) totalElements = countRs.getLong(1);

            // Paginated Results
            sqlBuilder.append(" ORDER BY el.log_datetime DESC LIMIT ? OFFSET ?");
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            int idx = 1;
            for (Object param : sqlParams) pstmt.setObject(idx++, param);
            pstmt.setInt(idx++, size);
            pstmt.setInt(idx++, page * size);

            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject logEntry = new JSONObject();
                logEntry.put("logId", rs.getLong("log_id"));
                logEntry.put("apiKey", rs.getString("who"));
                logEntry.put("operationType", rs.getString("operation_type"));
                logEntry.put("entityCode", rs.getString("entity_code"));
                logEntry.put("clientIp", rs.getString("client_ip"));
                logEntry.put("userAgent", rs.getString("user_agent"));
                logEntry.put("machineId", rs.getString("machine_id"));
                logEntry.put("outcome", rs.getString("outcome"));
                logEntry.put("failureReason", rs.getString("failure_reason"));
                logEntry.put("logDatetime", rs.getTimestamp("log_datetime").toLocalDateTime().toString());
                outputArray.add(logEntry);
            }

            responseBody.put("content", outputArray);
            responseBody.put("totalElements", totalElements);
            responseBody.put("totalPages", (totalElements + size - 1) / size);
            responseBody.put("number", page);
            responseBody.put("size", size);

        } catch (Exception e) {
            throw e;
        } finally {
            pool.cleanup(countRs, countPstmt, null);
            pool.cleanup(rs, pstmt, conn);
        }
        return responseBody;
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT not supported.", req.getRequestURI());
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE not supported.", req.getRequestURI());
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Use POST for audit logs.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }
}