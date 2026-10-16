package org.tsicoop.privacyvault.framework;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

/**
 * Custody lifecycle of a data principal: every record the vault holds for them and, against each
 * record, what happened to it (STORE, FETCH, SEARCH, ERASE), joined from event_log by entity_ref.
 * Backs the Legal page and the principal certificate (Section 63 BSA 2023).
 *
 * A record stored without a principal_id cannot be found by person; it is reachable by its
 * reference key, as a subject of one record.
 *
 * The result holds reference keys, entity codes, hashes and audit metadata only. It never carries
 * decrypted values, file names or search terms.
 */
public class CustodyService {

    public static class CustodyException extends Exception {
        public final int status;
        public CustodyException(int status, String message) {
            super(message);
            this.status = status;
        }
    }

    public static final String KIND_STORE = "STORE";
    public static final String KIND_FETCH = "FETCH";
    public static final String KIND_SEARCH = "SEARCH";
    public static final String KIND_ERASE = "ERASE";
    public static final String KIND_OTHER = "OTHER";

    /** Events returned per record by {@link #build}; counts always cover all of them. */
    public static final int DEFAULT_EVENT_LIMIT = 200;

    private CustodyService() { }

    // ------------------------------------------------------------------ lifecycle view

    /**
     * Custody view for a principal, or for one record when only a reference key is given.
     * Exactly one of principalId and referenceKey is expected; principalId wins when both are set.
     */
    public static JSONObject build(String principalId, String referenceKey, int eventLimit) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = pool.getConnection();
        try {
            JSONObject out = build(conn, principalId, referenceKey, eventLimit, false);
            out.remove("_all_events");
            return out;
        } finally {
            pool.cleanup(null, null, conn);
        }
    }

    /**
     * @param keepAllEvents when true every event is kept in each record (certificate); otherwise
     *                      only the latest {@code eventLimit} per record, with totals in {@code counts}.
     */
    static JSONObject build(Connection conn, String principalId, String referenceKey, int eventLimit,
                            boolean keepAllEvents) throws Exception {
        boolean byPrincipal = principalId != null && !principalId.trim().isEmpty();
        UUID refOnly = null;
        if (!byPrincipal) {
            if (referenceKey == null || referenceKey.trim().isEmpty()) {
                throw new CustodyException(400, "Give a principal_id or a reference_key.");
            }
            try {
                refOnly = UUID.fromString(referenceKey.trim());
            } catch (IllegalArgumentException e) {
                throw new CustodyException(400, "reference_key is not a valid UUID.");
            }
            principalId = principalOfRecord(conn, refOnly);
            if (principalId == null && !recordExists(conn, refOnly)) {
                throw new CustodyException(404, "No record with that reference key.");
            }
        } else {
            principalId = principalId.trim();
        }

        // A reference key whose record belongs to a principal opens the whole principal.
        boolean singleRecord = principalId == null;

        JSONArray records = new JSONArray();
        List<UUID> refs = new ArrayList<>();
        String sql = "SELECT entity_ref, entity_type, id_type_code, created_at, retain_until, erased_at, " +
                     "hashed_value_sha256, (encrypted_data_key IS NULL AND storage_key IS NULL) AS key_gone " +
                     "FROM vault_entities WHERE " + (singleRecord ? "entity_ref = ?" : "principal_id = ?") +
                     " ORDER BY created_at ASC, entity_ref ASC";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            if (singleRecord) ps.setObject(1, refOnly); else ps.setString(1, principalId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    JSONObject r = new JSONObject();
                    UUID ref = (UUID) rs.getObject("entity_ref");
                    refs.add(ref);
                    r.put("reference_key", ref.toString());
                    r.put("flavor", rs.getString("entity_type"));
                    r.put("entity_code", rs.getString("id_type_code"));
                    r.put("created_at", iso(rs.getTimestamp("created_at")));
                    r.put("retain_until", iso(rs.getTimestamp("retain_until")));
                    r.put("erased_at", iso(rs.getTimestamp("erased_at")));
                    r.put("sha256", rs.getString("hashed_value_sha256"));
                    r.put("status", rs.getTimestamp("erased_at") != null ? "ERASED" : "HELD");
                    records.add(r);
                }
            }
        }

        JSONObject register = principalId == null ? null : registerRow(conn, principalId);
        if (records.isEmpty() && register == null) {
            throw new CustodyException(404, byPrincipal
                    ? "No records or erasure request found for that principal_id."
                    : "No record with that reference key.");
        }

        // Events by record
        java.util.Map<String, List<JSONObject>> byRef = new java.util.HashMap<>();
        for (UUID u : refs) byRef.put(u.toString(), new ArrayList<>());
        List<JSONObject> subjectEvents = new ArrayList<>();
        List<JSONObject> all = new ArrayList<>();

        if (!refs.isEmpty()) {
            Array arr = conn.createArrayOf("uuid", refs.toArray());
            Array ops = conn.createArrayOf("text", refs.stream()
                    .map(u -> "ERASURE_SHRED_RECORD:" + u).toArray());
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT log_id, chain_seq, row_hash, who, operation_type, outcome, failure_reason, " +
                    "client_ip, machine_id, log_datetime, entity_ref FROM event_log " +
                    "WHERE entity_ref = ANY(?) OR operation_type = ANY(?) " +
                    "ORDER BY log_datetime ASC, log_id ASC")) {
                ps.setArray(1, arr);
                ps.setArray(2, ops);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        JSONObject e = event(rs);
                        String op = (String) e.get("operation");
                        UUID er = (UUID) rs.getObject("entity_ref");
                        String key = er != null ? er.toString()
                                : (op.startsWith("ERASURE_SHRED_RECORD:") ? op.substring("ERASURE_SHRED_RECORD:".length()) : null);
                        if (key != null && byRef.containsKey(key)) {
                            byRef.get(key).add(e);
                            all.add(e);
                        }
                    }
                }
            }
        }
        if (principalId != null) {
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT log_id, chain_seq, row_hash, who, operation_type, outcome, failure_reason, " +
                    "client_ip, machine_id, log_datetime, entity_ref FROM event_log " +
                    "WHERE operation_type = ? OR starts_with(operation_type, ?) " +
                    "   OR operation_type = ? OR starts_with(operation_type, ?) " +
                    "ORDER BY log_datetime ASC, log_id ASC")) {
                ps.setString(1, "ERASURE_SHRED:" + principalId);
                ps.setString(2, "ERASURE_SHRED:" + principalId + ":");
                ps.setString(3, "ERASURE_RESULT:" + principalId);
                ps.setString(4, "ERASURE_RESULT:" + principalId + ":");
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        JSONObject e = event(rs);
                        subjectEvents.add(e);
                        all.add(e);
                    }
                }
            }
        }

        // Per record: events in time order, plus an ERASE marker from erased_at when the erasure
        // was requested for the whole principal (no record-level event exists for it).
        String requestedBy = register == null ? null : (String) register.get("requested_by");
        long storeCount = 0, fetchCount = 0, searchCount = 0, eraseCount = 0;
        for (Object o : records) {
            JSONObject r = (JSONObject) o;
            List<JSONObject> evs = byRef.get((String) r.get("reference_key"));
            boolean hasErase = false;
            for (JSONObject e : evs) if (KIND_ERASE.equals(e.get("kind")) && "SUCCESS".equals(e.get("outcome"))) hasErase = true;
            if (r.get("erased_at") != null && !hasErase) {
                JSONObject m = new JSONObject();
                m.put("kind", KIND_ERASE);
                m.put("operation", "ERASURE_SHRED:" + principalId);
                m.put("outcome", "SUCCESS");
                m.put("at", r.get("erased_at"));
                m.put("who", requestedBy);
                m.put("via", "PRINCIPAL_ERASURE");
                evs.add(m);
                // keep the timeline ordered
                evs.sort((a, b) -> String.valueOf(a.get("at")).compareTo(String.valueOf(b.get("at"))));
            }
            JSONObject counts = new JSONObject();
            long s = 0, f = 0, q = 0, x = 0;
            String firstAccess = null, lastAccess = null;
            for (JSONObject e : evs) {
                String k = (String) e.get("kind");
                boolean ok = "SUCCESS".equals(e.get("outcome"));
                if (KIND_STORE.equals(k)) s++;
                else if (KIND_FETCH.equals(k)) f++;
                else if (KIND_SEARCH.equals(k)) q++;
                else if (KIND_ERASE.equals(k)) x++;
                if (ok && (KIND_FETCH.equals(k) || KIND_SEARCH.equals(k))) {
                    String at = (String) e.get("at");
                    if (firstAccess == null) firstAccess = at;
                    lastAccess = at;
                }
            }
            counts.put("store", s); counts.put("fetch", f); counts.put("search", q); counts.put("erase", x);
            counts.put("total", (long) evs.size());
            r.put("counts", counts);
            r.put("last_access", lastAccess);
            storeCount += s; fetchCount += f; searchCount += q; eraseCount += x;

            JSONArray out = new JSONArray();
            int from = keepAllEvents ? 0 : Math.max(0, evs.size() - eventLimit);
            for (int i = from; i < evs.size(); i++) out.add(evs.get(i));
            r.put("events", out);
            r.put("events_truncated", from > 0);
        }

        JSONObject subject = new JSONObject();
        subject.put("principal_id", principalId);
        subject.put("mode", singleRecord ? "RECORD" : "PRINCIPAL");
        subject.put("note", singleRecord
                ? "This record was stored without a principal_id, so it cannot be tied to a person."
                : null);
        subject.put("erasure", register);
        subject.put("holds", principalId == null ? new JSONArray() : holds(conn, principalId));

        JSONArray erasureEvents = new JSONArray();
        erasureEvents.addAll(subjectEvents);
        subject.put("erasure_events", erasureEvents);

        long erased = 0;
        for (Object o : records) if ("ERASED".equals(((JSONObject) o).get("status"))) erased++;
        JSONObject summary = new JSONObject();
        summary.put("records", (long) records.size());
        summary.put("erased", erased);
        summary.put("held", (long) records.size() - erased);
        summary.put("store_events", storeCount);
        summary.put("fetch_events", fetchCount);
        summary.put("search_events", searchCount);
        summary.put("erase_events", eraseCount);

        JSONObject out = new JSONObject();
        out.put("success", true);
        out.put("subject", subject);
        out.put("summary", summary);
        out.put("records", records);
        out.put("_all_events", all); // internal: consumed by certificate(), removed before sending
        return out;
    }

    // ------------------------------------------------------------------ certificate data

    /**
     * Data for the principal custody certificate: the full lifecycle, the audit chain verified
     * from the earliest event involved to the current head, and a digest over the manifest that
     * binds each record and event (with its chain row hash) into one value.
     * Refuses (409) when the chain is broken or an event predates the chain.
     */
    public static JSONObject certificate(String principalId, String referenceKey) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = pool.getConnection();
        try {
            JSONObject c = build(conn, principalId, referenceKey, Integer.MAX_VALUE, true);
            @SuppressWarnings("unchecked")
            List<JSONObject> all = (List<JSONObject>) c.remove("_all_events");

            long minSeq = Long.MAX_VALUE;
            for (JSONObject e : all) {
                Object seq = e.get("chain_seq");
                if (seq == null) {
                    throw new CustodyException(409, "An audit event for this subject is not in the hash chain. "
                            + "Apply db/04_audit_chain.sql and retry.");
                }
                minSeq = Math.min(minSeq, ((Number) seq).longValue());
            }

            JSONObject chain = new JSONObject();
            if (all.isEmpty()) {
                chain.put("verified", false);
                chain.put("note", "No audit events exist for this subject.");
            } else {
                try (PreparedStatement ps = conn.prepareStatement(
                        "SELECT valid, first_bad_seq, reason, head_seq, head_hash FROM verify_event_log_chain(?)")) {
                    ps.setLong(1, minSeq);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) {
                            throw new CustodyException(409, "Audit chain verification returned no result, certificate not issued.");
                        }
                        if (!rs.getBoolean("valid")) {
                            throw new CustodyException(409, "Audit chain verification failed at sequence "
                                    + rs.getLong("first_bad_seq") + " (" + rs.getString("reason")
                                    + "), certificate not issued.");
                        }
                        chain.put("verified", true);
                        chain.put("from_seq", minSeq);
                        chain.put("head_seq", rs.getLong("head_seq"));
                        chain.put("head_hash", rs.getString("head_hash"));
                        chain.put("verified_at", ZonedDateTime.now(ZoneOffset.UTC).toString());
                    }
                }
            }
            c.put("chain", chain);
            c.put("manifest_sha256", manifestDigest(c));
            c.put("machine_id", ForensicEngine.getMachineIdentifier());
            c.put("software_version", "TSI_PRIVACY_VAULT_V" + BuildInfo.version());
            c.put("generated_at", ZonedDateTime.now(ZoneOffset.UTC).toString());
            return c;
        } finally {
            pool.cleanup(null, null, conn);
        }
    }

    /**
     * SHA-256 over a canonical line per record and per event. Event lines carry the chain row hash,
     * so the digest changes if any audit row it covers is altered.
     */
    static String manifestDigest(JSONObject c) throws Exception {
        StringBuilder sb = new StringBuilder();
        JSONObject subject = (JSONObject) c.get("subject");
        sb.append("S|").append(subject.get("mode")).append('|').append(subject.get("principal_id")).append('\n');
        for (Object o : (JSONArray) c.get("records")) {
            JSONObject r = (JSONObject) o;
            sb.append("R|").append(r.get("reference_key")).append('|').append(r.get("flavor")).append('|')
              .append(r.get("entity_code")).append('|').append(r.get("sha256")).append('|')
              .append(r.get("created_at")).append('|').append(r.get("erased_at")).append('\n');
            for (Object eo : (JSONArray) r.get("events")) {
                JSONObject e = (JSONObject) eo;
                sb.append("E|").append(e.get("log_id")).append('|').append(e.get("chain_seq")).append('|')
                  .append(e.get("row_hash")).append('|').append(e.get("kind")).append('|')
                  .append(e.get("outcome")).append('|').append(e.get("at")).append('\n');
            }
        }
        for (Object eo : (JSONArray) subject.get("erasure_events")) {
            JSONObject e = (JSONObject) eo;
            sb.append("X|").append(e.get("log_id")).append('|').append(e.get("chain_seq")).append('|')
              .append(e.get("row_hash")).append('|').append(e.get("outcome")).append('|').append(e.get("at")).append('\n');
        }
        byte[] d = MessageDigest.getInstance("SHA-256").digest(sb.toString().getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (byte b : d) hex.append(String.format("%02x", b));
        return hex.toString();
    }

    // ------------------------------------------------------------------ helpers

    private static JSONObject event(ResultSet rs) throws java.sql.SQLException {
        JSONObject e = new JSONObject();
        String op = rs.getString("operation_type");
        e.put("log_id", rs.getLong("log_id"));
        long seq = rs.getLong("chain_seq");
        e.put("chain_seq", rs.wasNull() ? null : (Object) seq);
        e.put("row_hash", rs.getString("row_hash"));
        e.put("who", rs.getString("who"));
        e.put("operation", op);
        e.put("kind", kind(op));
        e.put("outcome", rs.getString("outcome"));
        e.put("reason", rs.getString("failure_reason"));
        e.put("ip", rs.getString("client_ip"));
        e.put("machine_id", rs.getString("machine_id"));
        e.put("at", iso(rs.getTimestamp("log_datetime")));
        return e;
    }

    static String kind(String op) {
        if (op == null) return KIND_OTHER;
        if (op.startsWith("STORE")) return KIND_STORE;
        if (op.startsWith("FETCH")) return KIND_FETCH;
        if (op.startsWith("SEARCH")) return KIND_SEARCH;
        if (op.startsWith("ERASURE_")) return KIND_ERASE;
        return KIND_OTHER;
    }

    private static String iso(Timestamp t) {
        return t == null ? null : t.toInstant().toString();
    }

    private static String principalOfRecord(Connection conn, UUID ref) throws java.sql.SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT principal_id FROM vault_entities WHERE entity_ref = ?")) {
            ps.setObject(1, ref);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    private static boolean recordExists(Connection conn, UUID ref) throws java.sql.SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT 1 FROM vault_entities WHERE entity_ref = ?")) {
            ps.setObject(1, ref);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private static JSONObject registerRow(Connection conn, String principalId) throws java.sql.SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT state, requested_by, requested_at, shredded_at, records_destroyed, records_retained, next_due " +
                "FROM principal_erasures WHERE principal_id = ?")) {
            ps.setString(1, principalId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                JSONObject r = new JSONObject();
                r.put("state", rs.getString("state"));
                r.put("requested_by", rs.getString("requested_by"));
                r.put("requested_at", iso(rs.getTimestamp("requested_at")));
                r.put("shredded_at", iso(rs.getTimestamp("shredded_at")));
                r.put("records_destroyed", rs.getLong("records_destroyed"));
                r.put("records_retained", rs.getLong("records_retained"));
                r.put("next_due", iso(rs.getTimestamp("next_due")));
                return r;
            }
        } catch (java.sql.SQLException e) {
            // principal_erasures is absent until db/03_erasure.sql has been applied
            return null;
        }
    }

    private static JSONArray holds(Connection conn, String principalId) {
        JSONArray out = new JSONArray();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT hold_id, reason, case_ref, placed_by, placed_at, released_at, released_by " +
                "FROM legal_holds WHERE principal_id = ? ORDER BY placed_at ASC")) {
            ps.setString(1, principalId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    JSONObject h = new JSONObject();
                    h.put("hold_id", rs.getLong("hold_id"));
                    h.put("reason", rs.getString("reason"));
                    h.put("case_ref", rs.getString("case_ref"));
                    h.put("placed_by", rs.getString("placed_by"));
                    h.put("placed_at", iso(rs.getTimestamp("placed_at")));
                    h.put("released_at", iso(rs.getTimestamp("released_at")));
                    h.put("released_by", rs.getString("released_by"));
                    out.add(h);
                }
            }
        } catch (java.sql.SQLException e) {
            // legal_holds is absent until db/03_erasure.sql has been applied
        }
        return out;
    }
}
