package org.tsicoop.privacyvault.framework;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.util.UUID;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Custody lifecycle and certificate data against a real PostgreSQL with db/00..04 applied.
 * Skipped unless TSI_TEST_PG_URL is set; run with
 * TEST_CLASS=CustodyServicePostgresTest tests/runners/run-erasure-tests.sh.
 */
public class CustodyServicePostgresTest {

    private Connection db;

    @Before
    public void setUp() throws Exception {
        String url = System.getenv("TSI_TEST_PG_URL");
        assumeTrue("TSI_TEST_PG_URL not set; skipping PostgreSQL custody tests", url != null && !url.isEmpty());
        System.setProperty("tsi.test", "1");
        db = DriverManager.getConnection(url, System.getenv("TSI_TEST_PG_USER"), System.getenv("TSI_TEST_PG_PASSWORD"));
        db.setAutoCommit(true);
        exec("ALTER TABLE event_log DISABLE TRIGGER USER");
        exec("TRUNCATE vault_search_index, vault_entities, principal_erasures, legal_holds, event_log RESTART IDENTITY CASCADE");
        exec("ALTER TABLE event_log ENABLE TRIGGER USER");
        SystemConfig.loadAppConfig(null);
    }

    @After
    public void tearDown() throws Exception {
        if (db != null) db.close();
    }

    private void exec(String sql, Object... args) throws Exception {
        try (PreparedStatement ps = db.prepareStatement(sql)) {
            for (int i = 0; i < args.length; i++) ps.setObject(i + 1, args[i]);
            ps.execute();
        }
    }

    private UUID record(String principal) throws Exception {
        UUID ref = UUID.randomUUID();
        exec("INSERT INTO vault_entities (entity_ref, entity_type, id_type_code, encrypted_content, encrypted_data_key, " +
                "hashed_value_sha256, key_version, payload_cipher, principal_id) VALUES (?, 'ID', 'AADHAAR', 'CT', 'DEK', ?, 1, 'AES_GCM', ?)",
                ref, "a".repeat(64), principal);
        return ref;
    }

    private void event(String op, UUID ref, String outcome) throws Exception {
        exec("INSERT INTO event_log (who, operation_type, entity_ref, client_ip, machine_id, outcome) VALUES ('VAULT:k1', ?, ?, '127.0.0.1', 'NODE:T', ?)",
                op, ref, outcome);
    }

    @Test
    public void lifecycleIsGroupedByRecordAndKind() throws Exception {
        UUID a = record("P1");
        UUID b = record("P1");
        UUID other = record("P2");
        event("STORE:ID:AADHAAR:" + a, a, "SUCCESS");
        event("FETCH:ID:AADHAAR:" + a, a, "SUCCESS");
        event("SEARCH:ID:AADHAAR:" + a, a, "SUCCESS");
        event("STORE:ID:AADHAAR:" + b, b, "SUCCESS");
        event("FETCH:" + other, other, "SUCCESS");

        JSONObject c = CustodyService.build("P1", null, 100);
        JSONObject sum = (JSONObject) c.get("summary");
        assertEquals(2L, sum.get("records"));
        assertEquals(2L, sum.get("store_events"));
        assertEquals(1L, sum.get("fetch_events"));
        assertEquals(1L, sum.get("search_events"));
        assertFalse("internal field must not leak", c.containsKey("_all_events"));
        JSONObject first = (JSONObject) ((JSONArray) c.get("records")).get(0);
        assertEquals(a.toString(), first.get("reference_key"));
        assertEquals(3, ((JSONArray) first.get("events")).size());
    }

    @Test
    public void referenceKeyOpensTheWholePrincipal() throws Exception {
        UUID a = record("P1");
        record("P1");
        JSONObject c = CustodyService.build(null, a.toString(), 100);
        assertEquals("PRINCIPAL", ((JSONObject) c.get("subject")).get("mode"));
        assertEquals(2L, ((JSONObject) c.get("summary")).get("records"));
    }

    @Test
    public void recordWithoutPrincipalIsFoundByReferenceOnly() throws Exception {
        UUID a = record(null);
        JSONObject c = CustodyService.build(null, a.toString(), 100);
        JSONObject subject = (JSONObject) c.get("subject");
        assertEquals("RECORD", subject.get("mode"));
        assertNotNull(subject.get("note"));
    }

    @Test
    public void unknownSubjectsAreNotFound() throws Exception {
        try {
            CustodyService.build("NOBODY", null, 10);
            org.junit.Assert.fail("expected 404");
        } catch (CustodyService.CustodyException e) {
            assertEquals(404, e.status);
        }
        try {
            CustodyService.build(null, "not-a-uuid", 10);
            org.junit.Assert.fail("expected 400");
        } catch (CustodyService.CustodyException e) {
            assertEquals(400, e.status);
        }
    }

    @Test
    public void erasedRecordsShowAnEraseEventAndNoHashInTheLifecycle() throws Exception {
        UUID a = record("P1");
        event("STORE:ID:AADHAAR:" + a, a, "SUCCESS");
        exec("INSERT INTO principal_erasures (principal_id, state, requested_by) VALUES ('P1', 'SHREDDED', 'admin@example.com')");
        exec("UPDATE vault_entities SET erased_at = now(), encrypted_data_key = NULL, encrypted_content = NULL, hashed_value_sha256 = NULL WHERE entity_ref = ?", a);
        exec("INSERT INTO event_log (who, operation_type, client_ip, machine_id, outcome) VALUES ('ADMIN:admin@example.com', 'ERASURE_SHRED:P1:condemned=1', '127.0.0.1', 'NODE:T', 'SUCCESS')");

        JSONObject c = CustodyService.build("P1", null, 100);
        JSONObject rec = (JSONObject) ((JSONArray) c.get("records")).get(0);
        assertEquals("ERASED", rec.get("status"));
        assertNull(rec.get("sha256"));
        JSONArray evs = (JSONArray) rec.get("events");
        JSONObject last = (JSONObject) evs.get(evs.size() - 1);
        assertEquals("ERASE", last.get("kind"));
        assertEquals("admin@example.com", last.get("who"));
        assertEquals(1, ((JSONArray) ((JSONObject) c.get("subject")).get("erasure_events")).size());
    }

    @Test
    public void principalPrefixCollisionDoesNotLeakOtherErasureEvents() throws Exception {
        record("ABC");
        record("ABCD");
        exec("INSERT INTO event_log (who, operation_type, client_ip, machine_id, outcome) VALUES ('ADMIN:x', 'ERASURE_SHRED:ABCD:condemned=1', '127.0.0.1', 'NODE:T', 'SUCCESS')");
        JSONObject c = CustodyService.build("ABC", null, 10);
        assertEquals(0, ((JSONArray) ((JSONObject) c.get("subject")).get("erasure_events")).size());
    }

    @Test
    public void certificateVerifiesTheChainAndIsDeterministic() throws Exception {
        UUID a = record("P1");
        event("STORE:ID:AADHAAR:" + a, a, "SUCCESS");
        event("FETCH:ID:AADHAAR:" + a, a, "SUCCESS");

        JSONObject c1 = CustodyService.certificate("P1", null);
        JSONObject chain = (JSONObject) c1.get("chain");
        assertEquals(Boolean.TRUE, chain.get("verified"));
        String d1 = (String) c1.get("manifest_sha256");
        assertEquals(64, d1.length());
        assertEquals(d1, CustodyService.certificate("P1", null).get("manifest_sha256"));

        event("FETCH:ID:AADHAAR:" + a, a, "SUCCESS");
        assertTrue("a new event changes the digest",
                !d1.equals(CustodyService.certificate("P1", null).get("manifest_sha256")));

        ByteArrayOutputStream pdf = new ByteArrayOutputStream();
        new BSACertificateGenerator().streamCustodyCertificate(c1, pdf);
        assertTrue(pdf.size() > 1000);
        assertEquals("%PDF", new String(pdf.toByteArray(), 0, 4, "US-ASCII"));
    }

    @Test
    public void certificateIsRefusedWhenTheChainIsBroken() throws Exception {
        UUID a = record("P1");
        event("STORE:ID:AADHAAR:" + a, a, "SUCCESS");
        event("FETCH:ID:AADHAAR:" + a, a, "SUCCESS");
        // Tamper with an audited field, bypassing the append-only guard for the test only.
        exec("ALTER TABLE event_log DISABLE TRIGGER USER");
        exec("UPDATE event_log SET outcome = 'ERROR' WHERE operation_type LIKE 'STORE:%'");
        exec("ALTER TABLE event_log ENABLE TRIGGER USER");
        try {
            CustodyService.certificate("P1", null);
            org.junit.Assert.fail("expected 409");
        } catch (CustodyService.CustodyException e) {
            assertEquals(409, e.status);
        }
    }
}
