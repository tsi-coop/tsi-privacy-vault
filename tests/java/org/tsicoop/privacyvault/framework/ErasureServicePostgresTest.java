package org.tsicoop.privacyvault.framework;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Erasure semantics against a real PostgreSQL with db/00..03 applied.
 * Skipped unless TSI_TEST_PG_URL is set; tests/runners/run-erasure-tests.sh sets it up.
 * Records are inserted directly, so no key anchor is needed: the assertions are about
 * what is left in the row once its key is destroyed.
 */
public class ErasureServicePostgresTest {

    private static final String ACTOR = "test-admin@example.com";
    private Connection db;

    @Before
    public void setUp() throws Exception {
        String url = System.getenv("TSI_TEST_PG_URL");
        assumeTrue("TSI_TEST_PG_URL not set; skipping PostgreSQL erasure tests", url != null && !url.isEmpty());
        System.setProperty("tsi.test", "1");
        db = DriverManager.getConnection(url, System.getenv("TSI_TEST_PG_USER"), System.getenv("TSI_TEST_PG_PASSWORD"));
        db.setAutoCommit(true);
        // event_log is append-only (db/04_audit_chain.sql); switch its guards off for the reset only.
        exec("ALTER TABLE event_log DISABLE TRIGGER USER");
        exec("TRUNCATE vault_search_index, vault_entities, principal_erasures, legal_holds, event_log RESTART IDENTITY CASCADE");
        exec("ALTER TABLE event_log ENABLE TRIGGER USER");
        // PoolDB reads these through SystemConfig, built from POSTGRES_* in the environment.
        SystemConfig.loadAppConfig(null);
    }

    @After
    public void tearDown() throws Exception {
        if (db != null) db.close();
    }

    // ---- fixtures ----------------------------------------------------------------------

    private void exec(String sql, Object... args) throws Exception {
        try (PreparedStatement ps = db.prepareStatement(sql)) {
            for (int i = 0; i < args.length; i++) ps.setObject(i + 1, args[i]);
            ps.execute();
        }
    }

    private long count(String sql, Object... args) throws Exception {
        try (PreparedStatement ps = db.prepareStatement(sql)) {
            for (int i = 0; i < args.length; i++) ps.setObject(i + 1, args[i]);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getLong(1);
            }
        }
    }

    /** until: SQL interval relative to now, e.g. "-1 day" or "30 days"; null = erasable now. */
    private UUID record(String principal, String code, String until, String backend, String storageKey) throws Exception {
        UUID ref = UUID.randomUUID();
        exec("INSERT INTO vault_entities (entity_ref, entity_type, id_type_code, file_name, encrypted_content, encrypted_data_key, " +
                "hashed_value_sha256, key_version, payload_cipher, principal_id, retain_until, " +
                "storage_backend, storage_key, content_sha256) VALUES (?, 'ID', ?, 'scan.pdf', 'CIPHERTEXT', 'WRAPPED-DEK', ?, 1, 'AES_GCM', ?, " +
                (until == null ? "NULL" : "now() + ?::interval") + ", ?, ?, ?)",
                buildArgs(ref, code, "a".repeat(64), principal, until, backend, storageKey, storageKey == null ? null : "b".repeat(64)));
        exec("INSERT INTO vault_search_index (index_hash, entity_ref, attribute_type) VALUES (?, ?, 'FULL')", "c".repeat(64), ref);
        return ref;
    }

    private static Object[] buildArgs(Object ref, String code, String hash, String principal, String until,
                                      String backend, String key, String contentHash) {
        List<Object> a = new ArrayList<>(Arrays.asList(ref, code, hash, principal));
        if (until != null) a.add(until);
        a.addAll(Arrays.asList(backend, key, contentHash));
        return a.toArray();
    }

    private UUID erasable(String principal, String code) throws Exception {
        return record(principal, code, null, "DATABASE", null);
    }

    private Map<String, Object> row(UUID ref) throws Exception {
        try (PreparedStatement ps = db.prepareStatement("SELECT * FROM vault_entities WHERE entity_ref = ?")) {
            ps.setObject(1, ref);
            try (ResultSet rs = ps.executeQuery()) {
                assertTrue("row must still exist", rs.next());
                Map<String, Object> m = new HashMap<>();
                for (int i = 1; i <= rs.getMetaData().getColumnCount(); i++) {
                    m.put(rs.getMetaData().getColumnName(i), rs.getObject(i));
                }
                return m;
            }
        }
    }

    private void assertDestroyed(UUID ref) throws Exception {
        Map<String, Object> r = row(ref);
        assertNotNull("erased_at", r.get("erased_at"));
        assertNull("wrapped DEK", r.get("encrypted_data_key"));
        assertNull("ciphertext", r.get("encrypted_content"));
        assertNull("plaintext hash", r.get("hashed_value_sha256"));
        assertNull("file name", r.get("file_name"));
        assertEquals("blind index entries", 0, count("SELECT count(*) FROM vault_search_index WHERE entity_ref = ?", ref));
    }

    private void assertIntact(UUID ref) throws Exception {
        Map<String, Object> r = row(ref);
        assertNull("erased_at", r.get("erased_at"));
        assertEquals("WRAPPED-DEK", r.get("encrypted_data_key"));
        assertEquals("CIPHERTEXT", r.get("encrypted_content"));
        assertEquals(1, count("SELECT count(*) FROM vault_search_index WHERE entity_ref = ?", ref));
    }

    private static String state(ErasureService.Outcome o) {
        return (String) o.body.get("state");
    }

    private String registerState(String principal) throws Exception {
        try (PreparedStatement ps = db.prepareStatement("SELECT state FROM principal_erasures WHERE principal_id = ?")) {
            ps.setString(1, principal);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    // ---- shred --------------------------------------------------------------------------

    @Test
    public void shredDestroysEveryRecordOfPrincipalAndLeavesOthersUntouched() throws Exception {
        UUID a1 = erasable("P1", "PAN");
        UUID a2 = erasable("P1", "ADDRESS");
        UUID other = erasable("P2", "PAN");
        UUID unlinked = erasable(null, "PAN");

        ErasureService.Outcome o = ErasureService.shredPrincipal("P1", ACTOR, "127.0.0.1", "test");

        assertEquals(200, o.status);
        assertEquals("SHREDDED", state(o));
        assertEquals(2L, o.body.get("records_destroyed"));
        assertEquals(0L, o.body.get("records_retained"));
        assertDestroyed(a1);
        assertDestroyed(a2);
        assertIntact(other);
        assertIntact(unlinked);
        assertEquals("SHREDDED", registerState("P1"));
        assertNull(registerState("P2"));
        assertNotNull(row(a1).get("created_at")); // the row and its reference key remain
    }

    @Test
    public void shredIsIdempotent() throws Exception {
        UUID r = erasable("P1", "PAN");
        ErasureService.shredPrincipal("P1", ACTOR, "127.0.0.1", "test");
        ErasureService.Outcome again = ErasureService.shredPrincipal("P1", ACTOR, "127.0.0.1", "test");
        assertEquals(200, again.status);
        assertEquals("SHREDDED", state(again));
        assertDestroyed(r);
    }

    @Test
    public void shredOfUnknownPrincipalStillBlocksFutureStores() throws Exception {
        ErasureService.Outcome o = ErasureService.shredPrincipal("GHOST", ACTOR, "127.0.0.1", "test");
        assertEquals("SHREDDED", state(o));
        try (Connection c = new PoolDB().getConnection()) {
            assertTrue(ErasureService.isPrincipalErased(c, "GHOST"));
            assertFalse(ErasureService.isPrincipalErased(c, "SOMEONE-ELSE"));
        }
    }

    // ---- retention ----------------------------------------------------------------------

    @Test
    public void retainedRecordsSurviveAndEntryIsPartial() throws Exception {
        UUID gone = erasable("P1", "MARKETING");
        UUID kept = record("P1", "KYC", "30 days", "DATABASE", null);
        UUID expired = record("P1", "KYC", "-1 day", "DATABASE", null);

        ErasureService.Outcome o = ErasureService.shredPrincipal("P1", ACTOR, "127.0.0.1", "test");

        assertEquals("PARTIAL", state(o));
        assertEquals(2L, o.body.get("records_destroyed"));
        assertEquals(1L, o.body.get("records_retained"));
        assertNotNull("next_due is the earliest retain_until", o.body.get("next_due"));
        assertDestroyed(gone);
        assertDestroyed(expired);
        assertIntact(kept);
    }

    @Test
    public void jobShredsOnceTheHoldPeriodPasses() throws Exception {
        UUID kept = record("P1", "KYC", "30 days", "DATABASE", null);
        ErasureService.shredPrincipal("P1", ACTOR, "127.0.0.1", "test");
        assertEquals(0, ErasureService.runDue().get("principals_shredded"));
        assertIntact(kept);

        // Thirty days later
        exec("UPDATE vault_entities SET retain_until = now() - interval '1 minute' WHERE entity_ref = ?", kept);
        exec("UPDATE principal_erasures SET next_due = now() - interval '1 minute' WHERE principal_id = 'P1'");

        assertEquals(1, ErasureService.runDue().get("principals_shredded"));
        assertDestroyed(kept);
        assertEquals("SHREDDED", registerState("P1"));
    }

    @Test
    public void nextDueIsTheEarliestRetainUntil() throws Exception {
        record("P1", "KYC", "90 days", "DATABASE", null);
        record("P1", "LOAN", "10 days", "DATABASE", null);
        ErasureService.Outcome o = ErasureService.shredPrincipal("P1", ACTOR, "127.0.0.1", "test");
        assertEquals("PARTIAL", state(o));
        assertEquals(2L, o.body.get("records_retained"));
        assertEquals(1, count("SELECT count(*) FROM principal_erasures WHERE principal_id = 'P1' " +
                "AND next_due BETWEEN now() + interval '9 days' AND now() + interval '11 days'"));
    }

    // ---- holds --------------------------------------------------------------------------

    @Test
    public void openHoldRefusesShredAndTouchesNothing() throws Exception {
        UUID r = erasable("P1", "PAN");
        ErasureService.placeHold("P1", "litigation", "CASE-1", ACTOR, "127.0.0.1", "test");

        ErasureService.Outcome o = ErasureService.shredPrincipal("P1", ACTOR, "127.0.0.1", "test");

        assertEquals(409, o.status);
        assertIntact(r);
        assertNull("no register entry on a refused request", registerState("P1"));
        assertEquals(1, count("SELECT count(*) FROM event_log WHERE operation_type LIKE 'ERASURE_SHRED:P1%' AND outcome = 'DENIED'"));
    }

    @Test
    public void shredWorksAfterHoldIsReleased() throws Exception {
        UUID r = erasable("P1", "PAN");
        ErasureService.Outcome placed = ErasureService.placeHold("P1", "litigation", null, ACTOR, "127.0.0.1", "test");
        int id = (Integer) placed.body.get("hold_id");
        assertEquals(200, ErasureService.releaseHold(id, ACTOR, "127.0.0.1", "test").status);
        assertEquals(404, ErasureService.releaseHold(id, ACTOR, "127.0.0.1", "test").status);
        assertEquals("SHREDDED", state(ErasureService.shredPrincipal("P1", ACTOR, "127.0.0.1", "test")));
        assertDestroyed(r);
    }

    @Test
    public void holdPlacedWhilePartialStopsTheScheduledShred() throws Exception {
        UUID due = record("P1", "KYC", "-1 day", "DATABASE", null);
        // A PARTIAL entry whose record only just became erasable
        exec("UPDATE vault_entities SET retain_until = now() + interval '1 hour' WHERE entity_ref = ?", due);
        ErasureService.shredPrincipal("P1", ACTOR, "127.0.0.1", "test");
        exec("UPDATE vault_entities SET retain_until = now() - interval '1 minute' WHERE entity_ref = ?", due);
        exec("UPDATE principal_erasures SET next_due = now() - interval '1 minute' WHERE principal_id = 'P1'");

        ErasureService.Outcome hold = ErasureService.placeHold("P1", "audit", null, ACTOR, "127.0.0.1", "test");
        JSONObject skipped = ErasureService.runDue();
        assertEquals(0, skipped.get("principals_shredded"));
        assertEquals(1, skipped.get("principals_held"));
        assertIntact(due);

        ErasureService.releaseHold((Integer) hold.body.get("hold_id"), ACTOR, "127.0.0.1", "test");
        assertEquals(1, ErasureService.runDue().get("principals_shredded"));
        assertDestroyed(due);
    }

    // ---- single record ------------------------------------------------------------------

    @Test
    public void shredRecordHonoursRetention() throws Exception {
        UUID kept = record(null, "KYC", "30 days", "DATABASE", null);
        UUID free = erasable(null, "PAN");

        assertEquals(409, ErasureService.shredRecord(kept.toString(), ACTOR, "127.0.0.1", "test").status);
        assertIntact(kept);

        assertEquals(200, ErasureService.shredRecord(free.toString(), ACTOR, "127.0.0.1", "test").status);
        assertDestroyed(free);
        assertEquals(Boolean.TRUE, ErasureService.shredRecord(free.toString(), ACTOR, "127.0.0.1", "test").body.get("already_erased"));
        assertEquals(404, ErasureService.shredRecord(UUID.randomUUID().toString(), ACTOR, "127.0.0.1", "test").status);
    }

    // ---- resumability -------------------------------------------------------------------

    @Test
    public void interruptedShredResumesFromTheQueue() throws Exception {
        UUID a = erasable("P1", "PAN");
        UUID b = erasable("P1", "ADDRESS");
        // Crash after the register entry and the condemn step, before any key was destroyed.
        exec("INSERT INTO principal_erasures (principal_id, state, requested_by) VALUES ('P1', 'SHREDDING', ?)", ACTOR);
        exec("UPDATE vault_entities SET erased_at = now() WHERE principal_id = 'P1'");
        assertEquals("WRAPPED-DEK", row(a).get("encrypted_data_key"));

        JSONObject r = ErasureService.runDue();

        assertEquals(1, r.get("principals_resumed"));
        assertDestroyed(a);
        assertDestroyed(b);
        assertEquals("SHREDDED", registerState("P1"));
    }

    // ---- external objects ---------------------------------------------------------------

    /** In-memory store whose delete can be made to fail. */
    private static class FakeStore implements FileStore {
        final Map<String, byte[]> objects = new HashMap<>();
        boolean failDeletes;

        public String backendName() { return "FAKE_S3"; }
        public void put(String key, byte[] c) { objects.put(key, c); }
        public byte[] get(String key) { return objects.get(key); }
        public boolean exists(String key) { return objects.containsKey(key); }
        public void health() { }
        public void delete(String key) {
            if (failDeletes) throw new IllegalStateException("backend down");
            objects.remove(key);
        }
    }

    @Test
    public void keyIsDestroyedEvenWhenObjectDeleteFailsAndObjectIsRetried() throws Exception {
        FakeStore store = new FakeStore();
        FileStoreFactory.registerForTesting("FAKE_S3", store);
        String key = UUID.randomUUID().toString();
        store.put(key, new byte[]{1, 2, 3});
        UUID ref = record("P1", "SCAN", null, "FAKE_S3", key);

        store.failDeletes = true;
        ErasureService.Outcome first = ErasureService.shredPrincipal("P1", ACTOR, "127.0.0.1", "test");

        // The key is already gone, so the object is unreadable ciphertext, but the job is not finished.
        assertNull(row(ref).get("encrypted_data_key"));
        assertEquals(key, row(ref).get("storage_key"));
        assertTrue(store.exists(key));
        assertEquals("SHREDDING", state(first));

        store.failDeletes = false;
        ErasureService.runDue();

        assertFalse(store.exists(key));
        assertNull(row(ref).get("storage_key"));
        assertEquals("SHREDDED", registerState("P1"));
    }

    // ---- register and certificate -------------------------------------------------------

    @Test
    public void certificateListsDestroyedAndRetainedWithReasons() throws Exception {
        UUID gone = erasable("P1", "MARKETING");
        UUID dated = record("P1", "KYC", "30 days", "DATABASE", null);
        ErasureService.shredPrincipal("P1", ACTOR, "127.0.0.1", "test");

        ErasureService.Outcome c = ErasureService.certificate("P1");

        assertEquals(200, c.status);
        JSONArray destroyed = (JSONArray) c.body.get("destroyed");
        JSONArray retained = (JSONArray) c.body.get("retained");
        assertEquals(1, destroyed.size());
        assertEquals(gone.toString(), ((JSONObject) destroyed.get(0)).get("reference_key"));
        assertEquals(Boolean.TRUE, ((JSONObject) destroyed.get(0)).get("key_destroyed"));
        assertEquals(1, retained.size());
        assertEquals(dated.toString(), ((JSONObject) retained.get(0)).get("reference_key"));
        assertNotNull(((JSONObject) retained.get(0)).get("retain_until"));
        assertEquals(404, ErasureService.certificate("NOPE").status);
    }

    @Test
    public void registerListsEntriesAndFiltersByState() throws Exception {
        erasable("DONE", "PAN");
        record("HALF", "KYC", "30 days", "DATABASE", null);
        ErasureService.shredPrincipal("DONE", ACTOR, "127.0.0.1", "test");
        ErasureService.shredPrincipal("HALF", ACTOR, "127.0.0.1", "test");

        assertEquals(2, ErasureService.register(null).size());
        JSONArray partial = ErasureService.register("PARTIAL");
        assertEquals(1, partial.size());
        assertEquals("HALF", ((JSONObject) partial.get(0)).get("principal_id"));
    }

    @Test
    public void everyOutcomeIsWrittenToEventLog() throws Exception {
        erasable("P1", "PAN");
        ErasureService.shredPrincipal("P1", ACTOR, "127.0.0.1", "test");
        assertTrue(count("SELECT count(*) FROM event_log WHERE operation_type LIKE 'ERASURE_SHRED:P1%' AND outcome = 'SUCCESS'") >= 1);
        assertTrue(count("SELECT count(*) FROM event_log WHERE operation_type LIKE 'ERASURE_RESULT:P1:SHREDDED%'") >= 1);
    }
}
