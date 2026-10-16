package org.tsicoop.privacyvault.framework;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

/** Needs PostgreSQL with db/*.sql applied; skipped when TSI_TEST_PG_URL is unset. */
public class AuditChainPostgresTest {

    private Connection db;

    @Before
    public void setUp() throws Exception {
        String url = System.getenv("TSI_TEST_PG_URL");
        assumeTrue("TSI_TEST_PG_URL not set; skipping audit chain tests", url != null && !url.isEmpty());
        db = DriverManager.getConnection(url, System.getenv("TSI_TEST_PG_USER"), System.getenv("TSI_TEST_PG_PASSWORD"));
        db.setAutoCommit(true);
        exec("ALTER TABLE event_log DISABLE TRIGGER USER");
        exec("TRUNCATE event_log RESTART IDENTITY");
        exec("ALTER TABLE event_log ENABLE TRIGGER USER");
    }

    @After
    public void tearDown() throws Exception {
        if (db != null) db.close();
    }

    private void exec(String sql) throws Exception {
        try (PreparedStatement ps = db.prepareStatement(sql)) { ps.execute(); }
    }

    private void log(String op) throws Exception {
        try (PreparedStatement ps = db.prepareStatement(
                "INSERT INTO event_log (who, operation_type, client_ip, outcome) VALUES ('t', ?, '127.0.0.1', 'SUCCESS')")) {
            ps.setString(1, op);
            ps.executeUpdate();
        }
    }

    private void seed(int n) throws Exception {
        for (int i = 0; i < n; i++) log("OP" + i);
    }

    /** Returns {valid, first_bad_seq, rows_checked}. */
    private Object[] verify() throws Exception {
        try (PreparedStatement ps = db.prepareStatement("SELECT valid, first_bad_seq, rows_checked FROM verify_event_log_chain()");
             ResultSet rs = ps.executeQuery()) {
            assertTrue(rs.next());
            long bad = rs.getLong(2);
            return new Object[]{rs.getBoolean(1), rs.wasNull() ? null : bad, rs.getLong(3)};
        }
    }

    private void asOwner(String sql) throws Exception {
        exec("ALTER TABLE event_log DISABLE TRIGGER USER");
        try { exec(sql); } finally { exec("ALTER TABLE event_log ENABLE TRIGGER USER"); }
    }

    @Test
    public void untouchedChainVerifies() throws Exception {
        seed(5);
        Object[] r = verify();
        assertEquals(true, r[0]);
        assertEquals(5L, r[2]);
    }

    @Test
    public void emptyLogIsValid() throws Exception {
        assertEquals(true, verify()[0]);
    }

    @Test
    public void editedRowIsDetected() throws Exception {
        seed(5);
        asOwner("UPDATE event_log SET outcome = 'DENIED' WHERE chain_seq = 3");
        Object[] r = verify();
        assertEquals(false, r[0]);
        assertEquals(3L, r[1]);
    }

    @Test
    public void deletedRowIsDetected() throws Exception {
        seed(5);
        asOwner("DELETE FROM event_log WHERE chain_seq = 3");
        Object[] r = verify();
        assertEquals(false, r[0]);
        assertEquals(3L, r[1]);
    }

    @Test
    public void rewrittenRowWithRecomputedOwnHashStillBreaksNextLink() throws Exception {
        seed(5);
        asOwner("UPDATE event_log e SET outcome = 'ERROR', "
                + "row_hash = event_log_compute_hash(e.prev_hash, ROW(e.log_id, e.who, e.operation_type, e.entity_code, e.entity_ref, e.utility_ref, "
                + "e.client_ip, e.user_agent, e.machine_id, 'ERROR', e.failure_reason, e.log_datetime, e.chain_seq, e.prev_hash, e.row_hash)::event_log) "
                + "WHERE chain_seq = 2");
        Object[] r = verify();
        assertEquals(false, r[0]);
    }

    @Test
    public void rowsWrittenWithTriggerBypassedAreDetected() throws Exception {
        seed(2);
        asOwner("INSERT INTO event_log (who, operation_type, client_ip) VALUES ('x', 'FORGED', '1.1.1.1')");
        assertEquals(false, verify()[0]);
    }

    @Test
    public void updateAndDeleteAreBlocked() throws Exception {
        seed(2);
        try {
            exec("UPDATE event_log SET outcome = 'DENIED'");
            fail("UPDATE should be blocked");
        } catch (java.sql.SQLException expected) {
            assertTrue(expected.getMessage().contains("append-only"));
        }
        try {
            exec("DELETE FROM event_log");
            fail("DELETE should be blocked");
        } catch (java.sql.SQLException expected) {
            assertTrue(expected.getMessage().contains("append-only"));
        }
        try {
            exec("TRUNCATE event_log");
            fail("TRUNCATE should be blocked");
        } catch (java.sql.SQLException expected) {
            assertTrue(expected.getMessage().contains("append-only"));
        }
    }

    @Test
    public void concurrentWritersDoNotForkTheChain() throws Exception {
        String url = System.getenv("TSI_TEST_PG_URL");
        Thread[] ts = new Thread[8];
        for (int t = 0; t < ts.length; t++) {
            ts[t] = new Thread(() -> {
                try (Connection c = DriverManager.getConnection(url, System.getenv("TSI_TEST_PG_USER"), System.getenv("TSI_TEST_PG_PASSWORD"))) {
                    for (int i = 0; i < 25; i++) {
                        try (PreparedStatement ps = c.prepareStatement(
                                "INSERT INTO event_log (who, operation_type, client_ip) VALUES ('c', 'CONC', '127.0.0.1')")) {
                            ps.executeUpdate();
                        }
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            ts[t].start();
        }
        for (Thread t : ts) t.join();
        Object[] r = verify();
        assertEquals(true, r[0]);
        assertEquals(200L, r[2]);
    }

    @Test
    public void headReportedForExternalAnchoring() throws Exception {
        seed(3);
        try (PreparedStatement ps = db.prepareStatement("SELECT head_seq, head_hash FROM verify_event_log_chain()");
             ResultSet rs = ps.executeQuery()) {
            assertTrue(rs.next());
            assertEquals(3L, rs.getLong(1));
            assertNotNull(rs.getString(2));
            assertFalse(rs.getString(2).isEmpty());
        }
    }
}
