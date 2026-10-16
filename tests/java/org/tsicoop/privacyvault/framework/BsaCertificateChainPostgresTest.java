package org.tsicoop.privacyvault.framework;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.tsicoop.privacyvault.api.admin.Legal;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

/** Needs PostgreSQL with db/*.sql applied; skipped when TSI_TEST_PG_URL is unset. */
public class BsaCertificateChainPostgresTest {

    private Connection db;
    private int status;
    private ByteArrayOutputStream body;

    @Before
    public void setUp() throws Exception {
        String url = System.getenv("TSI_TEST_PG_URL");
        assumeTrue("TSI_TEST_PG_URL not set; skipping certificate chain tests", url != null && !url.isEmpty());
        System.setProperty("tsi.test", "1");
        db = DriverManager.getConnection(url, System.getenv("TSI_TEST_PG_USER"), System.getenv("TSI_TEST_PG_PASSWORD"));
        db.setAutoCommit(true);
        exec("ALTER TABLE event_log DISABLE TRIGGER USER");
        exec("TRUNCATE vault_search_index, vault_entities, event_log RESTART IDENTITY CASCADE");
        exec("ALTER TABLE event_log ENABLE TRIGGER USER");
        SystemConfig.loadAppConfig(null);
        status = 200;
        body = new ByteArrayOutputStream();
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

    private UUID storedRecord() throws Exception {
        UUID ref = UUID.randomUUID();
        exec("INSERT INTO vault_entities (entity_ref, entity_type, id_type_code, encrypted_content, encrypted_data_key, "
                + "hashed_value_sha256, key_version, payload_cipher) VALUES (?, 'ID', 'PAN', 'C', 'K', ?, 1, 'AES_GCM')",
                ref, "a".repeat(64));
        // a later fetch first, then the store: the certificate must still cite the store
        exec("INSERT INTO event_log (who, operation_type, client_ip, machine_id, outcome, entity_ref) "
                + "VALUES ('VAULT:k', 'FETCH:PAN', '127.0.0.1', 'M1', 'SUCCESS', ?)", ref);
        exec("INSERT INTO event_log (who, operation_type, client_ip, machine_id, outcome, entity_ref, log_datetime) "
                + "VALUES ('VAULT:k', 'STORE:ID:PAN:x', '127.0.0.1', 'M1', 'SUCCESS', ?, now() - interval '1 hour')", ref);
        exec("INSERT INTO event_log (who, operation_type, client_ip, outcome) VALUES ('t', 'LATER', '127.0.0.1', 'SUCCESS')");
        return ref;
    }

    private void issue(UUID ref) throws Exception {
        HttpServletRequest req = (HttpServletRequest) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class[]{HttpServletRequest.class}, (p, m, a) -> {
                    if (m.getName().equals("getAttribute") && InputProcessor.REQUEST_DATA.equals(a[0])) {
                        return "{\"_func\":\"generate_entity_bsa_certificate\",\"referenceKey\":\"" + ref + "\"}";
                    }
                    if (m.getName().equals("getRequestURI")) return "/api/admin/legal";
                    return null;
                });
        ServletOutputStream out = new ServletOutputStream() {
            @Override public boolean isReady() { return true; }
            @Override public void setWriteListener(WriteListener l) { }
            @Override public void write(int b) { body.write(b); }
        };
        HttpServletResponse res = (HttpServletResponse) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class[]{HttpServletResponse.class}, (p, m, a) -> {
                    if (m.getName().equals("setStatus") || m.getName().equals("sendError")) status = (Integer) a[0];
                    if (m.getName().equals("getOutputStream")) return out;
                    return null;
                });
        new Legal().post(req, res);
    }

    private String pdfText() throws Exception {
        try (PDDocument doc = Loader.loadPDF(body.toByteArray())) {
            return new PDFTextStripper().getText(doc);
        }
    }

    private String head() throws Exception {
        try (PreparedStatement ps = db.prepareStatement("SELECT head_hash FROM verify_event_log_chain()");
             ResultSet rs = ps.executeQuery()) {
            rs.next();
            return rs.getString(1);
        }
    }

    @Test
    public void certificateCitesTheStoreEventAndTheHead() throws Exception {
        UUID ref = storedRecord();
        issue(ref);
        assertEquals(200, status);
        String text = pdfText();
        assertTrue(text, text.contains("Head hash: " + head()));
        assertTrue(text, text.contains("Log head at issue: sequence 3"));
        assertTrue(text, text.contains("Event: sequence 2")); // the STORE row, not the FETCH row
        assertTrue(text, text.contains("Software Source: TSI_PRIVACY_VAULT_V"));
        assertTrue(text, !text.contains("Software Source: null"));
    }

    @Test
    public void tamperedChainBlocksTheCertificate() throws Exception {
        UUID ref = storedRecord();
        exec("ALTER TABLE event_log DISABLE TRIGGER USER");
        exec("UPDATE event_log SET outcome = 'DENIED' WHERE chain_seq = 3");
        exec("ALTER TABLE event_log ENABLE TRIGGER USER");
        issue(ref);
        assertEquals(409, status);
        assertTrue(body.toString("UTF-8").contains("certificate not issued"));
    }
}
