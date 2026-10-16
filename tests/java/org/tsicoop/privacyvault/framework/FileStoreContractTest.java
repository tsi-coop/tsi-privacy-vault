package org.tsicoop.privacyvault.framework;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Behaviour every FileStore backend must honour. Subclass it and implement
 * createStore(); the data plane relies on exactly these semantics.
 */
public abstract class FileStoreContractTest {

    protected FileStore store;
    private final List<String> created = new ArrayList<>();

    /** Returns a ready store, or throws AssumptionViolatedException to skip. */
    protected abstract FileStore createStore() throws Exception;

    @Before
    public void setUp() throws Exception {
        store = createStore();
    }

    @After
    public void cleanUp() {
        if (store == null) return;
        for (String key : created) {
            try {
                store.delete(key);
            } catch (Exception ignored) {
                // best effort
            }
        }
    }

    private String newKey() {
        String key = UUID.randomUUID().toString();
        created.add(key);
        return key;
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    @Test
    public void healthPassesForReachableStore() {
        store.health();
    }

    @Test
    public void putThenGetReturnsIdenticalBytes() {
        String key = newKey();
        byte[] data = randomBytes(4096);
        store.put(key, data);
        assertArrayEquals(data, store.get(key));
    }

    @Test
    public void everyByteValueSurvives() {
        String key = newKey();
        byte[] data = new byte[256 * 4];
        for (int i = 0; i < data.length; i++) data[i] = (byte) i;
        store.put(key, data);
        assertArrayEquals(data, store.get(key));
    }

    @Test
    public void largePayloadRoundTrips() {
        String key = newKey();
        byte[] data = randomBytes(6 * 1024 * 1024); // above the default 5 MB upload limit
        store.put(key, data);
        assertArrayEquals(data, store.get(key));
    }

    @Test
    public void emptyPayloadRoundTrips() {
        String key = newKey();
        store.put(key, new byte[0]);
        byte[] got = store.get(key);
        assertNotNull(got);
        assertEquals0(got.length);
    }

    private static void assertEquals0(int n) {
        assertTrue("expected empty payload but got " + n + " bytes", n == 0);
    }

    @Test
    public void putOverwritesExistingObject() {
        String key = newKey();
        store.put(key, randomBytes(64));
        byte[] second = randomBytes(128);
        store.put(key, second);
        assertArrayEquals(second, store.get(key));
    }

    @Test
    public void getMissingKeyReturnsNull() {
        assertNull(store.get(UUID.randomUUID().toString()));
    }

    @Test
    public void existsTracksLifecycle() {
        String key = newKey();
        assertFalse(store.exists(key));
        store.put(key, randomBytes(16));
        assertTrue(store.exists(key));
        store.delete(key);
        assertFalse(store.exists(key));
    }

    @Test
    public void deleteRemovesObject() {
        String key = newKey();
        store.put(key, randomBytes(16));
        store.delete(key);
        assertNull(store.get(key));
    }

    @Test
    public void deleteMissingKeyIsNotAnError() {
        store.delete(UUID.randomUUID().toString());
    }

    @Test
    public void keysAreIndependent() {
        String a = newKey();
        String b = newKey();
        byte[] da = randomBytes(32);
        byte[] db = randomBytes(32);
        store.put(a, da);
        store.put(b, db);
        store.delete(a);
        assertNull(store.get(a));
        assertArrayEquals(db, store.get(b));
    }

    @Test
    public void backendNameIsReported() {
        assertNotNull(store.backendName());
        assertFalse(store.backendName().isEmpty());
    }
}
