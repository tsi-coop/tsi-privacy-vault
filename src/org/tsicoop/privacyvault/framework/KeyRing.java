package org.tsicoop.privacyvault.framework;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;

/**
 * In-memory view of the vault_key_ring table (docs/roadmap.md Phase 0).
 * The ACTIVE entry decides which anchor wraps new DEKs and which payload
 * cipher new records use; DECRYPT_ONLY entries remain usable for unwrap.
 */
public class KeyRing {

    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_DECRYPT_ONLY = "DECRYPT_ONLY";
    public static final String STATUS_RETIRED = "RETIRED";

    public static class KeyVersion {
        public final int version;
        public final String anchorType;
        public final String anchorRef;
        public final String cipher;
        public final String status;

        KeyVersion(int version, String anchorType, String anchorRef, String cipher, String status) {
            this.version = version;
            this.anchorType = anchorType;
            this.anchorRef = anchorRef;
            this.cipher = cipher;
            this.status = status;
        }
    }

    private static volatile Map<Integer, KeyVersion> ring = null;
    private static volatile KeyVersion active = null;

    public static KeyVersion getActive() {
        load(false);
        if (active == null) {
            throw new IllegalStateException("No ACTIVE entry in vault_key_ring. Apply db/01_key_management.sql.");
        }
        return active;
    }

    public static KeyVersion get(int version) {
        load(false);
        KeyVersion kv = ring.get(version);
        if (kv == null) {
            throw new IllegalStateException("Unknown key_version " + version + " in vault_key_ring.");
        }
        return kv;
    }

    public static void refresh() {
        load(true);
    }

    private static synchronized void load(boolean force) {
        if (ring != null && !force) return;
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT key_version, anchor_type, anchor_ref, cipher, status FROM vault_key_ring");
            rs = ps.executeQuery();
            Map<Integer, KeyVersion> loaded = new HashMap<>();
            KeyVersion act = null;
            while (rs.next()) {
                KeyVersion kv = new KeyVersion(
                        rs.getInt("key_version"),
                        rs.getString("anchor_type"),
                        rs.getString("anchor_ref"),
                        rs.getString("cipher"),
                        rs.getString("status"));
                loaded.put(kv.version, kv);
                if (STATUS_ACTIVE.equals(kv.status)) act = kv;
            }
            ring = loaded;
            active = act;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load vault_key_ring: " + e.getMessage(), e);
        } finally {
            if (pool != null) pool.cleanup(rs, ps, conn);
        }
    }
}
