package org.tsicoop.privacyvault.framework;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Single source of FileStore instances (docs/design/architecture.md, "Storage
 * backends"). The active backend applies to new FILE records only. Reads route
 * by the row's own storage_backend, so old and new records coexist.
 */
public class FileStoreFactory {

    public static final String ENV_FILE_STORE = "TSI_PRIVACY_VAULT_FILE_STORE";

    public static final String STORE_DATABASE = "DATABASE";
    public static final String STORE_AWS_S3 = "AWS_S3";
    public static final String STORE_S3_COMPATIBLE = "S3_COMPATIBLE";

    private static final ConcurrentHashMap<String, FileStore> STORES = new ConcurrentHashMap<>();

    private static final long RECHECK_INTERVAL_MS = 30_000L;

    private static volatile boolean healthy = true;
    private static volatile String healthError = null;
    private static volatile long lastCheckMs = 0;

    /** Backend for new FILE records. Defaults to DATABASE. */
    public static String getActiveBackend() {
        String v = System.getenv(ENV_FILE_STORE);
        return (v == null || v.trim().isEmpty()) ? STORE_DATABASE : v.trim().toUpperCase();
    }

    /**
     * Store for a backend selector, or null for DATABASE, where content stays
     * inline in vault_entities.
     */
    public static FileStore getExternal(String backend) {
        String type = (backend == null || backend.trim().isEmpty()) ? STORE_DATABASE : backend.trim().toUpperCase();
        if (STORE_DATABASE.equals(type)) {
            return null;
        }
        return STORES.computeIfAbsent(type, t -> {
            switch (t) {
                case STORE_AWS_S3:
                case STORE_S3_COMPATIBLE:
                    return new S3FileStore(t);
                default:
                    throw new IllegalArgumentException("Unsupported file store: " + t
                            + " (supported: DATABASE, AWS_S3, S3_COMPATIBLE)");
            }
        });
    }

    /** Test hook: installs a store under a backend selector. */
    static void registerForTesting(String backend, FileStore store) {
        STORES.put(backend.toUpperCase(), store);
    }

    /**
     * Fail-closed gate for the active external backend. A DATABASE deployment is
     * always healthy. On failure the data plane returns 503 until a later check
     * succeeds.
     */
    public static synchronized boolean healthCheck() {
        lastCheckMs = System.currentTimeMillis();
        try {
            FileStore store = getExternal(getActiveBackend());
            if (store != null) {
                store.health();
                System.out.println("File store health check passed: backend=" + store.backendName());
            }
            healthy = true;
            healthError = null;
        } catch (Exception e) {
            healthy = false;
            healthError = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            System.err.println("CRITICAL: file store health check failed - data plane disabled: " + healthError);
        }
        return healthy;
    }

    /**
     * Cached health. While unhealthy it re-checks at most every 30 seconds, so a recovered
     * bucket re-opens the data plane without an application restart.
     */
    public static boolean isHealthy() {
        if (!healthy && System.currentTimeMillis() - lastCheckMs >= RECHECK_INTERVAL_MS) {
            healthCheck();
        }
        return healthy;
    }

    /**
     * Where the active backend stores files, for display. Names the bucket, region and endpoint
     * host only. Credentials are never read here.
     */
    public static org.json.simple.JSONObject describeActive() {
        org.json.simple.JSONObject d = new org.json.simple.JSONObject();
        String backend = getActiveBackend();
        d.put("backend", backend);
        if (!STORE_DATABASE.equals(backend)) {
            d.put("bucket", env(S3FileStore.ENV_BUCKET));
            d.put("region", env(S3FileStore.ENV_REGION));
            d.put("prefix", env(S3FileStore.ENV_PREFIX));
            String endpoint = env(S3FileStore.ENV_ENDPOINT);
            String host = null;
            if (endpoint != null) {
                try {
                    host = java.net.URI.create(endpoint).getHost();
                } catch (Exception ignored) {
                    host = null;
                }
            }
            d.put("endpoint_host", host);
        }
        return d;
    }

    private static String env(String name) {
        String v = System.getenv(name);
        return (v == null || v.trim().isEmpty()) ? null : v.trim();
    }

    public static String getHealthError() {
        return healthError;
    }
}
