package org.tsicoop.privacyvault.framework;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Single source of KmsProvider instances (docs/roadmap.md Phase 0/1).
 * Anchor providers and their clients are built once and reused for the
 * application lifetime. Also owns the boot-time fail-closed health gate:
 * the data plane refuses traffic until a wrap/unwrap round-trip against
 * the ACTIVE key ring anchor succeeds.
 */
public class KmsProviderFactory {

    public static final String ENV_PROVIDER = "TSI_PRIVACY_VAULT_KMS_PROVIDER";

    public static final String ANCHOR_LOCAL = "LOCAL";
    public static final String ANCHOR_AWS_KMS = "AWS_KMS";

    private static final KmsProvider PROVIDER = new VersionedKmsProvider();
    private static final ConcurrentHashMap<String, KmsProvider> ANCHORS = new ConcurrentHashMap<>();

    private static volatile boolean healthy = false;
    private static volatile String healthError = "KMS health check has not run yet";

    /** Version-aware provider used by all data-plane and utility code. */
    public static KmsProvider getProvider() {
        return PROVIDER;
    }

    /** Shared anchor provider instance for a vault_key_ring anchor_type. */
    public static KmsProvider getAnchorProvider(String anchorType) {
        String type = anchorType == null ? ANCHOR_LOCAL : anchorType.trim().toUpperCase();
        return ANCHORS.computeIfAbsent(type, t -> {
            switch (t) {
                case ANCHOR_LOCAL:
                    return new LocalKmsProvider();
                case ANCHOR_AWS_KMS:
                    return new AwsKmsProvider();
                default:
                    throw new IllegalArgumentException("Unsupported KMS anchor: " + t
                            + " (see docs/roadmap.md Phase 2/3)");
            }
        });
    }

    /** Intended anchor declared by the operator; informational until activated via API. */
    public static String getConfiguredAnchor() {
        String v = System.getenv(ENV_PROVIDER);
        return (v == null || v.trim().isEmpty()) ? ANCHOR_LOCAL : v.trim().toUpperCase();
    }

    /**
     * Fail-closed gate (roadmap 4.1, decided): verifies the key ring is loadable
     * and the ACTIVE anchor completes a GenerateDataKey + Decrypt round-trip.
     * On failure the data plane returns 503 until a later check succeeds.
     */
    public static synchronized boolean healthCheck() {
        try {
            KeyRing.refresh();
            KeyRing.KeyVersion active = KeyRing.getActive();
            verifyRoundTrip(getAnchorProvider(active.anchorType));
            String configured = getConfiguredAnchor();
            if (!configured.equals(active.anchorType)) {
                System.out.println("WARN: " + ENV_PROVIDER + "=" + configured
                        + " differs from active key ring anchor " + active.anchorType
                        + ". Run activate_key_anchor to migrate.");
            }
            healthy = true;
            healthError = null;
            System.out.println("KMS health check passed: anchor=" + active.anchorType
                    + " key_version=" + active.version);
        } catch (Exception e) {
            healthy = false;
            healthError = e.getMessage();
            System.err.println("CRITICAL: KMS health check failed - data plane disabled: " + e.getMessage());
            logHealthFailure(e.getMessage());
        }
        return healthy;
    }

    /** GenerateDataKey + Decrypt round-trip against an anchor provider. */
    public static void verifyRoundTrip(KmsProvider anchor) {
        Map<String, String> keys = anchor.generateDataKey();
        String recovered = anchor.decryptDataKey(keys.get("encryptedDataKey"));
        if (!keys.get("plaintextDataKey").equals(recovered)) {
            throw new IllegalStateException("KMS round-trip mismatch: unwrapped data key differs from generated key");
        }
    }

    public static boolean isHealthy() {
        return healthy;
    }

    public static String getHealthError() {
        return healthError;
    }

    private static void logHealthFailure(String reason) {
        Connection conn = null;
        PreparedStatement ps = null;
        PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            ps = conn.prepareStatement("INSERT INTO event_log (who, operation_type, client_ip, user_agent, machine_id, outcome, failure_reason, log_datetime) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
            ps.setString(1, "SYSTEM");
            ps.setString(2, "KMS_HEALTH_CHECK");
            ps.setString(3, "127.0.0.1");
            ps.setString(4, "KmsProviderFactory");
            ps.setString(5, ForensicEngine.getMachineIdentifier());
            ps.setString(6, "ERROR");
            ps.setString(7, reason);
            ps.setTimestamp(8, Timestamp.valueOf(LocalDateTime.now()));
            ps.executeUpdate();
        } catch (Exception e) {
            // The DB itself may be the failing dependency; stdout already has the cause.
            System.err.println("KMS health check forensic logging failed: " + e.getMessage());
        } finally {
            if (pool != null) pool.cleanup(null, ps, conn);
        }
    }
}
