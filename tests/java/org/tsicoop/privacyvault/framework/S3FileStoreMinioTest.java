package org.tsicoop.privacyvault.framework;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assume.assumeTrue;
import static org.junit.Assert.fail;

import java.util.UUID;
import org.junit.Test;

/**
 * Runs the FileStore contract against a live MinIO. Skipped unless
 * TSI_TEST_S3_ENDPOINT is set; tests/runners/run-minio-contract.sh starts
 * MinIO, creates the bucket and sets these variables:
 *
 *   TSI_TEST_S3_ENDPOINT   https://localhost:9000 (HTTPS is required by S3FileStore)
 *   TSI_TEST_S3_BUCKET     bucket that already exists
 *   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY   credentials for the bucket
 *
 * The JVM must trust the MinIO certificate (-Djavax.net.ssl.trustStore).
 */
public class S3FileStoreMinioTest extends FileStoreContractTest {

    private static final String REGION = "us-east-1";

    private static String endpoint() {
        String v = System.getenv("TSI_TEST_S3_ENDPOINT");
        return (v == null || v.trim().isEmpty()) ? null : v.trim();
    }

    private static String bucket() {
        String v = System.getenv("TSI_TEST_S3_BUCKET");
        return (v == null || v.trim().isEmpty()) ? "vault-contract-test" : v.trim();
    }

    @Override
    protected FileStore createStore() {
        assumeTrue("TSI_TEST_S3_ENDPOINT not set; skipping MinIO contract test", endpoint() != null);
        return new S3FileStore(FileStoreFactory.STORE_S3_COMPATIBLE, bucket(), REGION, endpoint(), null);
    }

    @Test
    public void prefixIsolatesObjects() {
        String run = "run-" + UUID.randomUUID() + "/";
        S3FileStore a = new S3FileStore(FileStoreFactory.STORE_S3_COMPATIBLE, bucket(), REGION, endpoint(), run + "a");
        S3FileStore b = new S3FileStore(FileStoreFactory.STORE_S3_COMPATIBLE, bucket(), REGION, endpoint(), run + "b");
        String key = UUID.randomUUID().toString();
        byte[] data = {1, 2, 3, 4};
        try {
            a.put(key, data);
            assertArrayEquals(data, a.get(key));
            assertNull(b.get(key));
            assertFalse(b.exists(key));
        } finally {
            a.delete(key);
        }
    }

    @Test
    public void healthFailsForMissingBucket() {
        S3FileStore bad = new S3FileStore(FileStoreFactory.STORE_S3_COMPATIBLE,
                "no-such-bucket-" + UUID.randomUUID(), REGION, endpoint(), null);
        try {
            bad.health();
            fail("health() must throw for a bucket that does not exist");
        } catch (RuntimeException expected) {
            // fail closed
        }
    }

    @Test(expected = IllegalStateException.class)
    public void plainHttpEndpointIsRejected() {
        new S3FileStore(FileStoreFactory.STORE_S3_COMPATIBLE, bucket(), REGION, "http://localhost:9000", null);
    }
}
