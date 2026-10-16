package org.tsicoop.privacyvault.framework;

import java.net.URI;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * AWS S3 and S3-compatible (MinIO, Ceph RGW) file store. Credentials come from
 * the AWS default chain. A custom endpoint switches to path-style addressing,
 * which is what most on-prem object stores expect.
 */
public class S3FileStore implements FileStore {

    public static final String ENV_BUCKET = "TSI_PRIVACY_VAULT_S3_BUCKET";
    public static final String ENV_REGION = "TSI_PRIVACY_VAULT_S3_REGION";
    public static final String ENV_ENDPOINT = "TSI_PRIVACY_VAULT_S3_ENDPOINT";
    public static final String ENV_PREFIX = "TSI_PRIVACY_VAULT_S3_PREFIX";

    private final String backendName;
    private final S3Client s3;
    private final String bucket;
    private final String prefix;

    /** Configured from the TSI_PRIVACY_VAULT_S3_* environment variables. */
    public S3FileStore(String backendName) {
        this(backendName, env(ENV_BUCKET), env(ENV_REGION), env(ENV_ENDPOINT), env(ENV_PREFIX));
    }

    public S3FileStore(String backendName, String bucket, String region, String endpoint, String keyPrefix) {
        this.backendName = backendName;
        this.bucket = bucket;
        if (bucket == null) {
            throw new IllegalStateException(ENV_BUCKET + " is not set. The " + backendName + " file store requires a bucket.");
        }
        if (region == null) {
            throw new IllegalStateException(ENV_REGION + " is not set. The " + backendName + " file store requires a region.");
        }
        if (keyPrefix == null) {
            this.prefix = "";
        } else {
            this.prefix = keyPrefix.endsWith("/") ? keyPrefix : keyPrefix + "/";
        }

        S3ClientBuilder builder = S3Client.builder().region(Region.of(region));
        if (endpoint != null) {
            if (!endpoint.toLowerCase().startsWith("https://")) {
                throw new IllegalStateException(ENV_ENDPOINT + " must use https.");
            }
            builder.endpointOverride(URI.create(endpoint))
                    .serviceConfiguration(S3Configuration.builder().pathStyleAccessEnabled(true).build());
        } else if (FileStoreFactory.STORE_S3_COMPATIBLE.equals(backendName)) {
            throw new IllegalStateException(ENV_ENDPOINT + " is required for " + backendName + ".");
        }
        this.s3 = builder.build();
    }

    @Override
    public String backendName() {
        return backendName;
    }

    @Override
    public void put(String key, byte[] ciphertext) {
        s3.putObject(PutObjectRequest.builder()
                        .bucket(bucket)
                        .key(prefix + key)
                        .contentType("application/octet-stream")
                        .build(),
                RequestBody.fromBytes(ciphertext));
    }

    @Override
    public byte[] get(String key) {
        try {
            ResponseBytes<GetObjectResponse> r = s3.getObjectAsBytes(
                    GetObjectRequest.builder().bucket(bucket).key(prefix + key).build());
            return r.asByteArray();
        } catch (NoSuchKeyException e) {
            return null;
        }
    }

    @Override
    public void delete(String key) {
        s3.deleteObject(DeleteObjectRequest.builder().bucket(bucket).key(prefix + key).build());
    }

    @Override
    public boolean exists(String key) {
        try {
            s3.headObject(HeadObjectRequest.builder().bucket(bucket).key(prefix + key).build());
            return true;
        } catch (NoSuchKeyException e) {
            return false;
        } catch (S3Exception e) {
            if (e.statusCode() == 404) return false;
            throw e;
        }
    }

    @Override
    public void health() {
        s3.headBucket(HeadBucketRequest.builder().bucket(bucket).build());
    }

    private static String env(String name) {
        String v = System.getenv(name);
        return (v == null || v.trim().isEmpty()) ? null : v.trim();
    }
}
