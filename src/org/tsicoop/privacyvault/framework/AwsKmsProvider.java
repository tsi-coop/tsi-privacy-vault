package org.tsicoop.privacyvault.framework;

import java.net.URI;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;

/**
 * AWS KMS anchor (docs/roadmap.md Phase 1).
 * Configured via environment variables; credentials come from the AWS default
 * chain (IAM role / instance profile / env / shared config). One KmsClient is
 * built per provider instance and the factory holds a single shared instance.
 * Every call carries an encryption context binding ciphertext to this vault
 * node, and throttled/transient failures are retried with backoff.
 */
public class AwsKmsProvider implements KmsProvider {

    public static final String ENV_REGION = "TSI_PRIVACY_VAULT_AWS_REGION";
    public static final String ENV_KEY_ID = "TSI_PRIVACY_VAULT_AWS_KMS_KEY_ID";
    public static final String ENV_ENDPOINT = "TSI_PRIVACY_VAULT_AWS_ENDPOINT";

    private static final int MAX_ATTEMPTS = 3;
    private static final long BASE_BACKOFF_MS = 200;

    private final KmsClient kmsClient;
    private final String kmsKeyId;
    private final Map<String, String> encryptionContext;

    public AwsKmsProvider() {
        String region = firstNonEmpty(System.getenv(ENV_REGION), System.getProperty("aws.region"));
        this.kmsKeyId = firstNonEmpty(System.getenv(ENV_KEY_ID), System.getProperty("aws.kms.identifier"));
        if (this.kmsKeyId == null) {
            throw new IllegalStateException(ENV_KEY_ID + " is not set. The AWS_KMS anchor requires a key ARN or alias ARN.");
        }
        if (region == null) {
            throw new IllegalStateException(ENV_REGION + " is not set. The AWS_KMS anchor requires an AWS region.");
        }

        KmsClientBuilder builder = KmsClient.builder().region(Region.of(region));
        String endpoint = firstNonEmpty(System.getenv(ENV_ENDPOINT), null);
        if (endpoint != null) {
            // Test/dev override (e.g., LocalStack); unset in production
            builder.endpointOverride(URI.create(endpoint));
        }
        this.kmsClient = builder.build();

        Map<String, String> ctx = new HashMap<>();
        String nodeId = System.getenv("TSI_PRIVACY_VAULT_NODE_ID");
        if (nodeId != null && !nodeId.trim().isEmpty()) {
            ctx.put("vault_node_id", nodeId.trim());
        }
        this.encryptionContext = Collections.unmodifiableMap(ctx);
    }

    public String getKmsKeyId() {
        return kmsKeyId;
    }

    @Override
    public Map<String, String> generateDataKey() {
        GenerateDataKeyResponse response = withRetry("GenerateDataKey", () ->
                kmsClient.generateDataKey(GenerateDataKeyRequest.builder()
                        .keyId(kmsKeyId)
                        .keySpec(DataKeySpec.AES_256)
                        .encryptionContext(encryptionContext)
                        .build()));

        Map<String, String> keys = new HashMap<>();
        keys.put("plaintextDataKey", Base64.getEncoder().encodeToString(response.plaintext().asByteArray()));
        keys.put("encryptedDataKey", Base64.getEncoder().encodeToString(response.ciphertextBlob().asByteArray()));
        return keys;
    }

    @Override
    public String decryptDataKey(String encryptedDataKeyBase64) {
        byte[] encryptedKey = Base64.getDecoder().decode(encryptedDataKeyBase64);
        DecryptResponse response = withRetry("Decrypt", () ->
                kmsClient.decrypt(DecryptRequest.builder()
                        .ciphertextBlob(SdkBytes.fromByteArray(encryptedKey))
                        .keyId(kmsKeyId)
                        .encryptionContext(encryptionContext)
                        .build()));
        return Base64.getEncoder().encodeToString(response.plaintext().asByteArray());
    }

    @Override
    public String wrapDataKey(String plaintextDataKeyBase64) {
        byte[] rawDataKey = Base64.getDecoder().decode(plaintextDataKeyBase64);
        EncryptResponse response = withRetry("Encrypt", () ->
                kmsClient.encrypt(EncryptRequest.builder()
                        .keyId(kmsKeyId)
                        .plaintext(SdkBytes.fromByteArray(rawDataKey))
                        .encryptionContext(encryptionContext)
                        .build()));
        return Base64.getEncoder().encodeToString(response.ciphertextBlob().asByteArray());
    }

    @Override
    public byte[] aesEncrypt(byte[] data, byte[] key) throws Exception {
        return CipherUtil.encrypt(CipherUtil.AES_GCM, data, key);
    }

    @Override
    public byte[] aesDecrypt(byte[] data, byte[] key) throws Exception {
        return CipherUtil.decrypt(CipherUtil.AES_GCM, data, key);
    }

    private <T> T withRetry(String operation, Supplier<T> call) {
        SdkException last = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                return call.get();
            } catch (SdkException e) {
                last = e;
                if (!isRetryable(e) || attempt == MAX_ATTEMPTS) {
                    throw new RuntimeException("AWS KMS " + operation + " failed: " + e.getMessage(), e);
                }
                try {
                    Thread.sleep(BASE_BACKOFF_MS << (attempt - 1));
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("AWS KMS " + operation + " interrupted during retry backoff", e);
                }
            }
        }
        throw new RuntimeException("AWS KMS " + operation + " failed after " + MAX_ATTEMPTS + " attempts", last);
    }

    private boolean isRetryable(SdkException e) {
        if (e instanceof AwsServiceException) {
            AwsServiceException ase = (AwsServiceException) e;
            return ase.isThrottlingException() || ase.statusCode() >= 500;
        }
        return e.retryable();
    }

    private static String firstNonEmpty(String a, String b) {
        if (a != null && !a.trim().isEmpty()) return a.trim();
        if (b != null && !b.trim().isEmpty()) return b.trim();
        return null;
    }
}
