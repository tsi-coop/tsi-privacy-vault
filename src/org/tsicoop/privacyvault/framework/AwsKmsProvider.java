package org.tsicoop.privacyvault.framework;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

public class AwsKmsProvider implements KmsProvider {

    private final KmsClient kmsClient;
    private final String kmsKeyId;
    private static final String AES_ALGO = "AES/CBC/PKCS5Padding";

    public AwsKmsProvider() {
        // Load configurations
        String region = System.getProperty("aws.region", "ap-south-1");
        this.kmsKeyId = System.getProperty("aws.kms.identifier");
        this.kmsClient = KmsClient.builder()
                .region(Region.of(region))
                .build();
    }

    @Override
    public Map<String, String> generateDataKey() {
        // Requests AWS to generate a new unique key for a record
        GenerateDataKeyRequest request = GenerateDataKeyRequest.builder()
                .keyId(kmsKeyId)
                .keySpec(DataKeySpec.AES_256)
                .build();

        GenerateDataKeyResponse response = kmsClient.generateDataKey(request);

        Map<String, String> keys = new HashMap<>();
        keys.put("plaintextDataKey", Base64.getEncoder().encodeToString(response.plaintext().asByteArray()));
        keys.put("encryptedDataKey", Base64.getEncoder().encodeToString(response.ciphertextBlob().asByteArray()));
        return keys;
    }

    @Override
    public String decryptDataKey(String encryptedDataKeyBase64) {
        // Uses AWS KMS Master Key to unlock the individual record key
        byte[] encryptedKey = Base64.getDecoder().decode(encryptedDataKeyBase64);
        DecryptRequest decryptRequest = DecryptRequest.builder()
                .ciphertextBlob(SdkBytes.fromByteArray(encryptedKey))
                .keyId(kmsKeyId)
                .build();

        DecryptResponse response = kmsClient.decrypt(decryptRequest);
        return Base64.getEncoder().encodeToString(response.plaintext().asByteArray());
    }

    @Override
    public byte[] aesEncrypt(byte[] data, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGO);
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        
        byte[] encrypted = cipher.doFinal(data);
        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        return result;
    }

    @Override
    public byte[] aesDecrypt(byte[] data, byte[] key) throws Exception {
        byte[] iv = new byte[16];
        System.arraycopy(data, 0, iv, 0, 16);
        byte[] encrypted = new byte[data.length - 16];
        System.arraycopy(data, 16, encrypted, 0, encrypted.length);
        
        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(encrypted);
    }
}