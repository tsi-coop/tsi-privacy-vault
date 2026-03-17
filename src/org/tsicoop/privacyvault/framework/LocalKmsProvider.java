package org.tsicoop.privacyvault.framework;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Local implementation of KmsProvider using a fixed Master Key.
 * Replaces mock prefixes with actual AES-256 wrapping of Data Keys.
 */
public class LocalKmsProvider implements KmsProvider {

    private static final String ALGO = "AES/CBC/PKCS5Padding";
    
    // Normalize the environment variable or default string to exactly 32 bytes using SHA-256
    private static final byte[] MASTER_KEY = initializeMasterKey();

    private static byte[] initializeMasterKey() {
        try {
            String rawKey = System.getenv("TSI_PRIVACY_VAULT_MASTER_KEY");
            if (rawKey == null || rawKey.isEmpty()) {
                // Default fallback for dev path
                rawKey = "tsi-vault-default-32-byte-master-key-seed"; 
            }
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            return sha.digest(rawKey.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("KMS Initialization Failed", e);
        }
    }

    @Override
    public Map<String, String> generateDataKey() {
        try {
            // 1. Generate a new random 32-byte Data Key
            byte[] rawDataKey = new byte[32];
            new SecureRandom().nextBytes(rawDataKey);
            
            System.out.println("Master Key:"+MASTER_KEY);
            // 2. Wrap (Encrypt) the Data Key using the Master Key
            byte[] wrappedKey = aesEncrypt(rawDataKey, MASTER_KEY);
            
            Map<String, String> keys = new HashMap<>();
            keys.put("plaintextDataKey", Base64.getEncoder().encodeToString(rawDataKey));
            keys.put("encryptedDataKey", Base64.getEncoder().encodeToString(wrappedKey));
            return keys;
        } catch (Exception e) {
            throw new RuntimeException("Local KMS Failure: Could not generate data key", e);
        }
    }

    @Override
    public String decryptDataKey(String encryptedDataKeyB64) {
        try {
            // Unwrap (Decrypt) the Data Key using the Master Key
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedDataKeyB64);
            byte[] decryptedKey = aesDecrypt(encryptedBytes, MASTER_KEY);
            
            return Base64.getEncoder().encodeToString(decryptedKey);
        } catch (Exception e) {
            throw new RuntimeException("Local KMS Failure: Could not decrypt data key", e);
        }
    }

    @Override
    public byte[] aesEncrypt(byte[] data, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv); // Generate unique IV for this operation
        
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(data);
        
        // Prepend IV for storage
        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        return result;
    }

    @Override
    public byte[] aesDecrypt(byte[] data, byte[] key) throws Exception {
        // Extract the 16-byte IV from the front of the blob
        byte[] iv = new byte[16];
        System.arraycopy(data, 0, iv, 0, 16);
        
        byte[] encrypted = new byte[data.length - 16];
        System.arraycopy(data, 16, encrypted, 0, encrypted.length);
        
        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(encrypted);
    }
}