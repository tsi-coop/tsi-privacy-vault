package org.tsicoop.privacyvault.framework;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class LocalKmsProvider implements KmsProvider {

    private static final String ALGO = "AES/CBC/PKCS5Padding";

    @Override
    public Map<String, String> generateDataKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        Map<String, String> keys = new HashMap<>();
        keys.put("plaintextDataKey", Base64.getEncoder().encodeToString(key));
        // Simulate an encrypted key by prefixing it
        keys.put("encryptedDataKey", "MOCK_KMS_" + Base64.getEncoder().encodeToString(key));
        return keys;
    }

    @Override
    public String decryptDataKey(String encryptedDataKey) {
        // Strip the mock prefix to simulate decryption
        return encryptedDataKey.replace("MOCK_KMS_", "");
    }

    @Override
    public byte[] aesEncrypt(byte[] data, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
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
        byte[] iv = new byte[16];
        System.arraycopy(data, 0, iv, 0, 16);
        byte[] encrypted = new byte[data.length - 16];
        System.arraycopy(data, 16, encrypted, 0, encrypted.length);
        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(encrypted);
    }
}