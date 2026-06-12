package org.tsicoop.privacyvault.framework;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * Payload cipher primitives selected per key-ring version (docs/roadmap.md Phase 0).
 * AES_CBC_PKCS5 is retained for legacy (key_version 1) records; AES_GCM is used for
 * all new key versions. Both formats prepend the IV/nonce to the ciphertext blob.
 */
public class CipherUtil {

    public static final String AES_CBC_PKCS5 = "AES_CBC_PKCS5";
    public static final String AES_GCM = "AES_GCM";

    private static final String CBC_ALGO = "AES/CBC/PKCS5Padding";
    private static final String GCM_ALGO = "AES/GCM/NoPadding";
    private static final int CBC_IV_LENGTH = 16;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;

    public static byte[] encrypt(String cipherName, byte[] data, byte[] key) throws Exception {
        if (AES_GCM.equals(cipherName)) return encryptGcm(data, key);
        if (AES_CBC_PKCS5.equals(cipherName)) return encryptCbc(data, key);
        throw new IllegalArgumentException("Unsupported payload cipher: " + cipherName);
    }

    public static byte[] decrypt(String cipherName, byte[] data, byte[] key) throws Exception {
        if (AES_GCM.equals(cipherName)) return decryptGcm(data, key);
        if (AES_CBC_PKCS5.equals(cipherName)) return decryptCbc(data, key);
        throw new IllegalArgumentException("Unsupported payload cipher: " + cipherName);
    }

    private static byte[] encryptCbc(byte[] data, byte[] key) throws Exception {
        byte[] iv = new byte[CBC_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance(CBC_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return prependIv(iv, cipher.doFinal(data));
    }

    private static byte[] decryptCbc(byte[] data, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(CBC_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new IvParameterSpec(data, 0, CBC_IV_LENGTH));
        return cipher.doFinal(data, CBC_IV_LENGTH, data.length - CBC_IV_LENGTH);
    }

    private static byte[] encryptGcm(byte[] data, byte[] key) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance(GCM_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        return prependIv(iv, cipher.doFinal(data));
    }

    private static byte[] decryptGcm(byte[] data, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(GCM_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, data, 0, GCM_IV_LENGTH));
        return cipher.doFinal(data, GCM_IV_LENGTH, data.length - GCM_IV_LENGTH);
    }

    private static byte[] prependIv(byte[] iv, byte[] encrypted) {
        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        return result;
    }
}
