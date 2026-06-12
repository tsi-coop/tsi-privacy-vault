package org.tsicoop.privacyvault.framework;
import java.util.Map;

public interface KmsProvider {
    Map<String, String> generateDataKey();
    String decryptDataKey(String encryptedDataKeyBase64);
    byte[] aesEncrypt(byte[] data, byte[] key) throws Exception;
    byte[] aesDecrypt(byte[] encryptedData, byte[] key) throws Exception;

    /** Key-ring version under which new DEKs are wrapped (docs/roadmap.md Phase 0). */
    default int getActiveKeyVersion() {
        return 1;
    }

    /** Unwrap a DEK wrapped under a specific key-ring version. */
    default String decryptDataKey(String encryptedDataKeyBase64, int keyVersion) {
        return decryptDataKey(encryptedDataKeyBase64);
    }

    /** Decrypt a payload using the cipher recorded on the row (payload_cipher column). */
    default byte[] aesDecrypt(byte[] encryptedData, byte[] key, String payloadCipher) throws Exception {
        return CipherUtil.decrypt(payloadCipher, encryptedData, key);
    }

    /** Wrap an existing plaintext DEK under this anchor (used by the re-wrap migration job). */
    default String wrapDataKey(String plaintextDataKeyBase64) {
        throw new UnsupportedOperationException("wrapDataKey is not supported by " + getClass().getName());
    }
}
