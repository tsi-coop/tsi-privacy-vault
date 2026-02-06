package org.tsicoop.privacyvault.framework;
import java.util.Map;

public interface KmsProvider {
    Map<String, String> generateDataKey();
    String decryptDataKey(String encryptedDataKeyBase64);
    byte[] aesEncrypt(byte[] data, byte[] key) throws Exception;
    byte[] aesDecrypt(byte[] encryptedData, byte[] key) throws Exception;
}