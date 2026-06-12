package org.tsicoop.privacyvault.framework;

import java.util.Map;

/**
 * Key-version-aware KmsProvider facade (docs/roadmap.md Phase 0).
 * Routes DEK wrap/unwrap to the anchor recorded in vault_key_ring for the
 * relevant key version and selects the payload cipher per version. All
 * data-plane code obtains this via KmsProviderFactory.getProvider().
 */
public class VersionedKmsProvider implements KmsProvider {

    @Override
    public Map<String, String> generateDataKey() {
        KeyRing.KeyVersion active = KeyRing.getActive();
        Map<String, String> keys = KmsProviderFactory.getAnchorProvider(active.anchorType).generateDataKey();
        keys.put("keyVersion", String.valueOf(active.version));
        keys.put("payloadCipher", active.cipher);
        return keys;
    }

    @Override
    public String decryptDataKey(String encryptedDataKeyBase64) {
        return decryptDataKey(encryptedDataKeyBase64, KeyRing.getActive().version);
    }

    @Override
    public String decryptDataKey(String encryptedDataKeyBase64, int keyVersion) {
        KeyRing.KeyVersion kv = KeyRing.get(keyVersion);
        if (KeyRing.STATUS_RETIRED.equals(kv.status)) {
            throw new IllegalStateException("key_version " + keyVersion + " is RETIRED and can no longer unwrap keys");
        }
        return KmsProviderFactory.getAnchorProvider(kv.anchorType).decryptDataKey(encryptedDataKeyBase64);
    }

    @Override
    public int getActiveKeyVersion() {
        return KeyRing.getActive().version;
    }

    @Override
    public byte[] aesEncrypt(byte[] data, byte[] key) throws Exception {
        return CipherUtil.encrypt(KeyRing.getActive().cipher, data, key);
    }

    @Override
    public byte[] aesDecrypt(byte[] encryptedData, byte[] key) throws Exception {
        // Legacy single-arg path assumes the active cipher; readers of stored
        // records must use the payload_cipher overload instead.
        return CipherUtil.decrypt(KeyRing.getActive().cipher, encryptedData, key);
    }

    @Override
    public String wrapDataKey(String plaintextDataKeyBase64) {
        return KmsProviderFactory.getAnchorProvider(KeyRing.getActive().anchorType).wrapDataKey(plaintextDataKeyBase64);
    }
}
