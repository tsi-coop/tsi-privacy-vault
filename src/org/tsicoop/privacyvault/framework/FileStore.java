package org.tsicoop.privacyvault.framework;

/**
 * Backend for the encrypted bytes of FILE records (docs/design/architecture.md,
 * "Storage backends"). Implementations only ever receive ciphertext: the
 * payload is encrypted in the vault process before it reaches put().
 *
 * The default DATABASE backend is not a FileStore. Its content stays inline in
 * vault_entities.encrypted_content, so FileStoreFactory.getExternal returns
 * null for it and the data plane keeps its existing path.
 */
public interface FileStore {

    /** Selector stored in vault_entities.storage_backend, e.g. AWS_S3. */
    String backendName();

    /** Stores ciphertext under an opaque key. Overwrites an existing object. */
    void put(String key, byte[] ciphertext);

    /** Returns the stored ciphertext, or null when the key does not exist. */
    byte[] get(String key);

    /** Removes the object. Deleting a missing key is not an error. */
    void delete(String key);

    boolean exists(String key);

    /** Throws when the backend is unreachable or misconfigured. */
    void health();
}
