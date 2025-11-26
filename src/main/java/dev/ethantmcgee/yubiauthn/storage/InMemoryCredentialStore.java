package dev.ethantmcgee.yubiauthn.storage;

import dev.ethantmcgee.yubiauthn.model.StoredCredential;
import java.util.Collection;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory implementation of CredentialStore.
 *
 * <p>This implementation uses a ConcurrentHashMap for thread-safe access without external
 * synchronization.
 */
public class InMemoryCredentialStore implements CredentialStore {
  private final ConcurrentHashMap<String, StoredCredential> credentials = new ConcurrentHashMap<>();

  @Override
  public void store(String id, StoredCredential credential) {
    if (id == null || id.isEmpty()) {
      throw new IllegalArgumentException("Credential ID must not be null or empty");
    }
    if (credential == null) {
      throw new IllegalArgumentException("Credential must not be null");
    }
    credentials.put(id, credential);
  }

  @Override
  public Optional<StoredCredential> retrieve(String id) {
    if (id == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(credentials.get(id));
  }

  @Override
  public Collection<StoredCredential> findByRpId(String rpId) {
    if (rpId == null) {
      return java.util.Collections.emptyList();
    }
    return credentials.values().stream().filter(cred -> rpId.equals(cred.rpId())).toList();
  }

  @Override
  public boolean remove(String id) {
    if (id == null) {
      return false;
    }
    return credentials.remove(id) != null;
  }

  @Override
  public void clear() {
    credentials.clear();
  }

  @Override
  public int size() {
    return credentials.size();
  }
}
