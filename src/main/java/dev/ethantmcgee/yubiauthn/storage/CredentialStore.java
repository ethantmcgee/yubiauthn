package dev.ethantmcgee.yubiauthn.storage;

import dev.ethantmcgee.yubiauthn.model.StoredCredential;
import java.util.Collection;
import java.util.Optional;

/**
 * Interface for storing and retrieving credentials.
 *
 * <p>This abstraction allows for different storage implementations (in-memory, persistent, etc.)
 * for testing different scenarios.
 */
public interface CredentialStore {
  /**
   * Stores a credential with the given ID.
   *
   * @param id the credential ID (Base64URL-encoded)
   * @param credential the credential to store
   */
  void store(String id, StoredCredential credential);

  /**
   * Retrieves a credential by its ID.
   *
   * @param id the credential ID (Base64URL-encoded)
   * @return an Optional containing the credential if found, empty otherwise
   */
  Optional<StoredCredential> retrieve(String id);

  /**
   * Finds all credentials for a given Relying Party ID.
   *
   * @param rpId the Relying Party ID
   * @return a collection of matching credentials
   */
  Collection<StoredCredential> findByRpId(String rpId);

  /**
   * Removes a credential by its ID.
   *
   * @param id the credential ID (Base64URL-encoded)
   * @return true if the credential was removed, false if it didn't exist
   */
  boolean remove(String id);

  /** Removes all credentials from the store. */
  void clear();

  /**
   * Returns the number of credentials in the store.
   *
   * @return the credential count
   */
  int size();
}
