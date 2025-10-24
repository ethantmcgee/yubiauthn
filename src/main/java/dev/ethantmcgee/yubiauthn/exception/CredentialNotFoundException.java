package dev.ethantmcgee.yubiauthn.exception;

/**
 * Exception thrown when a credential cannot be found in the credential store.
 *
 * <p>This exception is typically thrown during authentication when the requested credential ID does
 * not exist in the credential storage.
 */
public class CredentialNotFoundException extends RuntimeException {
  /**
   * Constructs a new CredentialNotFoundException with the specified detail message.
   *
   * @param message the detail message explaining why the credential was not found
   */
  public CredentialNotFoundException(String message) {
    super(message);
  }
}
