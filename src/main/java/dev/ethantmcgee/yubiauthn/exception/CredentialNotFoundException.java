package dev.ethantmcgee.yubiauthn.exception;

/** Thrown when a requested credential cannot be found. */
public class CredentialNotFoundException extends AuthenticatorException {
  /**
   * Constructs a new credential not found exception with the specified detail message.
   *
   * @param message the detail message
   */
  public CredentialNotFoundException(String message) {
    super(message);
  }

  /**
   * Constructs a new credential not found exception with the specified detail message and cause.
   *
   * @param message the detail message
   * @param cause the cause of this exception
   */
  public CredentialNotFoundException(String message, Throwable cause) {
    super(message, cause);
  }
}
