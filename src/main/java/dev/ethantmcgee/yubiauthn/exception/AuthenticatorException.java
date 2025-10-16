package dev.ethantmcgee.yubiauthn.exception;

/** Base exception for all authenticator-related errors. */
public class AuthenticatorException extends Exception {
  /**
   * Constructs a new authenticator exception with the specified detail message.
   *
   * @param message the detail message
   */
  public AuthenticatorException(String message) {
    super(message);
  }

  /**
   * Constructs a new authenticator exception with the specified detail message and cause.
   *
   * @param message the detail message
   * @param cause the cause of this exception
   */
  public AuthenticatorException(String message, Throwable cause) {
    super(message, cause);
  }
}
