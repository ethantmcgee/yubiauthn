package dev.ethantmcgee.yubiauthn.exception;

/** Thrown when cryptographic operations fail. */
public class CryptoException extends AuthenticatorException {
  /**
   * Constructs a new crypto exception with the specified detail message.
   *
   * @param message the detail message
   */
  public CryptoException(String message) {
    super(message);
  }

  /**
   * Constructs a new crypto exception with the specified detail message and cause.
   *
   * @param message the detail message
   * @param cause the cause of this exception
   */
  public CryptoException(String message, Throwable cause) {
    super(message, cause);
  }
}
