package dev.ethantmcgee.yubiauthn.exception;

/**
 * Thrown when cryptographic operations fail.
 */
public class CryptoException extends AuthenticatorException {
  public CryptoException(String message) {
    super(message);
  }

  public CryptoException(String message, Throwable cause) {
    super(message, cause);
  }
}
