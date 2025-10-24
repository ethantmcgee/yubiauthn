package dev.ethantmcgee.yubiauthn.exception;

/**
 * Exception thrown when a cryptographic operation fails.
 *
 * <p>This exception indicates that an error occurred during key generation, signing, certificate
 * creation, or other cryptographic operations.
 */
public class CryptographicException extends Exception {
  public CryptographicException(String message) {
    super(message);
  }

  public CryptographicException(String message, Throwable cause) {
    super(message, cause);
  }
}
