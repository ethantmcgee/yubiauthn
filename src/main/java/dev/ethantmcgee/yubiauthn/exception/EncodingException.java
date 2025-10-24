package dev.ethantmcgee.yubiauthn.exception;

/**
 * Exception thrown when encoding or decoding operations fail.
 *
 * <p>This exception indicates that an error occurred during CBOR encoding, JSON serialization, or
 * other data encoding/decoding operations.
 */
public class EncodingException extends Exception {
  public EncodingException(String message) {
    super(message);
  }

  public EncodingException(String message, Throwable cause) {
    super(message, cause);
  }
}
