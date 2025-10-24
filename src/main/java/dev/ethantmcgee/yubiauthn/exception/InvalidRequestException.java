package dev.ethantmcgee.yubiauthn.exception;

/**
 * Exception thrown when a WebAuthn request does not meet the required specifications.
 *
 * <p>This exception is thrown when registration or authentication requests contain invalid data,
 * missing required fields, or violate WebAuthn protocol requirements.
 */
public class InvalidRequestException extends RuntimeException {
  /**
   * Constructs a new InvalidRequestException with the specified detail message.
   *
   * @param message the detail message explaining what is invalid about the request
   */
  public InvalidRequestException(String message) {
    super(message);
  }
}
