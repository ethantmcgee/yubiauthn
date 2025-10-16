package dev.ethantmcgee.yubiauthn.exception;

/** Thrown when a request does not meet the authenticator's requirements or constraints. */
public class InvalidRequestException extends AuthenticatorException {
  /**
   * Constructs a new invalid request exception with the specified detail message.
   *
   * @param message the detail message
   */
  public InvalidRequestException(String message) {
    super(message);
  }

  /**
   * Constructs a new invalid request exception with the specified detail message and cause.
   *
   * @param message the detail message
   * @param cause the cause of this exception
   */
  public InvalidRequestException(String message, Throwable cause) {
    super(message, cause);
  }
}
