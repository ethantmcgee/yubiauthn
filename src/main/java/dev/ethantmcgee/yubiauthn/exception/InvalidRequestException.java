package dev.ethantmcgee.yubiauthn.exception;

/** Thrown when a request does not meet the authenticator's requirements or constraints. */
public class InvalidRequestException extends AuthenticatorException {
  public InvalidRequestException(String message) {
    super(message);
  }

  public InvalidRequestException(String message, Throwable cause) {
    super(message, cause);
  }
}
