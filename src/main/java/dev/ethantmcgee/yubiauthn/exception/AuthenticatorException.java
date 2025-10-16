package dev.ethantmcgee.yubiauthn.exception;

/**
 * Base exception for all authenticator-related errors.
 */
public class AuthenticatorException extends Exception {
  public AuthenticatorException(String message) {
    super(message);
  }

  public AuthenticatorException(String message, Throwable cause) {
    super(message, cause);
  }
}
