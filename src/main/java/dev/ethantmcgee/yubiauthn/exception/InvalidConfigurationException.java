package dev.ethantmcgee.yubiauthn.exception;

/**
 * Thrown when the authenticator is configured incorrectly.
 */
public class InvalidConfigurationException extends AuthenticatorException {
  public InvalidConfigurationException(String message) {
    super(message);
  }

  public InvalidConfigurationException(String message, Throwable cause) {
    super(message, cause);
  }
}
