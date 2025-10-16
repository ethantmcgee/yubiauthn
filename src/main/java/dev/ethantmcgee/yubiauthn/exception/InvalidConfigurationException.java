package dev.ethantmcgee.yubiauthn.exception;

/** Thrown when the authenticator is configured incorrectly. */
public class InvalidConfigurationException extends AuthenticatorException {
  /**
   * Constructs a new invalid configuration exception with the specified detail message.
   *
   * @param message the detail message
   */
  public InvalidConfigurationException(String message) {
    super(message);
  }

  /**
   * Constructs a new invalid configuration exception with the specified detail message and cause.
   *
   * @param message the detail message
   * @param cause the cause of this exception
   */
  public InvalidConfigurationException(String message, Throwable cause) {
    super(message, cause);
  }
}
