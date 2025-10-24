package dev.ethantmcgee.yubiauthn.exception;

/**
 * Exception thrown when the YubiKeyEmulator is configured with invalid parameters.
 *
 * <p>This exception indicates that the emulator cannot be initialized or used due to incorrect or
 * incompatible configuration settings.
 */
public class InvalidConfigurationException extends RuntimeException {
  /**
   * Constructs a new InvalidConfigurationException with the specified detail message.
   *
   * @param message the detail message explaining the configuration error
   */
  public InvalidConfigurationException(String message) {
    super(message);
  }
}
