package dev.ethantmcgee.yubiauthn.exception;

/** Thrown when a requested credential cannot be found. */
public class CredentialNotFoundException extends AuthenticatorException {
  public CredentialNotFoundException(String message) {
    super(message);
  }

  public CredentialNotFoundException(String message, Throwable cause) {
    super(message, cause);
  }
}
