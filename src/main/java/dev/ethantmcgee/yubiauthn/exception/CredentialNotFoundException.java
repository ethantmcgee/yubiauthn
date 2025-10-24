package dev.ethantmcgee.yubiauthn.exception;

public class CredentialNotFoundException extends RuntimeException {
  public CredentialNotFoundException(String message) {
    super(message);
  }
}
