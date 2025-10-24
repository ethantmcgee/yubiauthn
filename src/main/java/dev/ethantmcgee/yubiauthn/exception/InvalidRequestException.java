package dev.ethantmcgee.yubiauthn.exception;

public class InvalidRequestException extends RuntimeException {
  public InvalidRequestException(String message) {
    super(message);
  }
}
