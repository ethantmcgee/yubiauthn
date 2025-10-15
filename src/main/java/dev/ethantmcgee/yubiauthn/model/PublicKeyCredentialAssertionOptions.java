package dev.ethantmcgee.yubiauthn.model;

import java.util.List;

public record PublicKeyCredentialAssertionOptions(
    List<PublicKeyCredentialRef> allowCredentials,
    String challenge,
    List<HintType> hints,
    String rpId,
    Integer timeout,
    UserVerificationType userVerification) {
  public PublicKeyCredentialAssertionOptions {
    if (allowCredentials == null) {
      allowCredentials = List.of();
    }
    if (challenge == null) {
      throw new IllegalArgumentException("challenge cannot be null");
    }
    if (hints == null) {
      hints = List.of();
    }
    if (rpId == null) {
      throw new IllegalArgumentException("rpId cannot be null");
    }
    if (timeout == null) {
      timeout = 60000;
    }
    if (userVerification == null) {
      userVerification = UserVerificationType.PREFERRED;
    }
  }
}
