package dev.ethantmcgee.yubiauthn.model;

import java.util.List;

public record PublicKeyCredentialCreationOptions(
    AttestationType attestation,
    List<AttestationType> attestationFormats,
    AuthenticatorSelection authenticatorSelection,
    String challenge,
    List<PublicKeyCredentialRef> excludeCredentials,
    Extensions extensions,
    List<HintType> hints,
    List<PublicKeyParameterType> pubKeyCredParams,
    RelyingParty rp,
    Integer timeout,
    User user) {
  public PublicKeyCredentialCreationOptions {
    if (attestation == null) {
      attestation = AttestationType.NONE;
    }
    if (attestationFormats == null) {
      attestationFormats = List.of();
    }
    if (authenticatorSelection == null) {
      authenticatorSelection = new AuthenticatorSelection(null, false, null, null);
    }
    if (challenge == null) {
      throw new IllegalArgumentException("challenge cannot be null");
    }
    if (excludeCredentials == null) {
      excludeCredentials = List.of();
    }
    if (extensions == null) {
      extensions = new Extensions(null, null, null, null);
    }
    if (hints == null) {
      hints = List.of();
    }
    if (pubKeyCredParams == null) {
      pubKeyCredParams = List.of();
    }
    if (rp == null) {
      throw new IllegalArgumentException("rp cannot be null");
    }
    if (timeout == null) {
      timeout = 60000;
    }
    if (user == null) {
      throw new IllegalArgumentException("user cannot be null");
    }
  }
}
