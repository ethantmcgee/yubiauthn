package dev.ethantmcgee.yubiauthn.model;

public record AuthenticatorSelection(
    AuthenticatorAttachmentType authenticatorAttachment,
    Boolean requireResidentKey,
    ResidentKeyType residentKey,
    UserVerificationType userVerification) {
  public AuthenticatorSelection {
    if (authenticatorAttachment == null) {
      authenticatorAttachment = AuthenticatorAttachmentType.ANY;
    }
    if (requireResidentKey == null) {
      requireResidentKey = false;
    }
    if (residentKey == null) {
      residentKey = requireResidentKey ? ResidentKeyType.REQUIRED : ResidentKeyType.DISCOURAGED;
    }
    if (userVerification == null) {
      userVerification = UserVerificationType.PREFERRED;
    }
  }
}
