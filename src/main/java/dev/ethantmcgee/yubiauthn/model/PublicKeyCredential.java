package dev.ethantmcgee.yubiauthn.model;

public record PublicKeyCredential(
    AuthenticatorAttachmentType authenticatorAttachment,
    String id,
    String rawId,
    AuthenticatorResponse response,
    CredentialType type,
    ExtensionResults clientExtensionResults
) {
  public PublicKeyCredential {
    if (authenticatorAttachment == null) {
      authenticatorAttachment = AuthenticatorAttachmentType.PLATFORM;
    }
    if (id == null) {
      throw new IllegalArgumentException("id cannot be null");
    }
    if (rawId == null) {
      throw new IllegalArgumentException("rawId cannot be null");
    }
    if (response == null) {
      throw new IllegalArgumentException("response cannot be null");
    }
    if (type == null) {
      type = CredentialType.PUBLIC_KEY;
    }
    if(clientExtensionResults == null) {
        clientExtensionResults = new ExtensionResults(null, null, null);
    }
  }

  public String toJson() {
    return "{}";
  }
}
