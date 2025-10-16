package dev.ethantmcgee.yubiauthn.model;

import java.util.List;

/**
 * Describes a credential for WebAuthn operations.
 *
 * <p>This record models the PublicKeyCredentialDescriptor dictionary from the Web Authentication
 * API. It is used to identify and describe credentials, particularly in allowCredentials and
 * excludeCredentials lists.
 *
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialDescriptor">MDN
 *     - PublicKeyCredentialDescriptor</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialdescriptor">W3C
 *     WebAuthn - PublicKeyCredentialDescriptor Dictionary</a>
 */
public record PublicKeyCredentialRef(
    String id, List<TransportType> transports, CredentialType type) {
  public PublicKeyCredentialRef {
    if (id == null) {
      throw new IllegalArgumentException("id cannot be null");
    }
    if (transports == null) {
      transports = List.of();
    }
    if (type == null) {
      type = CredentialType.PUBLIC_KEY;
    }
  }
}
