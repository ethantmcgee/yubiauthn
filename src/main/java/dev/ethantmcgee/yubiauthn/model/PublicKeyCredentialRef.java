package dev.ethantmcgee.yubiauthn.model;

import java.util.List;

/**
 * Describes a credential for WebAuthn operations.
 *
 * <p>This record models the PublicKeyCredentialDescriptor dictionary from the Web Authentication
 * API. It is used to identify and describe credentials, particularly in allowCredentials and
 * excludeCredentials lists.
 *
 * @param id The credential ID (base64url-encoded)
 * @param transports The list of transport types supported by the authenticator for this credential
 * @param type The type of credential (typically "public-key")
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialDescriptor">MDN
 *     - PublicKeyCredentialDescriptor</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialdescriptor">W3C
 *     WebAuthn - PublicKeyCredentialDescriptor Dictionary</a>
 */
public record PublicKeyCredentialRef(
    String id, List<TransportType> transports, CredentialType type) {
  /**
   * Canonical constructor that validates the credential descriptor conforms to the WebAuthn
   * specification.
   */
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
