package dev.ethantmcgee.yubiauthn.model;

/**
 * Represents relying party (RP) information for WebAuthn operations.
 *
 * <p>This record models the PublicKeyCredentialRpEntity dictionary from the Web Authentication API.
 * The relying party is the entity whose web application utilizes the Web Authentication API to
 * register and authenticate users.
 *
 * @param id The relying party identifier (typically a domain name)
 * @param name A human-palatable name for the relying party
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API">MDN - Web
 *     Authentication API</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrpentity">W3C WebAuthn
 *     - PublicKeyCredentialRpEntity Dictionary</a>
 */
public record RelyingParty(String id, String name) {
  /**
   * Canonical constructor that validates the relying party information conforms to the WebAuthn
   * specification.
   */
  public RelyingParty {
    if (id == null) {
      throw new IllegalArgumentException("id cannot be null");
    }
    if (name == null) {
      throw new IllegalArgumentException("name cannot be null");
    }
  }
}
