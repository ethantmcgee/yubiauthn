package dev.ethantmcgee.yubiauthn.model;

/**
 * Represents user account information for WebAuthn credential creation.
 *
 * <p>This record models the PublicKeyCredentialUserEntity dictionary from the Web Authentication
 * API. It contains information about the user account for which a credential is being created.
 *
 * @param displayName A human-palatable name for the user account, intended for display
 * @param id A unique identifier for the user account (user handle)
 * @param name A human-palatable identifier for the user account (e.g., username or email)
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions">MDN
 *     - User Entity</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentity">W3C
 *     WebAuthn - PublicKeyCredentialUserEntity Dictionary</a>
 */
public record User(String displayName, String id, String name) {
  // validate that the assertion response conforms to specification
  public User {
    if (displayName == null) {
      throw new IllegalArgumentException("displayName cannot be null");
    }
    if (id == null) {
      throw new IllegalArgumentException("id cannot be null");
    }
    if (name == null) {
      throw new IllegalArgumentException("name cannot be null");
    }
  }
}
