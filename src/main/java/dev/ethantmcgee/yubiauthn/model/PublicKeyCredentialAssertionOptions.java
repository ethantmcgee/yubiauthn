package dev.ethantmcgee.yubiauthn.model;

import java.util.List;

/**
 * Options for requesting an authentication assertion during WebAuthn authentication.
 *
 * <p>This record models the PublicKeyCredentialRequestOptions dictionary from the Web Authentication API.
 * It contains the parameters needed to guide the authentication process, including the challenge,
 * allowed credentials, and user verification requirements.
 *
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get#publickey_object_structure">MDN - PublicKeyCredentialRequestOptions</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions">W3C WebAuthn - PublicKeyCredentialRequestOptions Dictionary</a>
 */
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
