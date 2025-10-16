package dev.ethantmcgee.yubiauthn.model;

/**
 * Criteria for selecting authenticators during credential creation.
 *
 * <p>This record models the AuthenticatorSelectionCriteria dictionary from the Web Authentication API.
 * It allows relying parties to specify requirements for the authenticators that may be used for
 * credential creation, such as attachment type and user verification requirements.
 *
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_selection">MDN - Authenticator Selection</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorselectioncriteria">W3C WebAuthn - AuthenticatorSelectionCriteria Dictionary</a>
 */
public record AuthenticatorSelection(
    AuthenticatorAttachmentType authenticatorAttachment,
    Boolean requireResidentKey,
    ResidentKeyType residentKey,
    UserVerificationType userVerification) {
  public AuthenticatorSelection {
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
