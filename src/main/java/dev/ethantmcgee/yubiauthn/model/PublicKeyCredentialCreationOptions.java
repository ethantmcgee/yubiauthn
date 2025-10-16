package dev.ethantmcgee.yubiauthn.model;

import java.util.List;

/**
 * Options for creating a new credential during WebAuthn registration.
 *
 * <p>This record models the PublicKeyCredentialCreationOptions dictionary from the Web
 * Authentication API. It contains the parameters needed to guide the credential creation process,
 * including relying party information, user information, challenge, and various options controlling
 * the authenticator behavior.
 *
 * @param attestation The relying party's preference for attestation conveyance
 * @param attestationFormats The preferred attestation formats
 * @param authenticatorSelection Criteria for selecting authenticators
 * @param challenge The challenge (random bytes from server) to be signed
 * @param excludeCredentials Credentials to exclude from the creation process
 * @param extensions Extension inputs for credential creation
 * @param hints Hints to guide the user agent in selecting authenticators
 * @param pubKeyCredParams Acceptable credential types and algorithms
 * @param rp Relying party information
 * @param timeout Timeout in milliseconds for the operation
 * @param user User account information
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create#publickey_object_structure">MDN
 *     - PublicKeyCredentialCreationOptions</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptions">W3C
 *     WebAuthn - PublicKeyCredentialCreationOptions Dictionary</a>
 */
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
  // validate that the assertion response conforms to specification
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
