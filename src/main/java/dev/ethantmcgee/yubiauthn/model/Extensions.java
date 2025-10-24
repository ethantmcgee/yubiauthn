package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonAlias;

/**
 * Represents WebAuthn extension inputs for credential creation and authentication.
 *
 * <p>This record models the AuthenticationExtensionsClientInputs dictionary from the Web
 * Authentication API. Extensions provide additional functionality beyond the core WebAuthn
 * specification, such as credential protection policies and minimum PIN length requirements.
 *
 * @param credProps Whether to enable the credProps extension
 * @param credentialProtectionPolicy The credential protection policy level to enforce
 * @param enforceCredentialProtectionPolicy Whether to enforce the credential protection policy
 * @param minPinLength Whether to enable the minPinLength extension
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions">MDN
 *     - WebAuthn Extensions</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsclientinputs">W3C
 *     WebAuthn - AuthenticationExtensionsClientInputs Dictionary</a>
 */
public record Extensions(
    Boolean credProps,
    @JsonAlias({"credProtect", "credentialProtectionPolicy"})
        CredentialProtectionPolicyType credentialProtectionPolicy,
    @JsonAlias({"enforceCredProtect", "enforceCredentialProtectionPolicy"})
        Boolean enforceCredentialProtectionPolicy,
    Boolean minPinLength) {
  /**
   * Canonical constructor that validates and normalizes extension inputs according to the WebAuthn
   * specification.
   */
  public Extensions {
    if (credProps == null) {
      credProps = false;
    }
    if (enforceCredentialProtectionPolicy == null) {
      enforceCredentialProtectionPolicy = false;
    }
    if (minPinLength == null) {
      minPinLength = false;
    }
  }
}
