package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonAlias;

/**
 * Represents WebAuthn extension inputs for credential creation and authentication.
 *
 * <p>This record models the AuthenticationExtensionsClientInputs dictionary from the Web Authentication API.
 * Extensions provide additional functionality beyond the core WebAuthn specification, such as
 * credential protection policies and minimum PIN length requirements.
 *
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions">MDN - WebAuthn Extensions</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsclientinputs">W3C WebAuthn - AuthenticationExtensionsClientInputs Dictionary</a>
 */
public record Extensions(
    Boolean credProps,
    @JsonAlias({"credProtect", "credentialProtectionPolicy"})
        CredentialProtectionPolicyType credentialProtectionPolicy,
    @JsonAlias({"enforceCredProtect", "enforceCredentialProtectionPolicy"})
        Boolean enforceCredentialProtectionPolicy,
    Boolean minPinLength) {
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
