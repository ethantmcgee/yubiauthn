package dev.ethantmcgee.yubiauthn.model;

/**
 * Represents WebAuthn extension outputs returned by the authenticator.
 *
 * <p>This record models the AuthenticationExtensionsClientOutputs dictionary from the Web
 * Authentication API. It contains the results of processing extension inputs during credential
 * creation or authentication.
 *
 * @param credProps The result of the credProps extension
 * @param credProtect The credential protection policy level that was set
 * @param minPinLength The minimum PIN length supported by the authenticator
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions">MDN
 *     - WebAuthn Extensions</a>
 * @see <a
 *     href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsclientoutputs">W3C
 *     WebAuthn - AuthenticationExtensionsClientOutputs Dictionary</a>
 */
public record ExtensionResults(
    CredPropsResult credProps, Integer credProtect, Integer minPinLength) {}
