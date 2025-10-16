package dev.ethantmcgee.yubiauthn.model;

/**
 * Result of the credProps extension.
 *
 * <p>The credProps extension returns information about the properties of the created credential,
 * specifically whether it is a resident key (discoverable credential).
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension">W3C WebAuthn - Credential Properties Extension</a>
 */
public record CredPropsResult(Boolean rk) {}
