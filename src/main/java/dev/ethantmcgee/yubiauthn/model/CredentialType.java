package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Defines the type of credential.
 *
 * <p>This enum models the PublicKeyCredentialType enum from the Web Authentication API. Currently,
 * "public-key" is the only defined credential type for WebAuthn.
 *
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/type">MDN -
 *     PublicKeyCredential.type</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialtype">W3C WebAuthn -
 *     PublicKeyCredentialType Enumeration</a>
 */
@Getter
@RequiredArgsConstructor
public enum CredentialType {
  PUBLIC_KEY("public-key");

  @JsonValue private final String value;
}
