package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Provides hints to help the user agent select appropriate authenticators.
 *
 * <p>This enum models the PublicKeyCredentialHints enum from the Web Authentication API.
 * Hints guide the user experience by suggesting which type of authenticator to use.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#enum-hints">W3C WebAuthn - PublicKeyCredentialHints Enumeration</a>
 */
@Getter
@RequiredArgsConstructor
public enum HintType {
  SECURITY_KEY("security-key"),
  CLIENT_DEVICE("client-device"),
  HYBRID("hybrid");

  @JsonValue private final String value;
}
