package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Describes the authenticator's attachment modality.
 *
 * <p>This enum models the AuthenticatorAttachment enum from the Web Authentication API.
 * It indicates whether the authenticator is platform-attached (built into the device)
 * or cross-platform (removable and usable across devices).
 *
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/authenticatorAttachment">MDN - authenticatorAttachment</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#enum-attachment">W3C WebAuthn - AuthenticatorAttachment Enumeration</a>
 */
@Getter
@RequiredArgsConstructor
public enum AuthenticatorAttachmentType {
  PLATFORM("platform"),
  CROSS_PLATFORM("cross-platform");

  @JsonValue private final String value;
}
