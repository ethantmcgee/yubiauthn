package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Specifies the relying party's preference for attestation conveyance.
 *
 * <p>This enum models the AttestationConveyancePreference enum from the Web Authentication API.
 * Attestation provides cryptographic proof of the authenticator's characteristics and provenance.
 *
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#attestation">MDN
 *     - attestation</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#enum-attestation-convey">W3C WebAuthn -
 *     AttestationConveyancePreference Enumeration</a>
 */
@Getter
@RequiredArgsConstructor
public enum AttestationType {
  NONE("none"),
  DIRECT("direct"),
  ENTERPRISE("enterprise"),
  INDIRECT("indirect");

  @JsonValue private final String value;
}
