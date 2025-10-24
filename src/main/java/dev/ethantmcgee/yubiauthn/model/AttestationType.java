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
  /** No attestation is requested. */
  NONE("none"),
  /** Direct attestation is requested from the authenticator. */
  DIRECT("direct"),
  /** Enterprise attestation is requested. */
  ENTERPRISE("enterprise"),
  /** Indirect attestation is requested via an anonymization CA. */
  INDIRECT("indirect");

  @JsonValue private final String value;
}
