package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Defines the attestation statement format identifiers.
 *
 * <p>This enum specifies the various attestation formats that authenticators can use to provide
 * cryptographic proof of their characteristics. Each format has a specific structure and
 * verification procedure.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-attestation-formats">W3C WebAuthn -
 *     Attestation Statement Formats</a>
 */
@Getter
@RequiredArgsConstructor
public enum AttestationFormat {
  /** The packed attestation statement format. */
  PACKED("packed"),
  /** The FIDO U2F attestation statement format (legacy). */
  FIDO_U2F("fido-u2f"),
  /** No attestation statement is provided. */
  NONE("none");

  @JsonValue private final String value;
}
