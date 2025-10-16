package dev.ethantmcgee.yubiauthn.model;

/**
 * Represents the attestation object returned during credential registration.
 *
 * <p>This record contains the attestation format identifier, authenticator data, and attestation
 * statement. The attestation object is used to verify the provenance of an authenticator and its
 * attested credentials.
 *
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/attestationObject">MDN
 *     - attestationObject</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#attestation-object">W3C WebAuthn - Attestation
 *     Object</a>
 */
public record AttestationObject(
    String fmt, AuthenticatorData authData, AttestationStatement attStmt) {
  public AttestationObject {
    if (fmt == null || fmt.isBlank()) {
      throw new IllegalArgumentException("Format must not be null or blank");
    }
    if (authData == null) {
      throw new IllegalArgumentException("Authenticator data must not be null");
    }
    if (attStmt == null) {
      throw new IllegalArgumentException("Attestation statement must not be null");
    }
  }
}
