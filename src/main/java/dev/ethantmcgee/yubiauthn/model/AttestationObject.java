package dev.ethantmcgee.yubiauthn.model;

/**
 * Represents the attestation object returned during credential registration.
 *
 * <p>This record contains the attestation format identifier, authenticator data, and attestation
 * statement. The attestation object is used to verify the provenance of an authenticator and its
 * attested credentials.
 *
 * @param fmt The attestation format identifier (e.g., "packed", "fido-u2f", "none")
 * @param authData The authenticator data containing the credential public key and other information
 * @param attStmt The attestation statement containing cryptographic proof
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/attestationObject">MDN
 *     - attestationObject</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#attestation-object">W3C WebAuthn - Attestation
 *     Object</a>
 */
public record AttestationObject(
    AttestationFormat fmt, AuthenticatorData authData, AttestationStatement attStmt) {
  /**
   * Canonical constructor that validates the attestation object conforms to the WebAuthn
   * specification.
   */
  public AttestationObject {
    if (fmt == null) {
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
