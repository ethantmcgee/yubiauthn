package dev.ethantmcgee.yubiauthn.model;

/**
 * Represents the attestation statement within an attestation object.
 *
 * <p>The attestation statement contains cryptographic proof of the authenticator's characteristics
 * and is specific to the attestation format being used. This implementation represents the packed
 * attestation format which is commonly used.
 *
 * @param sig The attestation signature
 * @param x5c The attestation certificate chain (optional, may be null)
 * @param alg The COSE algorithm identifier used for the signature (optional, may be null)
 * @see <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement">W3C WebAuthn - Attestation
 *     Statement</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C WebAuthn - Packed
 *     Attestation Format</a>
 */
public record AttestationStatement(byte[] sig, byte[] x5c, COSEAlgorithmIdentifier alg) {
  /**
   * Canonical constructor that validates the attestation statement conforms to the WebAuthn
   * specification.
   *
   * <p>Note: For NONE attestation format, the signature may be an empty array.
   */
  public AttestationStatement {
    if (sig == null) {
      throw new IllegalArgumentException("Signature must not be null");
    }
  }
}
