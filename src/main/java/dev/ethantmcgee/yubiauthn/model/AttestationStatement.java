package dev.ethantmcgee.yubiauthn.model;

/**
 * Represents the attestation statement within an attestation object.
 *
 * <p>The attestation statement contains cryptographic proof of the authenticator's characteristics
 * and is specific to the attestation format being used. This implementation represents the packed
 * attestation format which is commonly used.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement">W3C WebAuthn - Attestation
 *     Statement</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C WebAuthn - Packed
 *     Attestation Format</a>
 */
public record AttestationStatement(byte[] sig, byte[][] x5c, COSEAlgorithmIdentifier alg) {
  public AttestationStatement {
    if (sig == null || sig.length == 0) {
      throw new IllegalArgumentException("Signature must not be null or empty");
    }
  }
}
