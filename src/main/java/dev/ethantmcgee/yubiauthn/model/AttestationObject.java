package dev.ethantmcgee.yubiauthn.model;

/**
 * Attestation object containing the authenticator data and attestation statement.
 * This is the core data structure returned during credential creation.
 */
public record AttestationObject(
    String fmt,
    AuthenticatorData authData,
    AttestationStatement attStmt
) {
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

    /**
     * Attestation statement containing the signature and certificates.
     */
    public record AttestationStatement(
        byte[] sig,
        byte[][] x5c,
        COSEAlgorithmIdentifier alg
    ) {
        public AttestationStatement {
            if (sig == null || sig.length == 0) {
                throw new IllegalArgumentException("Signature must not be null or empty");
            }
        }
    }
}
