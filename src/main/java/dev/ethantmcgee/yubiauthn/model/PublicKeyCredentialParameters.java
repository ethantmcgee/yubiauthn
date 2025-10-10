package dev.ethantmcgee.yubiauthn.model;

/**
 * Parameters for credential creation specifying the type and algorithm.
 */
public record PublicKeyCredentialParameters(
    PublicKeyCredentialType type,
    COSEAlgorithmIdentifier alg
) {
    public PublicKeyCredentialParameters {
        if (type == null || alg == null) {
            throw new IllegalArgumentException("Type and algorithm must not be null");
        }
    }
}
