package dev.ethantmcgee.yubiauthn.model;

/**
 * COSE Algorithm Identifiers as defined in RFC 8152.
 * Used to specify which cryptographic algorithm to use for credential creation.
 */
public enum COSEAlgorithmIdentifier {
    ES256(-7),    // ECDSA with SHA-256
    ES384(-35),   // ECDSA with SHA-384
    ES512(-36),   // ECDSA with SHA-512
    RS256(-257),  // RSASSA-PKCS1-v1_5 with SHA-256
    RS384(-258),  // RSASSA-PKCS1-v1_5 with SHA-384
    RS512(-259),  // RSASSA-PKCS1-v1_5 with SHA-512
    EdDSA(-8);    // EdDSA

    private final int value;

    COSEAlgorithmIdentifier(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static COSEAlgorithmIdentifier fromValue(int value) {
        for (COSEAlgorithmIdentifier alg : values()) {
            if (alg.value == value) {
                return alg;
            }
        }
        throw new IllegalArgumentException("Unknown COSE algorithm identifier: " + value);
    }
}
