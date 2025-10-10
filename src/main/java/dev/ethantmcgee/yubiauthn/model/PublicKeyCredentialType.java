package dev.ethantmcgee.yubiauthn.model;

/**
 * Credential type for WebAuthn.
 * Currently only "public-key" is defined in the specification.
 */
public enum PublicKeyCredentialType {
    PUBLIC_KEY("public-key");

    private final String value;

    PublicKeyCredentialType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
