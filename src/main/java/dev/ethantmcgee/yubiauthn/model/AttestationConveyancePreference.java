package dev.ethantmcgee.yubiauthn.model;

/**
 * Attestation conveyance preference for WebAuthn credential creation.
 */
public enum AttestationConveyancePreference {
    NONE("none"),
    INDIRECT("indirect"),
    DIRECT("direct"),
    ENTERPRISE("enterprise");

    private final String value;

    AttestationConveyancePreference(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
