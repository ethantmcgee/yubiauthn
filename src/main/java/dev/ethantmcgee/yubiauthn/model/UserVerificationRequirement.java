package dev.ethantmcgee.yubiauthn.model;

/**
 * User verification requirement for WebAuthn operations.
 */
public enum UserVerificationRequirement {
    REQUIRED("required"),
    PREFERRED("preferred"),
    DISCOURAGED("discouraged");

    private final String value;

    UserVerificationRequirement(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
