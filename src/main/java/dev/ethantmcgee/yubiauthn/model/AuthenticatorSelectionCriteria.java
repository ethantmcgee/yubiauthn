package dev.ethantmcgee.yubiauthn.model;

/**
 * Authenticator selection criteria for credential creation.
 */
public record AuthenticatorSelectionCriteria(
    AuthenticatorAttachment authenticatorAttachment,
    Boolean requireResidentKey,
    String residentKey,
    UserVerificationRequirement userVerification
) {
    public enum AuthenticatorAttachment {
        PLATFORM("platform"),
        CROSS_PLATFORM("cross-platform");

        private final String value;

        AuthenticatorAttachment(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }
}
