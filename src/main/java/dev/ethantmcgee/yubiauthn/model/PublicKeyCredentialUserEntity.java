package dev.ethantmcgee.yubiauthn.model;

/**
 * User entity information for WebAuthn.
 */
public record PublicKeyCredentialUserEntity(
    byte[] id,
    String name,
    String displayName
) {
    public PublicKeyCredentialUserEntity {
        if (id == null || id.length == 0) {
            throw new IllegalArgumentException("User ID must not be null or empty");
        }
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("User name must not be null or blank");
        }
        if (displayName == null || displayName.isBlank()) {
            throw new IllegalArgumentException("User display name must not be null or blank");
        }
    }
}
