package dev.ethantmcgee.yubiauthn.model;

/**
 * Relying Party entity information for WebAuthn.
 */
public record PublicKeyCredentialRpEntity(
    String id,
    String name
) {
    public PublicKeyCredentialRpEntity {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("RP name must not be null or blank");
        }
    }
}
