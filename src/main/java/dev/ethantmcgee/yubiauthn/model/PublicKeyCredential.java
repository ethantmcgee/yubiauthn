package dev.ethantmcgee.yubiauthn.model;

/**
 * Public key credential returned from the authenticator.
 * This is the top-level object returned to the relying party.
 */
public record PublicKeyCredential<T>(
    byte[] id,
    String type,
    byte[] rawId,
    T response,
    AuthenticatorAttachment authenticatorAttachment
) {
    public PublicKeyCredential {
        if (id == null || id.length == 0) {
            throw new IllegalArgumentException("ID must not be null or empty");
        }
        if (type == null || type.isBlank()) {
            throw new IllegalArgumentException("Type must not be null or blank");
        }
        if (rawId == null || rawId.length == 0) {
            throw new IllegalArgumentException("Raw ID must not be null or empty");
        }
        if (response == null) {
            throw new IllegalArgumentException("Response must not be null");
        }
    }

    public enum AuthenticatorAttachment {
        PLATFORM,
        CROSS_PLATFORM
    }
}
