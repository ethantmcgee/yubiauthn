package dev.ethantmcgee.yubiauthn.model;

import java.util.List;

/**
 * Descriptor for an existing public key credential.
 */
public record PublicKeyCredentialDescriptor(
    PublicKeyCredentialType type,
    byte[] id,
    List<AuthenticatorTransport> transports
) {
    public PublicKeyCredentialDescriptor {
        if (type == null) {
            throw new IllegalArgumentException("Type must not be null");
        }
        if (id == null || id.length == 0) {
            throw new IllegalArgumentException("Credential ID must not be null or empty");
        }
    }
}
