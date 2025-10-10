package dev.ethantmcgee.yubiauthn.model;

import java.util.List;

/**
 * Options for requesting authentication with an existing WebAuthn credential.
 */
public record PublicKeyCredentialRequestOptions(
    byte[] challenge,
    Long timeout,
    String rpId,
    List<PublicKeyCredentialDescriptor> allowCredentials,
    UserVerificationRequirement userVerification
) {
    public PublicKeyCredentialRequestOptions {
        if (challenge == null || challenge.length == 0) {
            throw new IllegalArgumentException("Challenge must not be null or empty");
        }
    }
}
