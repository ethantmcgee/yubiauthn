package dev.ethantmcgee.yubiauthn.model;

import java.util.List;

/**
 * Options for creating a new WebAuthn credential.
 * This represents the parameters passed from the relying party to the authenticator.
 */
public record PublicKeyCredentialCreationOptions(
    PublicKeyCredentialRpEntity rp,
    PublicKeyCredentialUserEntity user,
    byte[] challenge,
    List<PublicKeyCredentialParameters> pubKeyCredParams,
    Long timeout,
    List<PublicKeyCredentialDescriptor> excludeCredentials,
    AuthenticatorSelectionCriteria authenticatorSelection,
    AttestationConveyancePreference attestation
) {
    public PublicKeyCredentialCreationOptions {
        if (rp == null) {
            throw new IllegalArgumentException("RP must not be null");
        }
        if (user == null) {
            throw new IllegalArgumentException("User must not be null");
        }
        if (challenge == null || challenge.length == 0) {
            throw new IllegalArgumentException("Challenge must not be null or empty");
        }
        if (pubKeyCredParams == null || pubKeyCredParams.isEmpty()) {
            throw new IllegalArgumentException("Public key credential parameters must not be null or empty");
        }
    }
}
