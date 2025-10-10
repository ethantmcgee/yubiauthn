package dev.ethantmcgee.yubiauthn.model;

/**
 * Response from authenticator after credential creation.
 */
public record AuthenticatorAttestationResponse(
    byte[] clientDataJSON,
    byte[] attestationObject,
    AuthenticatorTransport[] transports
) {
    public AuthenticatorAttestationResponse {
        if (clientDataJSON == null || clientDataJSON.length == 0) {
            throw new IllegalArgumentException("Client data JSON must not be null or empty");
        }
        if (attestationObject == null || attestationObject.length == 0) {
            throw new IllegalArgumentException("Attestation object must not be null or empty");
        }
    }
}
