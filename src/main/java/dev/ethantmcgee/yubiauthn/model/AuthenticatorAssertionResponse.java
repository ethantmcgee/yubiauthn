package dev.ethantmcgee.yubiauthn.model;

/**
 * Response from authenticator after authentication/assertion.
 */
public record AuthenticatorAssertionResponse(
    byte[] clientDataJSON,
    byte[] authenticatorData,
    byte[] signature,
    byte[] userHandle
) {
    public AuthenticatorAssertionResponse {
        if (clientDataJSON == null || clientDataJSON.length == 0) {
            throw new IllegalArgumentException("Client data JSON must not be null or empty");
        }
        if (authenticatorData == null || authenticatorData.length == 0) {
            throw new IllegalArgumentException("Authenticator data must not be null or empty");
        }
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature must not be null or empty");
        }
    }
}
