package dev.ethantmcgee.yubiauthn.model;

import java.util.List;

/**
 * Represents the authenticator's response to a credential registration request.
 *
 * <p>This record models the AuthenticatorAttestationResponse interface from the Web Authentication
 * API. It contains the attestation object and related data created during credential registration.
 *
 * @param clientDataJSON The JSON-serialized client data passed to the authenticator
 * @param attestationObject The attestation object containing the authenticator data and attestation
 *     statement
 * @param transports The list of transport types supported by the authenticator
 * @param authenticatorData The parsed authenticator data containing the credential public key
 * @param publicKeyAlgorithm The algorithm identifier for the credential public key
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse">MDN
 *     - AuthenticatorAttestationResponse</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#iface-authenticatorattestationresponse">W3C
 *     WebAuthn - AuthenticatorAttestationResponse Interface</a>
 */
public record RegistrationResponse(
    String clientDataJSON,
    String attestationObject,
    List<TransportType> transports,
    AuthenticatorData authenticatorData,
    COSEAlgorithmIdentifier publicKeyAlgorithm) {
  public RegistrationResponse {
    if (clientDataJSON == null) {
      throw new IllegalArgumentException("clientDataJSON cannot be null");
    }
    if (attestationObject == null) {
      throw new IllegalArgumentException("attestationObject cannot be null");
    }
    if (transports == null) {
      transports = List.of();
    }
    if (authenticatorData == null) {
      throw new IllegalArgumentException("authenticatorData cannot be null");
    }
    if (publicKeyAlgorithm == null) {
      throw new IllegalArgumentException("publicKeyAlgorithm cannot be null");
    }
  }
}
