package dev.ethantmcgee.yubiauthn.model;

import java.util.List;

/**
 * Represents the authenticator's response to an authentication assertion request.
 *
 * <p>This record models the AuthenticatorAssertionResponse interface from the Web Authentication
 * API. It contains the signature and related data created during authentication.
 *
 * @param clientDataJSON The JSON-serialized client data passed to the authenticator
 * @param transports The list of transport types supported by the authenticator
 * @param authenticatorData The authenticator data containing flags and signature counter
 * @param publicKeyAlgorithm The algorithm used to generate the assertion signature
 * @param signature The assertion signature over the authenticator data and client data hash
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse">MDN -
 *     AuthenticatorAssertionResponse</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#iface-authenticatorassertionresponse">W3C
 *     WebAuthn - AuthenticatorAssertionResponse Interface</a>
 */
public record AssertionResponse(
    String clientDataJSON,
    List<TransportType> transports,
    AuthenticatorData authenticatorData,
    COSEAlgorithmIdentifier publicKeyAlgorithm,
    String signature) {
  // validate that the assertion response conforms to specification
  public AssertionResponse {
    if (clientDataJSON == null) {
      throw new IllegalArgumentException("clientDataJSON cannot be null");
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
    if (signature == null) {
      throw new IllegalArgumentException("signature cannot be null");
    }
  }
}
