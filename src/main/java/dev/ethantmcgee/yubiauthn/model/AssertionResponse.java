package dev.ethantmcgee.yubiauthn.model;

import java.util.List;

/**
 * Represents the authenticator's response to an authentication assertion request.
 *
 * <p>This record models the AuthenticatorAssertionResponse interface from the Web Authentication
 * API. It contains the signature and related data created during authentication.
 *
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
