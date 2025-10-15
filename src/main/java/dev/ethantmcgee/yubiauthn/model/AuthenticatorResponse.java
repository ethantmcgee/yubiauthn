package dev.ethantmcgee.yubiauthn.model;

import java.util.List;

public record AuthenticatorResponse(
    String clientDataJSON,
    String attestationObject,
    List<TransportType> transports,
    AuthenticatorData authenticatorData,
    String publicKey,
    COSEAlgorithmIdentifier publicKeyAlgorithm) {
  public AuthenticatorResponse {
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
    if (publicKey == null) {
      throw new IllegalArgumentException("publicKey cannot be null");
    }
    if (publicKeyAlgorithm == null) {
      throw new IllegalArgumentException("publicKeyAlgorithm cannot be null");
    }
  }
}
