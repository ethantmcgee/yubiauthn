package dev.ethantmcgee.yubiauthn.model;

import java.util.List;

public record PublicKeyCredentialRef(
    String id, List<TransportType> transports, CredentialType type) {
  public PublicKeyCredentialRef {
    if (id == null) {
      throw new IllegalArgumentException("id cannot be null");
    }
    if (transports == null) {
      transports = List.of();
    }
    if (type == null) {
      type = CredentialType.PUBLIC_KEY;
    }
  }
}
