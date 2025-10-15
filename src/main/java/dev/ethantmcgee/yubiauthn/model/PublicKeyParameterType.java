package dev.ethantmcgee.yubiauthn.model;

public record PublicKeyParameterType(COSEAlgorithmIdentifier alg, CredentialType type) {
  public PublicKeyParameterType {
    if (alg == null) {
      throw new IllegalArgumentException("alg cannot be null");
    }
    if (type == null) {
      type = CredentialType.PUBLIC_KEY;
    }
  }
}
