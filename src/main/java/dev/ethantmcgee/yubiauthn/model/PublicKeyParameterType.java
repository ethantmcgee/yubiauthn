package dev.ethantmcgee.yubiauthn.model;

/**
 * Describes the desired properties of a credential to be created.
 *
 * <p>This record models the PublicKeyCredentialParameters dictionary from the Web Authentication API.
 * It specifies the type of credential and the cryptographic signature algorithm that will be used with it.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialparameters">W3C WebAuthn - PublicKeyCredentialParameters Dictionary</a>
 */
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
