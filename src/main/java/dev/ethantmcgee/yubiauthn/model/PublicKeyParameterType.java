package dev.ethantmcgee.yubiauthn.model;

/**
 * Describes the desired properties of a credential to be created.
 *
 * <p>This record models the PublicKeyCredentialParameters dictionary from the Web Authentication
 * API. It specifies the type of credential and the cryptographic signature algorithm that will be
 * used with it.
 *
 * @param alg The COSE algorithm identifier for the credential
 * @param type The type of credential (typically "public-key")
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialparameters">W3C
 *     WebAuthn - PublicKeyCredentialParameters Dictionary</a>
 */
public record PublicKeyParameterType(COSEAlgorithmIdentifier alg, CredentialType type) {
  // validate that the assertion response conforms to specification
  public PublicKeyParameterType {
    if (alg == null) {
      throw new IllegalArgumentException("alg cannot be null");
    }
    if (type == null) {
      type = CredentialType.PUBLIC_KEY;
    }
  }
}
