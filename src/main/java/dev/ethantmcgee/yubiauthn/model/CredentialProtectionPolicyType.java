package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Defines the credential protection policy for the credProtect extension.
 *
 * <p>This enum specifies the level of user verification required to use a credential. It is part of
 * the FIDO2 credProtect extension which allows relying parties to specify how credentials should be
 * protected.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-credProtect-extension">FIDO2
 *     - credProtect Extension</a>
 */
@Getter
@RequiredArgsConstructor
public enum CredentialProtectionPolicyType {
  /** User verification is optional. */
  OPTIONAL("userVerificationOptional", 1),
  /** User verification is optional with credential ID list. */
  WITH_ID_LIST("userVerificationOptionalWithCredentialIDList", 2),
  /** User verification is required. */
  REQUIRED("userVerificationRequired", 3);

  @JsonValue private final String value;
  private final Integer responseValue;
}
