package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Specifies the relying party's requirements for user verification.
 *
 * <p>This enum models the UserVerificationRequirement enum from the Web Authentication API. User
 * verification ensures that the person authenticating is indeed the owner of the credential,
 * typically through biometrics, PIN, or password.
 *
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions#user_verification">MDN
 *     - User Verification</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#enum-userVerificationRequirement">W3C WebAuthn -
 *     UserVerificationRequirement Enumeration</a>
 */
@Getter
@RequiredArgsConstructor
public enum UserVerificationType {
  /** User verification is discouraged. */
  DISCOURAGED("discouraged"),
  /** User verification is preferred but not required. */
  PREFERRED("preferred"),
  /** User verification is required. */
  REQUIRED("required");

  @JsonValue private final String value;
}
