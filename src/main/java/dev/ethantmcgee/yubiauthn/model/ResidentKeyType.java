package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Specifies the relying party's requirements for resident key (discoverable credential) creation.
 *
 * <p>This enum models the ResidentKeyRequirement enum from the Web Authentication API. Resident
 * keys (also called discoverable credentials) are stored on the authenticator and can be used
 * without the relying party providing credential IDs.
 *
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API#discoverable_credentials">MDN
 *     - Discoverable Credentials</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#enum-residentKeyRequirement">W3C WebAuthn -
 *     ResidentKeyRequirement Enumeration</a>
 */
@Getter
@RequiredArgsConstructor
public enum ResidentKeyType {
  /** Resident key creation is discouraged. */
  DISCOURAGED("discouraged"),
  /** Resident key creation is preferred but not required. */
  PREFERRED("preferred"),
  /** Resident key creation is required. */
  REQUIRED("required");

  @JsonValue private final String value;
}
