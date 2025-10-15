package dev.ethantmcgee.yubiauthn.model;

public record Extensions(
    Boolean credProps,
    CredentialProtectionPolicyType credentialProtectionPolicy,
    Boolean enforceCredentialProtectionPolicy,
    Boolean minPinLength) {
  public Extensions {
    if (credProps == null) {
      credProps = false;
    }
    if (credentialProtectionPolicy == null) {
      credentialProtectionPolicy = CredentialProtectionPolicyType.OPTIONAL;
    }
    if (enforceCredentialProtectionPolicy == null) {
      enforceCredentialProtectionPolicy = false;
    }
    if (minPinLength == null) {
      minPinLength = false;
    }
  }
}
