package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum CredentialProtectionPolicyType {
  OPTIONAL("userVerificationOptional"),
  WITH_ID_LIST("userVerificationOptionalWithCredentialIDList"),
  REQUIRED("userVerificationRequired");

  @JsonValue private final String value;
}
