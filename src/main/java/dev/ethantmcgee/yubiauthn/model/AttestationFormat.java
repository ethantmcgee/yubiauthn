package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum AttestationFormat {
  PACKED("packed"),
  TPM("tpm"),
  ANDROID_KEY("android-key"),
  ANDROID_SAFETY_NET("android-safetynet"),
  FIDO_U2F("fido-u2f"),
  APPLE("apple"),
  NONE("none");

  @JsonValue private final String value;
}
