package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum UserVerificationType {
  DISCOURAGED("discouraged"),
  PREFERRED("preferred"),
  REQUIRED("required");

  @JsonValue private final String value;
}
