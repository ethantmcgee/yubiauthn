package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum AttestationType {
  NONE("none"),
  DIRECT("direct"),
  ENTERPRISE("enterprise"),
  INDIRECT("indirect");

  @JsonValue private final String value;
}
