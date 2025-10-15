package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum HintType {
  SECURITY_KEY("security-key"),
  CLIENT_DEVICE("client-device"),
  HYBRID("hybrid");

  @JsonValue private final String value;
}
