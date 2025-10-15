package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum AuthenticatorAttachmentType {
  PLATFORM("platform"),
  CROSS_PLATFORM("cross-platform"),
  ANY("any");

  @JsonValue private final String value;
}
