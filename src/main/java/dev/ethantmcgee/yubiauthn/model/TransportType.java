package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum TransportType {
  BLE("ble"),
  HYBRID("hybrid"),
  INTERNAL("internal"),
  NFC("nfc"),
  USB("usb");

  @JsonValue private final String value;
}
