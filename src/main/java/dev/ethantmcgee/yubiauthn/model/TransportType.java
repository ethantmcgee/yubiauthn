package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Defines the transport mechanisms supported by an authenticator.
 *
 * <p>This enum models the AuthenticatorTransport enum from the Web Authentication API.
 * It describes how the client communicates with the authenticator (e.g., USB, NFC, Bluetooth).
 *
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialDescriptor#transports">MDN - transports</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#enum-transport">W3C WebAuthn - AuthenticatorTransport Enumeration</a>
 */
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
