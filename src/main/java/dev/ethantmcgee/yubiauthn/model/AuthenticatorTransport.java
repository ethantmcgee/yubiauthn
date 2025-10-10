package dev.ethantmcgee.yubiauthn.model;

/**
 * Authenticator transport types.
 */
public enum AuthenticatorTransport {
    USB("usb"),
    NFC("nfc"),
    BLE("ble"),
    INTERNAL("internal"),
    HYBRID("hybrid");

    private final String value;

    AuthenticatorTransport(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
