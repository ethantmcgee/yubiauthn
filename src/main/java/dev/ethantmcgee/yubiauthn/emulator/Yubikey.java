package dev.ethantmcgee.yubiauthn.emulator;

import dev.ethantmcgee.yubiauthn.model.AttestationFormat;
import dev.ethantmcgee.yubiauthn.model.AuthenticatorAttachmentType;
import dev.ethantmcgee.yubiauthn.model.COSEAlgorithmIdentifier;
import dev.ethantmcgee.yubiauthn.model.TransportType;
import java.util.List;
import java.util.UUID;

/**
 * Factory class for creating pre-configured YubiKey emulator instances.
 *
 * <p>This class provides factory methods for creating emulators that mimic real YubiKey devices
 * with their actual characteristics and capabilities.
 */
public class Yubikey {
  /**
   * Creates a YubiKey 5C NFC emulator instance.
   *
   * <p>The emulator is configured with the actual characteristics of a YubiKey 5C NFC device,
   * including its AAGUID, supported algorithms, and transport types.
   *
   * @return a configured YubiKeyEmulator instance mimicking a YubiKey 5C NFC
   */
  public static YubiKeyEmulator get5cNfc() {
    return YubiKeyEmulator.builder()
        .aaguid(UUID.fromString("2fc0579f-8113-47ea-b116-bb5a8db9202a"))
        .deviceIdentifier("312e332e362e312e342e312e34313438322e312e37")
        .description("YubiKey 5C NFC")
        .attestationFormat(AttestationFormat.PACKED)
        .transports(List.of(TransportType.USB, TransportType.NFC))
        .supportedAlgorithms(List.of(COSEAlgorithmIdentifier.ES256, COSEAlgorithmIdentifier.ES512))
        .supportedAttachmentTypes(List.of(AuthenticatorAttachmentType.CROSS_PLATFORM))
        .supportsUserPresence(true)
        .supportsUserVerification(true)
        .supportsResidentKey(true)
        .supportsEnterpriseAttestation(false)
        .supportsCredProtect(true)
        .supportsMinPinLength(true)
        .pinLength(4)
        .backupEligible(false)
        .backupState(false)
        .build();
  }
}
