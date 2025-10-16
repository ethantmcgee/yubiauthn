package dev.ethantmcgee.yubiauthn.emulator;

import dev.ethantmcgee.yubiauthn.exception.CryptoException;
import dev.ethantmcgee.yubiauthn.exception.InvalidConfigurationException;
import dev.ethantmcgee.yubiauthn.model.AuthenticatorAttachmentType;
import dev.ethantmcgee.yubiauthn.model.COSEAlgorithmIdentifier;
import dev.ethantmcgee.yubiauthn.model.TransportType;
import java.util.List;

public class Yubikey {
  public static YubiKeyEmulator get5cNfc() throws CryptoException, InvalidConfigurationException {
      return YubiKeyEmulator.builder()
              .aaguid("2fc0579f-8113-47ea-b116-bb5a8db9202a")
              .description("YubiKey 5 Series with NFC")
              .attestationSubject("CN=YubiKey NFC 5C,OU=Authenticator Attestation,O=Yubico,C=SE")
              .transports(List.of(TransportType.USB, TransportType.NFC))
              .supportedAlgorithms(
                      List.of(COSEAlgorithmIdentifier.ES256, COSEAlgorithmIdentifier.ES512))
              .supportedAttachmentTypes(List.of(AuthenticatorAttachmentType.CROSS_PLATFORM))
              .supportsUserPresence(true)
              .supportsUserVerification(true)
              .supportsResidentKey(true)
              .supportsEnterpriseAttestation(false)
              .supportsCredProtect(true)
              .supportsMinPinLength(true)
              .pinLength(4)
              .build();
  }
}
