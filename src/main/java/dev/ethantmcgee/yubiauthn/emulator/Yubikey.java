package dev.ethantmcgee.yubiauthn.emulator;

import dev.ethantmcgee.yubiauthn.exception.CryptoException;
import dev.ethantmcgee.yubiauthn.exception.InvalidConfigurationException;
import dev.ethantmcgee.yubiauthn.model.AttestationFormat;
import dev.ethantmcgee.yubiauthn.model.AuthenticatorAttachmentType;
import dev.ethantmcgee.yubiauthn.model.COSEAlgorithmIdentifier;
import dev.ethantmcgee.yubiauthn.model.TransportType;
import java.util.List;

/**
 * Convenience factory class providing pre-configured YubiKey authenticator emulators.
 *
 * <p>This class contains static methods to create emulators matching real YubiKey authenticator
 * models with their correct AAGUIDs, capabilities, and attestation formats.
 *
 * <h2>Available YubiKey Emulators</h2>
 *
 * <ul>
 *   <li>{@link #get5cNfc()} - YubiKey 5C NFC with packed attestation
 *   <li>{@link #get5Ci()} - YubiKey 5Ci with packed attestation
 *   <li>{@link #get5NanoFido()} - YubiKey 5 Nano (FIDO edition) with fido-u2f attestation
 *   <li>{@link #getSecurityKey()} - Security Key by Yubico with fido-u2f attestation
 *   <li>{@link #getSecurityKeyNfc()} - Security Key NFC by Yubico with fido-u2f attestation
 *   <li>{@link #getBioSeries()} - YubiKey Bio Series with packed attestation
 * </ul>
 *
 * @see YubiKeyEmulator
 */
public class Yubikey {

  /**
   * Creates a YubiKey 5C NFC emulator with packed attestation format.
   *
   * <p>The YubiKey 5C NFC is a USB-C authenticator with NFC support, providing both user presence
   * and user verification capabilities with resident key support.
   *
   * @return Configured YubiKey 5C NFC emulator
   * @throws CryptoException If cryptographic initialization fails
   * @throws InvalidConfigurationException If configuration is invalid
   */
  public static YubiKeyEmulator get5cNfc() throws CryptoException, InvalidConfigurationException {
    return YubiKeyEmulator.builder()
        .aaguid("2fc0579f-8113-47ea-b116-bb5a8db9202a")
        .description("YubiKey 5C NFC")
        .attestationFormat(AttestationFormat.PACKED)
        .attestationSubject("CN=YubiKey 5C NFC,OU=Authenticator Attestation,O=Yubico,C=SE")
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

  /**
   * Creates a YubiKey 5Ci emulator with packed attestation format.
   *
   * <p>The YubiKey 5Ci is a dual USB-C and Lightning connector authenticator designed for both
   * computers and iOS devices.
   *
   * @return Configured YubiKey 5Ci emulator
   * @throws CryptoException If cryptographic initialization fails
   * @throws InvalidConfigurationException If configuration is invalid
   */
  public static YubiKeyEmulator get5Ci() throws CryptoException, InvalidConfigurationException {
    return YubiKeyEmulator.builder()
        .aaguid("c5ef55ff-ad9a-4b9f-b580-adebafe026d0")
        .description("YubiKey 5Ci")
        .attestationFormat(AttestationFormat.PACKED)
        .attestationSubject("CN=YubiKey 5Ci,OU=Authenticator Attestation,O=Yubico,C=SE")
        .transports(List.of(TransportType.USB))
        .supportedAlgorithms(
            List.of(
                COSEAlgorithmIdentifier.ES256,
                COSEAlgorithmIdentifier.ES512,
                COSEAlgorithmIdentifier.RS256))
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

  /**
   * Creates a YubiKey 5 Nano (FIDO edition) emulator with fido-u2f attestation format.
   *
   * <p>The YubiKey 5 Nano is a very small USB-A authenticator designed to stay plugged in. This
   * FIDO edition uses the fido-u2f attestation format.
   *
   * @return Configured YubiKey 5 Nano FIDO emulator
   * @throws CryptoException If cryptographic initialization fails
   * @throws InvalidConfigurationException If configuration is invalid
   */
  public static YubiKeyEmulator get5NanoFido()
      throws CryptoException, InvalidConfigurationException {
    return YubiKeyEmulator.builder()
        .aaguid("fa2b99dc-9e39-4257-8f92-4a30d23c4118")
        .description("YubiKey 5 Nano (FIDO)")
        .attestationFormat(AttestationFormat.FIDO_U2F)
        .attestationSubject("CN=YubiKey 5 Nano FIDO,OU=Authenticator Attestation,O=Yubico,C=SE")
        .transports(List.of(TransportType.USB))
        .supportedAlgorithms(List.of(COSEAlgorithmIdentifier.ES256))
        .supportedAttachmentTypes(List.of(AuthenticatorAttachmentType.CROSS_PLATFORM))
        .supportsUserPresence(true)
        .supportsUserVerification(false)
        .supportsResidentKey(false)
        .supportsEnterpriseAttestation(false)
        .supportsCredProtect(false)
        .supportsMinPinLength(false)
        .backupEligible(false)
        .backupState(false)
        .build();
  }

  /**
   * Creates a Security Key by Yubico emulator with fido-u2f attestation format.
   *
   * <p>The Security Key by Yubico is a basic USB-A FIDO U2F authenticator without PIN or resident
   * key support.
   *
   * @return Configured Security Key emulator
   * @throws CryptoException If cryptographic initialization fails
   * @throws InvalidConfigurationException If configuration is invalid
   */
  public static YubiKeyEmulator getSecurityKey()
      throws CryptoException, InvalidConfigurationException {
    return YubiKeyEmulator.builder()
        .aaguid("f8a011f3-8c0a-4d15-8006-17111f9edc7d")
        .description("Security Key by Yubico")
        .attestationFormat(AttestationFormat.FIDO_U2F)
        .attestationSubject("CN=Security Key by Yubico,OU=Authenticator Attestation,O=Yubico,C=SE")
        .transports(List.of(TransportType.USB))
        .supportedAlgorithms(List.of(COSEAlgorithmIdentifier.ES256))
        .supportedAttachmentTypes(List.of(AuthenticatorAttachmentType.CROSS_PLATFORM))
        .supportsUserPresence(true)
        .supportsUserVerification(false)
        .supportsResidentKey(false)
        .supportsEnterpriseAttestation(false)
        .supportsCredProtect(false)
        .supportsMinPinLength(false)
        .backupEligible(false)
        .backupState(false)
        .build();
  }

  /**
   * Creates a Security Key NFC by Yubico emulator with fido-u2f attestation format.
   *
   * <p>The Security Key NFC is similar to the Security Key but adds NFC support for mobile devices.
   *
   * @return Configured Security Key NFC emulator
   * @throws CryptoException If cryptographic initialization fails
   * @throws InvalidConfigurationException If configuration is invalid
   */
  public static YubiKeyEmulator getSecurityKeyNfc()
      throws CryptoException, InvalidConfigurationException {
    return YubiKeyEmulator.builder()
        .aaguid("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73")
        .description("Security Key NFC by Yubico")
        .attestationFormat(AttestationFormat.FIDO_U2F)
        .attestationSubject(
            "CN=Security Key NFC by Yubico,OU=Authenticator Attestation,O=Yubico,C=SE")
        .transports(List.of(TransportType.USB, TransportType.NFC))
        .supportedAlgorithms(List.of(COSEAlgorithmIdentifier.ES256))
        .supportedAttachmentTypes(List.of(AuthenticatorAttachmentType.CROSS_PLATFORM))
        .supportsUserPresence(true)
        .supportsUserVerification(false)
        .supportsResidentKey(false)
        .supportsEnterpriseAttestation(false)
        .supportsCredProtect(false)
        .supportsMinPinLength(false)
        .backupEligible(false)
        .backupState(false)
        .build();
  }

  /**
   * Creates a YubiKey Bio Series emulator with packed attestation format.
   *
   * <p>The YubiKey Bio Series includes biometric authentication with fingerprint support, enabling
   * passwordless authentication with user verification.
   *
   * @return Configured YubiKey Bio Series emulator
   * @throws CryptoException If cryptographic initialization fails
   * @throws InvalidConfigurationException If configuration is invalid
   */
  public static YubiKeyEmulator getBioSeries()
      throws CryptoException, InvalidConfigurationException {
    return YubiKeyEmulator.builder()
        .aaguid("d8522d9f-575b-4866-88a9-ba99fa02f35b")
        .description("YubiKey Bio Series")
        .attestationFormat(AttestationFormat.PACKED)
        .attestationSubject("CN=YubiKey Bio Series,OU=Authenticator Attestation,O=Yubico,C=SE")
        .transports(List.of(TransportType.USB))
        .supportedAlgorithms(
            List.of(
                COSEAlgorithmIdentifier.ES256,
                COSEAlgorithmIdentifier.ES512,
                COSEAlgorithmIdentifier.RS256))
        .supportedAttachmentTypes(List.of(AuthenticatorAttachmentType.CROSS_PLATFORM))
        .supportsUserPresence(true)
        .supportsUserVerification(true)
        .supportsResidentKey(true)
        .supportsEnterpriseAttestation(false)
        .supportsCredProtect(true)
        .supportsMinPinLength(true)
        .pinLength(6)
        .backupEligible(false)
        .backupState(false)
        .build();
  }
}
