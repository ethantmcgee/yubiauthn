package dev.ethantmcgee.yubiauthn.emulator;

import static org.assertj.core.api.Assertions.*;

import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.*;
import dev.ethantmcgee.yubiauthn.InMemoryCredentialStore;
import dev.ethantmcgee.yubiauthn.JavaWebauthnServerIntegrationTest.CredentialCreationResponse;
import dev.ethantmcgee.yubiauthn.model.AttestationFormat;
import dev.ethantmcgee.yubiauthn.model.COSEAlgorithmIdentifier;
import dev.ethantmcgee.yubiauthn.util.JsonUtil;
import java.util.Base64;
import java.util.List;
import net.datafaker.Faker;
import org.junit.jupiter.api.Test;

class AttestationFormatTest {
  private final Faker faker = new Faker();
  private final com.fasterxml.jackson.databind.ObjectMapper jsonMapper = JsonUtil.getJsonMapper();

  @Test
  void testPackedAttestation_ES256() throws Exception {
    var emulator = Yubikey.get5cNfc();
    var domain = faker.internet().domainName();
    var credentialStore = new InMemoryCredentialStore();
    RelyingParty rp = RelyingParty.builder()
        .identity(RelyingPartyIdentity.builder().id(domain).name("Test RP").build())
        .credentialRepository(credentialStore)
        .build();

    var email = faker.internet().emailAddress();
    var userId = ByteArray.fromBase64Url(Base64.getUrlEncoder().encodeToString(email.getBytes()));
    var creationOptions = rp.startRegistration(
        StartRegistrationOptions.builder()
            .user(UserIdentity.builder().name(email).displayName(email).id(userId).build())
            .build());

    var credential = emulator.create(creationOptions.toJson());

    assertThat(credential).isNotNull();
    assertThat(credential.response()).isNotNull();

    // Verify with WebAuthn server library
    var result = rp.finishRegistration(
        FinishRegistrationOptions.builder()
            .request(creationOptions)
            .response(jsonMapper.readValue(credential.toJson(), CredentialCreationResponse.class).credential())
            .build());

    assertThat(result.isAttestationTrusted()).isFalse(); // Self-signed
  }

  @Test
  void testFidoU2FAttestation_ES256() throws Exception {
    // Create emulator with FIDO U2F attestation format
    var emulator = Yubikey.get5cNfc().toBuilder()
        .attestationFormat(AttestationFormat.FIDO_U2F)
        .attestationAlgorithm(COSEAlgorithmIdentifier.ES256)
        .build();

    var domain = faker.internet().domainName();
    var credentialStore = new InMemoryCredentialStore();
    RelyingParty rp = RelyingParty.builder()
        .identity(RelyingPartyIdentity.builder().id(domain).name("Test RP").build())
        .credentialRepository(credentialStore)
        .build();

    var email = faker.internet().emailAddress();
    var userId = ByteArray.fromBase64Url(Base64.getUrlEncoder().encodeToString(email.getBytes()));
    var creationOptions = rp.startRegistration(
        StartRegistrationOptions.builder()
            .user(UserIdentity.builder().name(email).displayName(email).id(userId).build())
            .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
                .build())
            .build());

    var credential = emulator.create(creationOptions.toJson());

    assertThat(credential).isNotNull();
    assertThat(credential.response()).isNotNull();
    assertThat(credential.response().attestationObject()).isNotNull();
  }

  @Test
  void testFidoU2FAttestation_OnlySupportsES256() throws Exception {
    // U2F format is hardcoded to ES256 only
    var emulator = Yubikey.get5cNfc().toBuilder()
        .attestationFormat(AttestationFormat.FIDO_U2F)
        // Even if authenticator supports other algorithms, U2F can only use ES256
        .supportedAlgorithms(List.of(COSEAlgorithmIdentifier.ES256, COSEAlgorithmIdentifier.ES384))
        .build();

    var domain = faker.internet().domainName();
    var credentialStore = new InMemoryCredentialStore();
    RelyingParty rp = RelyingParty.builder()
        .identity(RelyingPartyIdentity.builder().id(domain).name("Test RP").build())
        .credentialRepository(credentialStore)
        .build();

    var email = faker.internet().emailAddress();
    var userId = ByteArray.fromBase64Url(Base64.getUrlEncoder().encodeToString(email.getBytes()));

    var creationOptions = rp.startRegistration(
        StartRegistrationOptions.builder()
            .user(UserIdentity.builder().name(email).displayName(email).id(userId).build())
            .build());

    // Should succeed with ES256 (which is the default preference)
    var credential = emulator.create(creationOptions.toJson());
    assertThat(credential).isNotNull();
    assertThat(credential.response().publicKeyAlgorithm()).isEqualTo(COSEAlgorithmIdentifier.ES256);
  }

  @Test
  void testNoneAttestation() throws Exception {
    var emulator = Yubikey.get5cNfc().toBuilder()
        .attestationFormat(AttestationFormat.NONE)
        .build();

    var domain = faker.internet().domainName();
    var email = faker.internet().emailAddress();
    var userId = ByteArray.fromBase64Url(Base64.getUrlEncoder().encodeToString(email.getBytes()));

    var credentialStore = new InMemoryCredentialStore();
    RelyingParty rp = RelyingParty.builder()
        .identity(RelyingPartyIdentity.builder().id(domain).name("Test RP").build())
        .credentialRepository(credentialStore)
        .attestationConveyancePreference(AttestationConveyancePreference.NONE)
        .build();

    var creationOptions = rp.startRegistration(
        StartRegistrationOptions.builder()
            .user(UserIdentity.builder().name(email).displayName(email).id(userId).build())
            .build());

    var credential = emulator.create(creationOptions.toJson());

    assertThat(credential).isNotNull();
    assertThat(credential.response()).isNotNull();
  }

  @Test
  void testAttestationAlgorithmConfiguration() throws Exception {
    // Test that attestation algorithm can be configured independently of credential algorithm
    var emulator = YubiKeyEmulator.builder()
        .aaguid(java.util.UUID.randomUUID())
        .deviceIdentifier("1234567890ABCDEF")
        .attestationFormat(AttestationFormat.PACKED)
        .attestationAlgorithm(COSEAlgorithmIdentifier.RS256) // Use RS256 for attestation
        .supportedAlgorithms(List.of(COSEAlgorithmIdentifier.ES256)) // But only ES256 for credentials
        .supportedAttachmentTypes(List.of(dev.ethantmcgee.yubiauthn.model.AuthenticatorAttachmentType.CROSS_PLATFORM))
        .supportsUserVerification(true)
        .build();

    var domain = faker.internet().domainName();
    var credentialStore = new InMemoryCredentialStore();
    RelyingParty rp = RelyingParty.builder()
        .identity(RelyingPartyIdentity.builder().id(domain).name("Test RP").build())
        .credentialRepository(credentialStore)
        .build();

    var email = faker.internet().emailAddress();
    var userId = ByteArray.fromBase64Url(Base64.getUrlEncoder().encodeToString(email.getBytes()));
    var creationOptions = rp.startRegistration(
        StartRegistrationOptions.builder()
            .user(UserIdentity.builder().name(email).displayName(email).id(userId).build())
            .build());

    var credential = emulator.create(creationOptions.toJson());

    // Credential should use ES256 (only supported algorithm)
    assertThat(credential).isNotNull();
    assertThat(credential.response().publicKeyAlgorithm())
        .isEqualTo(COSEAlgorithmIdentifier.ES256);
    // Attestation signature uses RS256 (configured attestation algorithm)
  }
}
