package dev.ethantmcgee.yubiauthn;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.Extensions;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.RegistrationExtensionInputs;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import dev.ethantmcgee.yubiauthn.emulator.Yubikey;
import dev.ethantmcgee.yubiauthn.util.JsonUtil;
import java.util.Base64;
import net.datafaker.Faker;
import org.junit.jupiter.api.Test;

public class JavaWebauthnServerIntegrationTest {
  private final Faker faker = new Faker();
  private final ObjectMapper jsonMapper = JsonUtil.getJsonMapper();

  public record CredentialCreationResponse(
      @JsonValue
          PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
              credential) {}

  public record CredentialAssertionResponse(
      @JsonValue
          PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
              credential) {}

  @Test
  void testYubiKey5cNfcPackedAttestation() throws Exception {
    final var emulator = Yubikey.get5cNfc();

    final var domain = faker.internet().domainName();
    final var credentialStore = new InMemoryCredentialStore();
    RelyingParty rp =
        RelyingParty.builder()
            .identity(RelyingPartyIdentity.builder().id(domain).name("Example Company").build())
            .credentialRepository(credentialStore)
            .build();

    final var email = faker.internet().emailAddress();
    final var userId =
        ByteArray.fromBase64Url(Base64.getUrlEncoder().encodeToString(email.getBytes()));
    final var creationOptions =
        rp.startRegistration(
            StartRegistrationOptions.builder()
                .user(UserIdentity.builder().name(email).displayName(email).id(userId).build())
                .authenticatorSelection(
                    AuthenticatorSelectionCriteria.builder()
                        .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
                        .residentKey(ResidentKeyRequirement.REQUIRED)
                        .userVerification(UserVerificationRequirement.REQUIRED)
                        .build())
                .extensions(
                    RegistrationExtensionInputs.builder()
                        .credProtect(
                            Extensions.CredentialProtection.CredentialProtectionInput.require(
                                Extensions.CredentialProtection.CredentialProtectionPolicy
                                    .UV_REQUIRED))
                        .credProps(true)
                        .build())
                .build());

    final var createResult = emulator.create(creationOptions.toJson());

    final var registeredCredential =
        rp.finishRegistration(
            FinishRegistrationOptions.builder()
                .request(creationOptions)
                .response(
                    jsonMapper.readValue(createResult.toJson(), CredentialCreationResponse.class)
                        .credential)
                .build());

    credentialStore.addCredential(
        email,
        userId,
        RegisteredCredential.builder()
            .credentialId(registeredCredential.getKeyId().getId())
            .userHandle(userId)
            .publicKeyCose(registeredCredential.getPublicKeyCose())
            .build());

    final var assertionOptions =
        rp.startAssertion(
            StartAssertionOptions.builder()
                .userHandle(userId)
                .username(email)
                .userVerification(UserVerificationRequirement.REQUIRED)
                .build());

    final var assertResult = emulator.get(getPublicKeyCredential(assertionOptions.toJson()));

    final var assertedCredential =
        rp.finishAssertion(
            FinishAssertionOptions.builder()
                .request(assertionOptions)
                .response(
                    jsonMapper.readValue(assertResult.toJson(), CredentialAssertionResponse.class)
                        .credential)
                .build());

    assertTrue(assertedCredential.isSuccess());
  }

  @Test
  void testYubiKeyNeoFidoU2FAttestation() throws Exception {
    final var emulator = Yubikey.getNeoU2F();

    final var domain = faker.internet().domainName();
    final var credentialStore = new InMemoryCredentialStore();
    RelyingParty rp =
        RelyingParty.builder()
            .identity(RelyingPartyIdentity.builder().id(domain).name("Example Company").build())
            .credentialRepository(credentialStore)
            .build();

    final var email = faker.internet().emailAddress();
    final var userId =
        ByteArray.fromBase64Url(Base64.getUrlEncoder().encodeToString(email.getBytes()));
    final var creationOptions =
        rp.startRegistration(
            StartRegistrationOptions.builder()
                .user(UserIdentity.builder().name(email).displayName(email).id(userId).build())
                .authenticatorSelection(
                    AuthenticatorSelectionCriteria.builder()
                        .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
                        .residentKey(ResidentKeyRequirement.DISCOURAGED)
                        .userVerification(UserVerificationRequirement.DISCOURAGED)
                        .build())
                .build());

    final var createResult = emulator.create(creationOptions.toJson());

    final var registeredCredential =
        rp.finishRegistration(
            FinishRegistrationOptions.builder()
                .request(creationOptions)
                .response(
                    jsonMapper.readValue(createResult.toJson(), CredentialCreationResponse.class)
                        .credential)
                .build());

    credentialStore.addCredential(
        email,
        userId,
        RegisteredCredential.builder()
            .credentialId(registeredCredential.getKeyId().getId())
            .userHandle(userId)
            .publicKeyCose(registeredCredential.getPublicKeyCose())
            .build());

    final var assertionOptions =
        rp.startAssertion(
            StartAssertionOptions.builder()
                .userHandle(userId)
                .username(email)
                .userVerification(UserVerificationRequirement.DISCOURAGED)
                .build());

    final var assertResult = emulator.get(getPublicKeyCredential(assertionOptions.toJson()));

    final var assertedCredential =
        rp.finishAssertion(
            FinishAssertionOptions.builder()
                .request(assertionOptions)
                .response(
                    jsonMapper.readValue(assertResult.toJson(), CredentialAssertionResponse.class)
                        .credential)
                .build());

    assertTrue(assertedCredential.isSuccess());
  }

  private String getPublicKeyCredential(String json) throws JsonProcessingException {
    final var object = jsonMapper.readTree(json);
    return object.get("publicKeyCredentialRequestOptions").toString();
  }
}
