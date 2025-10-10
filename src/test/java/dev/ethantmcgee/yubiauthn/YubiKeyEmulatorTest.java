package dev.ethantmcgee.yubiauthn;

import dev.ethantmcgee.yubiauthn.crypto.CryptoUtils;
import dev.ethantmcgee.yubiauthn.emulator.YubiKeyEmulator;
import dev.ethantmcgee.yubiauthn.model.*;
import dev.ethantmcgee.yubiauthn.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for YubiKey emulator functionality.
 */
class YubiKeyEmulatorTest {

    private YubiKeyEmulator emulator;

    @BeforeEach
    void setUp() throws Exception {
        emulator = new YubiKeyEmulator();
    }

    @Test
    void testMakeCredentialWithES256() throws Exception {
        // Arrange
        byte[] challenge = CryptoUtils.generateChallenge();
        byte[] userId = "user123".getBytes();

        PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("example.com", "Example Corp"),
            new PublicKeyCredentialUserEntity(userId, "user@example.com", "Test User"),
            challenge,
            List.of(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
            30000L,
            null,
            new AuthenticatorSelectionCriteria(
                AuthenticatorSelectionCriteria.AuthenticatorAttachment.CROSS_PLATFORM,
                false,
                "discouraged",
                UserVerificationRequirement.PREFERRED
            ),
            AttestationConveyancePreference.DIRECT
        );

        // Act
        PublicKeyCredential<AuthenticatorAttestationResponse> credential = emulator.makeCredential(options);

        // Assert
        assertThat(credential).isNotNull();
        assertThat(credential.id()).isNotNull().isNotEmpty();
        assertThat(credential.rawId()).isNotNull().isNotEmpty();
        assertThat(credential.type()).isEqualTo("public-key");
        assertThat(credential.response()).isNotNull();
        assertThat(credential.response().clientDataJSON()).isNotNull().isNotEmpty();
        assertThat(credential.response().attestationObject()).isNotNull().isNotEmpty();
        assertThat(credential.response().transports()).containsExactlyInAnyOrder(
            AuthenticatorTransport.NFC,
            AuthenticatorTransport.USB
        );
        assertThat(credential.authenticatorAttachment()).isEqualTo(PublicKeyCredential.AuthenticatorAttachment.CROSS_PLATFORM);

        // Verify credential was stored
        assertThat(emulator.getCredentialCount()).isEqualTo(1);
    }

    @Test
    void testMakeCredentialWithMultipleAlgorithms() throws Exception {
        // Arrange
        byte[] challenge = CryptoUtils.generateChallenge();
        byte[] userId = "user456".getBytes();

        PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("example.com", "Example Corp"),
            new PublicKeyCredentialUserEntity(userId, "user@example.com", "Test User"),
            challenge,
            List.of(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256),
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES384)
            ),
            30000L,
            null,
            null,
            AttestationConveyancePreference.NONE
        );

        // Act
        PublicKeyCredential<AuthenticatorAttestationResponse> credential = emulator.makeCredential(options);

        // Assert
        assertThat(credential).isNotNull();
        assertThat(credential.id()).isNotNull();
    }

    @Test
    void testGetAssertion() throws Exception {
        // Arrange - First create a credential
        byte[] challenge1 = CryptoUtils.generateChallenge();
        byte[] userId = "user789".getBytes();

        PublicKeyCredentialCreationOptions createOptions = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("example.com", "Example Corp"),
            new PublicKeyCredentialUserEntity(userId, "user@example.com", "Test User"),
            challenge1,
            List.of(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
            30000L,
            null,
            null,
            AttestationConveyancePreference.NONE
        );

        PublicKeyCredential<AuthenticatorAttestationResponse> createdCredential = emulator.makeCredential(createOptions);

        // Now test assertion
        byte[] challenge2 = CryptoUtils.generateChallenge();
        PublicKeyCredentialRequestOptions requestOptions = new PublicKeyCredentialRequestOptions(
            challenge2,
            30000L,
            "example.com",
            List.of(new PublicKeyCredentialDescriptor(
                PublicKeyCredentialType.PUBLIC_KEY,
                createdCredential.rawId(),
                List.of(AuthenticatorTransport.USB, AuthenticatorTransport.NFC)
            )),
            UserVerificationRequirement.PREFERRED
        );

        // Act
        PublicKeyCredential<AuthenticatorAssertionResponse> assertion = emulator.getAssertion(requestOptions);

        // Assert
        assertThat(assertion).isNotNull();
        assertThat(assertion.id()).isNotNull().isNotEmpty();
        assertThat(assertion.rawId()).isNotNull().isNotEmpty();
        assertThat(assertion.type()).isEqualTo("public-key");
        assertThat(assertion.response()).isNotNull();
        assertThat(assertion.response().clientDataJSON()).isNotNull().isNotEmpty();
        assertThat(assertion.response().authenticatorData()).isNotNull().isNotEmpty();
        assertThat(assertion.response().signature()).isNotNull().isNotEmpty();
        assertThat(assertion.response().userHandle()).isNotNull().isEqualTo(userId);
    }

    @Test
    void testGetAssertionWithoutAllowCredentials() throws Exception {
        // Arrange - Create a credential
        byte[] challenge1 = CryptoUtils.generateChallenge();
        byte[] userId = "userABC".getBytes();

        PublicKeyCredentialCreationOptions createOptions = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("example.com", "Example Corp"),
            new PublicKeyCredentialUserEntity(userId, "user@example.com", "Test User"),
            challenge1,
            List.of(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
            30000L,
            null,
            null,
            AttestationConveyancePreference.NONE
        );

        emulator.makeCredential(createOptions);

        // Request assertion without specifying allowCredentials
        byte[] challenge2 = CryptoUtils.generateChallenge();
        PublicKeyCredentialRequestOptions requestOptions = new PublicKeyCredentialRequestOptions(
            challenge2,
            30000L,
            "example.com",
            null, // No specific credentials
            UserVerificationRequirement.PREFERRED
        );

        // Act
        PublicKeyCredential<AuthenticatorAssertionResponse> assertion = emulator.getAssertion(requestOptions);

        // Assert
        assertThat(assertion).isNotNull();
        assertThat(assertion.response().userHandle()).isEqualTo(userId);
    }

    @Test
    void testGetAssertionWithNoMatchingCredential() throws Exception {
        // Arrange
        byte[] challenge = CryptoUtils.generateChallenge();
        byte[] nonExistentCredentialId = new byte[16];

        PublicKeyCredentialRequestOptions requestOptions = new PublicKeyCredentialRequestOptions(
            challenge,
            30000L,
            "example.com",
            List.of(new PublicKeyCredentialDescriptor(
                PublicKeyCredentialType.PUBLIC_KEY,
                nonExistentCredentialId,
                null
            )),
            UserVerificationRequirement.PREFERRED
        );

        // Act & Assert
        assertThatThrownBy(() -> emulator.getAssertion(requestOptions))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("No matching credential found");
    }

    @Test
    void testSignatureCounterIncreases() throws Exception {
        // Arrange
        byte[] challenge1 = CryptoUtils.generateChallenge();
        byte[] userId = "userCounter".getBytes();

        PublicKeyCredentialCreationOptions createOptions = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("example.com", "Example Corp"),
            new PublicKeyCredentialUserEntity(userId, "user@example.com", "Test User"),
            challenge1,
            List.of(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
            30000L,
            null,
            null,
            AttestationConveyancePreference.NONE
        );

        PublicKeyCredential<AuthenticatorAttestationResponse> credential = emulator.makeCredential(createOptions);

        // Perform multiple assertions
        for (int i = 0; i < 3; i++) {
            byte[] challenge = CryptoUtils.generateChallenge();
            PublicKeyCredentialRequestOptions requestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                30000L,
                "example.com",
                List.of(new PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType.PUBLIC_KEY,
                    credential.rawId(),
                    null
                )),
                UserVerificationRequirement.PREFERRED
            );

            PublicKeyCredential<AuthenticatorAssertionResponse> assertion = emulator.getAssertion(requestOptions);
            assertThat(assertion).isNotNull();
        }

        // The counter should have increased
        assertThat(emulator.getCredentialCount()).isEqualTo(1);
    }

    @Test
    void testClearCredentials() throws Exception {
        // Arrange
        byte[] challenge = CryptoUtils.generateChallenge();
        byte[] userId = "userClear".getBytes();

        PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("example.com", "Example Corp"),
            new PublicKeyCredentialUserEntity(userId, "user@example.com", "Test User"),
            challenge,
            List.of(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
            30000L,
            null,
            null,
            AttestationConveyancePreference.NONE
        );

        emulator.makeCredential(options);
        assertThat(emulator.getCredentialCount()).isEqualTo(1);

        // Act
        emulator.clearCredentials();

        // Assert
        assertThat(emulator.getCredentialCount()).isEqualTo(0);
    }

    @Test
    void testGetAAGUID() {
        // Act
        byte[] aaguid = emulator.getAAGUID();

        // Assert
        assertThat(aaguid).isNotNull().hasSize(16);
    }

    @Test
    void testMultipleCredentialsForSameRP() throws Exception {
        // Arrange
        String rpId = "example.com";

        // Create first credential
        PublicKeyCredentialCreationOptions options1 = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity(rpId, "Example Corp"),
            new PublicKeyCredentialUserEntity("user1".getBytes(), "user1@example.com", "User One"),
            CryptoUtils.generateChallenge(),
            List.of(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
            30000L,
            null,
            null,
            AttestationConveyancePreference.NONE
        );

        // Create second credential
        PublicKeyCredentialCreationOptions options2 = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity(rpId, "Example Corp"),
            new PublicKeyCredentialUserEntity("user2".getBytes(), "user2@example.com", "User Two"),
            CryptoUtils.generateChallenge(),
            List.of(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
            30000L,
            null,
            null,
            AttestationConveyancePreference.NONE
        );

        // Act
        PublicKeyCredential<AuthenticatorAttestationResponse> credential1 = emulator.makeCredential(options1);
        PublicKeyCredential<AuthenticatorAttestationResponse> credential2 = emulator.makeCredential(options2);

        // Assert
        assertThat(emulator.getCredentialCount()).isEqualTo(2);
        assertThat(credential1.id()).isNotEqualTo(credential2.id());
    }
}
