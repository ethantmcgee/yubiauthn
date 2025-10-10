package dev.ethantmcgee.yubiauthn;

import dev.ethantmcgee.yubiauthn.model.*;
import dev.ethantmcgee.yubiauthn.model.*;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for model validation.
 */
class ModelValidationTest {

    @Test
    void testPublicKeyCredentialRpEntityValidation() {
        // Valid
        PublicKeyCredentialRpEntity validRp = new PublicKeyCredentialRpEntity("example.com", "Example");
        assertThat(validRp).isNotNull();

        // Invalid - null name
        assertThatThrownBy(() -> new PublicKeyCredentialRpEntity("example.com", null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("name must not be null");

        // Invalid - blank name
        assertThatThrownBy(() -> new PublicKeyCredentialRpEntity("example.com", ""))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("name must not be null or blank");
    }

    @Test
    void testPublicKeyCredentialUserEntityValidation() {
        byte[] validId = "user123".getBytes();

        // Valid
        PublicKeyCredentialUserEntity validUser = new PublicKeyCredentialUserEntity(
            validId, "user@example.com", "Test User"
        );
        assertThat(validUser).isNotNull();

        // Invalid - null id
        assertThatThrownBy(() -> new PublicKeyCredentialUserEntity(null, "user@example.com", "Test User"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("User ID must not be null");

        // Invalid - empty id
        assertThatThrownBy(() -> new PublicKeyCredentialUserEntity(new byte[0], "user@example.com", "Test User"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("User ID must not be null or empty");

        // Invalid - null name
        assertThatThrownBy(() -> new PublicKeyCredentialUserEntity(validId, null, "Test User"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("User name must not be null");
    }

    @Test
    void testPublicKeyCredentialCreationOptionsValidation() {
        PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity("example.com", "Example");
        PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(
            "user123".getBytes(), "user@example.com", "Test User"
        );
        byte[] challenge = new byte[32];
        List<PublicKeyCredentialParameters> params = List.of(
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)
        );

        // Valid
        PublicKeyCredentialCreationOptions validOptions = new PublicKeyCredentialCreationOptions(
            rp, user, challenge, params, 30000L, null, null, AttestationConveyancePreference.NONE
        );
        assertThat(validOptions).isNotNull();

        // Invalid - null RP
        assertThatThrownBy(() -> new PublicKeyCredentialCreationOptions(
            null, user, challenge, params, 30000L, null, null, AttestationConveyancePreference.NONE
        ))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("RP must not be null");

        // Invalid - empty challenge
        assertThatThrownBy(() -> new PublicKeyCredentialCreationOptions(
            rp, user, new byte[0], params, 30000L, null, null, AttestationConveyancePreference.NONE
        ))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Challenge must not be null or empty");

        // Invalid - empty params
        assertThatThrownBy(() -> new PublicKeyCredentialCreationOptions(
            rp, user, challenge, List.of(), 30000L, null, null, AttestationConveyancePreference.NONE
        ))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Public key credential parameters must not be null or empty");
    }

    @Test
    void testCOSEAlgorithmIdentifierFromValue() {
        assertThat(COSEAlgorithmIdentifier.fromValue(-7)).isEqualTo(COSEAlgorithmIdentifier.ES256);
        assertThat(COSEAlgorithmIdentifier.fromValue(-35)).isEqualTo(COSEAlgorithmIdentifier.ES384);
        assertThat(COSEAlgorithmIdentifier.fromValue(-257)).isEqualTo(COSEAlgorithmIdentifier.RS256);

        assertThatThrownBy(() -> COSEAlgorithmIdentifier.fromValue(999))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Unknown COSE algorithm identifier");
    }

    @Test
    void testAuthenticatorDataBuilder() throws Exception {
        // Arrange
        byte[] rpIdHash = new byte[32];
        byte[] attestedCredData = new byte[77];

        // Act
        AuthenticatorData authData = new AuthenticatorData.Builder()
            .rpIdHash(rpIdHash)
            .userPresent(true)
            .userVerified(true)
            .signCount(10)
            .attestedCredentialData(attestedCredData)
            .build();

        // Assert
        assertThat(authData).isNotNull();
        assertThat(authData.getRpIdHash()).isEqualTo(rpIdHash);
        assertThat(authData.getSignCount()).isEqualTo(10);
        assertThat(authData.getAttestedCredentialData()).isEqualTo(attestedCredData);

        // Verify flags
        byte flags = authData.getFlags();
        assertThat((flags & 0x01) != 0).isTrue(); // UP
        assertThat((flags & 0x04) != 0).isTrue(); // UV
        assertThat((flags & 0x40) != 0).isTrue(); // AT
    }

    @Test
    void testAuthenticatorDataEncoding() throws Exception {
        // Arrange
        byte[] rpIdHash = new byte[32];
        AuthenticatorData authData = new AuthenticatorData.Builder()
            .rpIdHash(rpIdHash)
            .userPresent(true)
            .signCount(5)
            .build();

        // Act
        byte[] encoded = authData.encode();

        // Assert
        assertThat(encoded).isNotNull();
        // Minimum size: 32 (rpIdHash) + 1 (flags) + 4 (signCount) = 37
        assertThat(encoded.length).isGreaterThanOrEqualTo(37);
    }
}
