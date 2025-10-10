package dev.ethantmcgee.yubiauthn;

import dev.ethantmcgee.yubiauthn.crypto.CryptoUtils;
import dev.ethantmcgee.yubiauthn.model.COSEAlgorithmIdentifier;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for cryptographic utilities.
 */
class CryptoUtilsTest {

    @Test
    void testGenerateES256KeyPair() throws Exception {
        // Act
        KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);

        // Assert
        assertThat(keyPair).isNotNull();
        assertThat(keyPair.getPublic()).isInstanceOf(ECPublicKey.class);
        assertThat(keyPair.getPrivate()).isNotNull();
    }

    @Test
    void testGenerateES384KeyPair() throws Exception {
        // Act
        KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES384);

        // Assert
        assertThat(keyPair).isNotNull();
        assertThat(keyPair.getPublic()).isInstanceOf(ECPublicKey.class);
    }

    @Test
    void testEncodeCOSEPublicKey() throws Exception {
        // Arrange
        KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);

        // Act
        byte[] coseKey = CryptoUtils.encodeCOSEPublicKey(keyPair.getPublic(), COSEAlgorithmIdentifier.ES256);

        // Assert
        assertThat(coseKey).isNotNull().isNotEmpty();
        // COSE key should start with a map indicator (0xA5 for 5 entries)
        assertThat(coseKey[0]).isEqualTo((byte) 0xA5);
    }

    @Test
    void testSignES256() throws Exception {
        // Arrange
        KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
        byte[] data = "test data".getBytes();

        // Act
        byte[] signature = CryptoUtils.sign(data, keyPair.getPrivate(), COSEAlgorithmIdentifier.ES256);

        // Assert
        assertThat(signature).isNotNull().isNotEmpty();
    }

    @Test
    void testGenerateAttestationCertificate() throws Exception {
        // Arrange
        KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);

        // Act
        X509Certificate cert = CryptoUtils.generateAttestationCertificate(
            keyPair,
            "CN=Test Authenticator,O=Test,C=US"
        );

        // Assert
        assertThat(cert).isNotNull();
        assertThat(cert.getSubjectX500Principal().getName()).contains("CN=Test Authenticator");
        assertThat(cert.getIssuerX500Principal().getName()).contains("CN=YubiKey NFC 5C Emulator");
    }

    @Test
    void testCreateAttestedCredentialData() {
        // Arrange
        byte[] aaguid = new byte[16];
        byte[] credentialId = new byte[16];
        byte[] publicKey = new byte[77]; // typical COSE key size

        // Act
        byte[] attestedCredentialData = CryptoUtils.createAttestedCredentialData(aaguid, credentialId, publicKey);

        // Assert
        assertThat(attestedCredentialData).isNotNull();
        // Should be: 16 (aaguid) + 2 (length) + 16 (credId) + 77 (pubKey) = 111 bytes
        assertThat(attestedCredentialData).hasSize(16 + 2 + 16 + 77);
    }

    @Test
    void testGenerateCredentialId() {
        // Act
        byte[] credentialId1 = CryptoUtils.generateCredentialId();
        byte[] credentialId2 = CryptoUtils.generateCredentialId();

        // Assert
        assertThat(credentialId1).isNotNull().hasSize(16);
        assertThat(credentialId2).isNotNull().hasSize(16);
        assertThat(credentialId1).isNotEqualTo(credentialId2);
    }

    @Test
    void testGenerateChallenge() {
        // Act
        byte[] challenge1 = CryptoUtils.generateChallenge();
        byte[] challenge2 = CryptoUtils.generateChallenge();

        // Assert
        assertThat(challenge1).isNotNull().hasSize(32);
        assertThat(challenge2).isNotNull().hasSize(32);
        assertThat(challenge1).isNotEqualTo(challenge2);
    }
}
