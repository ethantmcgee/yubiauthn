package dev.ethantmcgee.yubiauthn.crypto;

import static org.assertj.core.api.Assertions.*;

import dev.ethantmcgee.yubiauthn.exception.CryptographicException;
import dev.ethantmcgee.yubiauthn.model.COSEAlgorithmIdentifier;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CryptoUtilsTest {

  @Test
  void testGenerateKeyPair_ES256() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
    assertThat(keyPair).isNotNull();
    assertThat(keyPair.getPublic()).isInstanceOf(ECPublicKey.class);
    assertThat(keyPair.getPrivate()).isNotNull();
  }

  @Test
  void testGenerateKeyPair_ES384() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES384);
    assertThat(keyPair).isNotNull();
    assertThat(keyPair.getPublic()).isInstanceOf(ECPublicKey.class);
  }

  @Test
  void testGenerateKeyPair_ES512() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES512);
    assertThat(keyPair).isNotNull();
    assertThat(keyPair.getPublic()).isInstanceOf(ECPublicKey.class);
  }

  @Test
  void testGenerateKeyPair_RS256() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.RS256);
    assertThat(keyPair).isNotNull();
    assertThat(keyPair.getPublic()).isInstanceOf(RSAPublicKey.class);
    assertThat(keyPair.getPrivate()).isNotNull();
  }

  @Test
  void testGenerateKeyPair_EdDSA() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.EdDSA);
    assertThat(keyPair).isNotNull();
    assertThat(keyPair.getPublic()).isInstanceOf(EdECPublicKey.class);
    assertThat(keyPair.getPrivate()).isNotNull();
  }

  @Test
  void testEncodeCOSEPublicKey_EC() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
    byte[] encoded = CryptoUtils.encodeCOSEPublicKey(keyPair.getPublic(), COSEAlgorithmIdentifier.ES256);
    assertThat(encoded).isNotNull();
    assertThat(encoded.length).isGreaterThan(0);
  }

  @Test
  void testEncodeCOSEPublicKey_RSA() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.RS256);
    byte[] encoded = CryptoUtils.encodeCOSEPublicKey(keyPair.getPublic(), COSEAlgorithmIdentifier.RS256);
    assertThat(encoded).isNotNull();
    assertThat(encoded.length).isGreaterThan(0);
  }

  @Test
  void testEncodeCOSEPublicKey_EdDSA() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.EdDSA);
    byte[] encoded = CryptoUtils.encodeCOSEPublicKey(keyPair.getPublic(), COSEAlgorithmIdentifier.EdDSA);
    assertThat(encoded).isNotNull();
    assertThat(encoded.length).isGreaterThan(0);
  }

  @Test
  void testEncodeCOSEPublicKey_NullPublicKey() {
    assertThatThrownBy(() -> CryptoUtils.encodeCOSEPublicKey(null, COSEAlgorithmIdentifier.ES256))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Public key must not be null");
  }

  @Test
  void testEncodeCOSEPublicKey_NullAlgorithm() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
    assertThatThrownBy(() -> CryptoUtils.encodeCOSEPublicKey(keyPair.getPublic(), null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Algorithm must not be null");
  }

  @Test
  void testSign_ES256() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
    byte[] data = "test data".getBytes();
    byte[] signature = CryptoUtils.sign(data, keyPair.getPrivate(), COSEAlgorithmIdentifier.ES256);
    assertThat(signature).isNotNull();
    assertThat(signature.length).isGreaterThan(0);
  }

  @Test
  void testSign_RS256() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.RS256);
    byte[] data = "test data".getBytes();
    byte[] signature = CryptoUtils.sign(data, keyPair.getPrivate(), COSEAlgorithmIdentifier.RS256);
    assertThat(signature).isNotNull();
    assertThat(signature.length).isGreaterThan(0);
  }

  @Test
  void testSign_EdDSA() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.EdDSA);
    byte[] data = "test data".getBytes();
    byte[] signature = CryptoUtils.sign(data, keyPair.getPrivate(), COSEAlgorithmIdentifier.EdDSA);
    assertThat(signature).isNotNull();
    assertThat(signature.length).isGreaterThan(0);
  }

  @Test
  void testSign_NullData() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
    assertThatThrownBy(() -> CryptoUtils.sign(null, keyPair.getPrivate(), COSEAlgorithmIdentifier.ES256))
        .isInstanceOf(CryptographicException.class)
        .hasMessageContaining("Data to sign must not be null");
  }

  @Test
  void testSign_EmptyData() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
    assertThatThrownBy(() -> CryptoUtils.sign(new byte[0], keyPair.getPrivate(), COSEAlgorithmIdentifier.ES256))
        .isInstanceOf(CryptographicException.class)
        .hasMessageContaining("Data to sign must not be null or empty");
  }

  @Test
  void testGenerateAttestationCertificate() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
    UUID aaguid = UUID.randomUUID();
    // Use a valid hex string for device ID
    var cert = CryptoUtils.generateAttestationCertificate(keyPair, "1234567890ABCDEF", aaguid);

    assertThat(cert).isNotNull();
    assertThat(cert.getSubjectX500Principal().getName()).contains("YubiAuthN");
  }

  @Test
  void testGenerateAttestationCertificate_NullKeyPair() {
    UUID aaguid = UUID.randomUUID();
    assertThatThrownBy(() -> CryptoUtils.generateAttestationCertificate(null, "test-device", aaguid))
        .isInstanceOf(CryptographicException.class)
        .hasMessageContaining("Key pair must not be null");
  }

  @Test
  void testGenerateAttestationCertificate_NullAAGUID() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
    assertThatThrownBy(() -> CryptoUtils.generateAttestationCertificate(keyPair, "test-device", null))
        .isInstanceOf(CryptographicException.class)
        .hasMessageContaining("AAGUID must not be null");
  }

  @Test
  void testGenerateCredentialId() {
    byte[] credId1 = CryptoUtils.generateCredentialId();
    byte[] credId2 = CryptoUtils.generateCredentialId();

    assertThat(credId1).hasSize(16);
    assertThat(credId2).hasSize(16);
    assertThat(credId1).isNotEqualTo(credId2);
  }

  @Test
  void testEncodeU2FPublicKey() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
    byte[] u2fKey = CryptoUtils.encodeU2FPublicKey((ECPublicKey) keyPair.getPublic());

    assertThat(u2fKey).hasSize(65);
    assertThat(u2fKey[0]).isEqualTo((byte) 0x04); // Uncompressed point indicator
  }

  @Test
  void testEncodeU2FPublicKey_Null() {
    assertThatThrownBy(() -> CryptoUtils.encodeU2FPublicKey(null))
        .isInstanceOf(CryptographicException.class)
        .hasMessageContaining("Public key must not be null");
  }

  @Test
  void testCreateU2FSignatureData() throws Exception {
    byte[] rpIdHash = new byte[32];
    byte[] clientDataHash = new byte[32];
    byte[] credentialId = new byte[16];
    byte[] publicKey = new byte[65];
    publicKey[0] = 0x04;

    byte[] sigData = CryptoUtils.createU2FSignatureData(rpIdHash, clientDataHash, credentialId, publicKey);

    assertThat(sigData).isNotNull();
    assertThat(sigData.length).isEqualTo(1 + 32 + 32 + 16 + 65); // reserved + rpIdHash + clientDataHash + credId + pubKey
    assertThat(sigData[0]).isEqualTo((byte) 0x00); // Reserved byte
  }

  @Test
  void testCreateU2FSignatureData_InvalidRpIdHash() {
    byte[] badHash = new byte[31]; // Wrong size
    byte[] clientDataHash = new byte[32];
    byte[] credentialId = new byte[16];
    byte[] publicKey = new byte[65];

    assertThatThrownBy(() -> CryptoUtils.createU2FSignatureData(badHash, clientDataHash, credentialId, publicKey))
        .isInstanceOf(CryptographicException.class)
        .hasMessageContaining("RP ID hash must be 32 bytes");
  }

  @Test
  void testCreateU2FSignatureData_InvalidPublicKey() {
    byte[] rpIdHash = new byte[32];
    byte[] clientDataHash = new byte[32];
    byte[] credentialId = new byte[16];
    byte[] badPublicKey = new byte[64]; // Wrong size

    assertThatThrownBy(() -> CryptoUtils.createU2FSignatureData(rpIdHash, clientDataHash, credentialId, badPublicKey))
        .isInstanceOf(CryptographicException.class)
        .hasMessageContaining("Public key must be 65 bytes");
  }
}
