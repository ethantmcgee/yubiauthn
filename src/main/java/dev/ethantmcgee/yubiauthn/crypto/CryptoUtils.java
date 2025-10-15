package dev.ethantmcgee.yubiauthn.crypto;

import dev.ethantmcgee.yubiauthn.model.COSEAlgorithmIdentifier;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CryptoUtils {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public static KeyPair generateKeyPair(COSEAlgorithmIdentifier algorithm)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    return switch (algorithm) {
      case ES256 -> generateECKeyPair("secp256r1");
      case ES384 -> generateECKeyPair("secp384r1");
      case ES512 -> generateECKeyPair("secp521r1");
      case RS256, RS384, RS512 -> generateRSAKeyPair(2048);
      case EdDSA -> generateEdDSAKeyPair();
    };
  }

  private static KeyPair generateECKeyPair(String curveName)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
    ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
    keyGen.initialize(ecSpec, new SecureRandom());
    return keyGen.generateKeyPair();
  }

  private static KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
    keyGen.initialize(keySize, new SecureRandom());
    return keyGen.generateKeyPair();
  }

  private static KeyPair generateEdDSAKeyPair()
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", new BouncyCastleProvider());
    return keyGen.generateKeyPair();
  }

  /** Encodes a public key in COSE format according to RFC 8152. */
  public static byte[] encodeCOSEPublicKey(PublicKey publicKey, COSEAlgorithmIdentifier algorithm)
      throws IOException {
    Map<Integer, Object> coseKey = new HashMap<>();

    if (publicKey instanceof ECPublicKey ecPublicKey) {
      // EC2 key type
      coseKey.put(1, 2); // kty: EC2
      coseKey.put(3, algorithm.getValue()); // alg

      // Determine the curve
      int curve =
          switch (algorithm) {
            case ES256 -> 1; // P-256
            case ES384 -> 2; // P-384
            case ES512 -> 3; // P-521
            default -> throw new IllegalArgumentException("Unsupported EC algorithm: " + algorithm);
          };
      coseKey.put(-1, curve); // crv

      // Extract x and y coordinates
      byte[] x = ecPublicKey.getW().getAffineX().toByteArray();
      byte[] y = ecPublicKey.getW().getAffineY().toByteArray();

      // Remove leading zero byte if present (for positive BigInteger)
      x = removeLeadingZero(x);
      y = removeLeadingZero(y);

      coseKey.put(-2, x); // x coordinate
      coseKey.put(-3, y); // y coordinate
    } else {
      throw new IllegalArgumentException(
          "Unsupported public key type: " + publicKey.getClass().getName());
    }

    return encodeCBOR(coseKey);
  }

  private static byte[] removeLeadingZero(byte[] bytes) {
    if (bytes.length > 0 && bytes[0] == 0) {
      byte[] result = new byte[bytes.length - 1];
      System.arraycopy(bytes, 1, result, 0, result.length);
      return result;
    }
    return bytes;
  }

  private static byte[] encodeCBOR(Map<Integer, Object> map) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    // Major type 5 (map) with additional info for count
    baos.write(0xA0 | map.size());

    // Sort keys for deterministic encoding
    map.keySet().stream()
        .sorted()
        .forEach(
            key -> {
              try {
                // Encode key (negative or positive integer)
                encodeCBORInteger(baos, key);

                // Encode value
                Object value = map.get(key);
                if (value instanceof Integer intValue) {
                  encodeCBORInteger(baos, intValue);
                } else if (value instanceof byte[] byteValue) {
                  encodeCBORByteString(baos, byteValue);
                }
              } catch (IOException e) {
                throw new RuntimeException(e);
              }
            });

    return baos.toByteArray();
  }

  private static void encodeCBORInteger(ByteArrayOutputStream baos, int value) throws IOException {
    if (value >= 0) {
      if (value < 24) {
        baos.write(value);
      } else if (value < 256) {
        baos.write(0x18);
        baos.write(value);
      } else {
        baos.write(0x19);
        baos.write((value >> 8) & 0xFF);
        baos.write(value & 0xFF);
      }
    } else {
      // Negative integer
      int absValue = -1 - value;
      if (absValue < 24) {
        baos.write(0x20 | absValue);
      } else if (absValue < 256) {
        baos.write(0x38);
        baos.write(absValue);
      }
    }
  }

  private static void encodeCBORByteString(ByteArrayOutputStream baos, byte[] bytes)
      throws IOException {
    if (bytes.length < 24) {
      baos.write(0x40 | bytes.length);
    } else if (bytes.length < 256) {
      baos.write(0x58);
      baos.write(bytes.length);
    } else {
      baos.write(0x59);
      baos.write((bytes.length >> 8) & 0xFF);
      baos.write(bytes.length & 0xFF);
    }
    baos.write(bytes);
  }

  public static byte[] sign(byte[] data, PrivateKey privateKey, COSEAlgorithmIdentifier algorithm)
      throws Exception {
    String signatureAlgorithm =
        switch (algorithm) {
          case ES256 -> "SHA256withECDSA";
          case ES384 -> "SHA384withECDSA";
          case ES512 -> "SHA512withECDSA";
          case RS256 -> "SHA256withRSA";
          case RS384 -> "SHA384withRSA";
          case RS512 -> "SHA512withRSA";
          case EdDSA -> "Ed25519";
        };

    Signature signature = Signature.getInstance(signatureAlgorithm, new BouncyCastleProvider());
    signature.initSign(privateKey);
    signature.update(data);
    return signature.sign();
  }

  public static X509Certificate generateAttestationCertificate(KeyPair keyPair, String subject)
      throws Exception {
    long now = System.currentTimeMillis();
    Date startDate = new Date(now);
    Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1 year validity

    X500Name issuer = new X500Name("CN=YubiKey NFC 5C Emulator,O=YubiAuthn,C=US");
    X500Name subjectName = new X500Name(subject);
    BigInteger serialNumber = new BigInteger(Long.toString(now));

    SubjectPublicKeyInfo subjectPublicKeyInfo =
        SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

    X509v3CertificateBuilder certBuilder =
        new X509v3CertificateBuilder(
            issuer, serialNumber, startDate, endDate, subjectName, subjectPublicKeyInfo);

    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider(new BouncyCastleProvider())
            .build(keyPair.getPrivate());

    X509CertificateHolder certHolder = certBuilder.build(signer);
    return new JcaX509CertificateConverter()
        .setProvider(new BouncyCastleProvider())
        .getCertificate(certHolder);
  }

  public static byte[] createAttestedCredentialData(
      byte[] aaguid, byte[] credentialId, byte[] credentialPublicKey) {
    ByteBuffer buffer =
        ByteBuffer.allocate(16 + 2 + credentialId.length + credentialPublicKey.length);
    buffer.put(aaguid);
    buffer.putShort((short) credentialId.length);
    buffer.put(credentialId);
    buffer.put(credentialPublicKey);
    return buffer.array();
  }

  public static byte[] generateCredentialId() {
    byte[] credentialId = new byte[16];
    new SecureRandom().nextBytes(credentialId);
    return credentialId;
  }

  public static byte[] generateChallenge() {
    byte[] challenge = new byte[32];
    new SecureRandom().nextBytes(challenge);
    return challenge;
  }
}
