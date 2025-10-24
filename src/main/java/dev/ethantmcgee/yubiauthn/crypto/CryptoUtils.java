package dev.ethantmcgee.yubiauthn.crypto;

import com.upokecenter.cbor.CBORObject;
import dev.ethantmcgee.yubiauthn.model.COSEAlgorithmIdentifier;
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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Utility class providing cryptographic operations for WebAuthn credential creation and
 * authentication.
 *
 * <p>This class offers methods for key pair generation, digital signatures, certificate generation,
 * and COSE key encoding as required by the WebAuthn specification. It uses Bouncy Castle as the
 * cryptographic provider.
 */
public class CryptoUtils {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * Generates a key pair for the specified cryptographic algorithm.
   *
   * @param algorithm the COSE algorithm identifier specifying which key type to generate
   * @return a newly generated key pair suitable for the specified algorithm
   * @throws NoSuchAlgorithmException if the algorithm is not supported
   * @throws InvalidAlgorithmParameterException if the algorithm parameters are invalid
   */
  public static KeyPair generateKeyPair(COSEAlgorithmIdentifier algorithm)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    return switch (algorithm) {
      case ES256 -> generateECKeyPair("secp256r1");
      case ES384 -> generateECKeyPair("secp384r1");
      case ES512 -> generateECKeyPair("secp521r1");
      case RS256, RS384, RS512 -> generateRSAKeyPair();
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

  private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
    keyGen.initialize(2048, new SecureRandom());
    return keyGen.generateKeyPair();
  }

  private static KeyPair generateEdDSAKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", new BouncyCastleProvider());
    return keyGen.generateKeyPair();
  }

  /**
   * Signs data using the specified private key and algorithm.
   *
   * @param data the data to sign
   * @param privateKey the private key to use for signing
   * @param algorithm the COSE algorithm identifier specifying the signature algorithm
   * @return the digital signature
   * @throws Exception if signing fails
   */
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

  /**
   * Generates an X.509 attestation certificate for the authenticator.
   *
   * @param keyPair the key pair to include in the certificate
   * @param deviceIdentifier the device identifier to include in the certificate extension
   * @param aaguid the authenticator AAGUID to include in the certificate extension
   * @return a self-signed X.509 certificate
   * @throws CertIOException if there is an error adding certificate extensions
   * @throws CertificateException if there is an error creating the certificate
   * @throws OperatorCreationException if there is an error creating the content signer
   */
  public static X509Certificate generateAttestationCertificate(
      KeyPair keyPair, String deviceIdentifier, UUID aaguid)
      throws CertIOException, CertificateException, OperatorCreationException {
    long now = System.currentTimeMillis();
    Date startDate = new Date(now);
    Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1 year validity

    X500Name issuer = new X500Name("CN=YubiAuthN");
    X500Name subjectName =
        new X500Name("CN=YubiAuthN,OU=Authenticator Attestation,O=YubiAuthN,C=US");
    BigInteger serialNumber = new BigInteger(Long.toString(now));

    SubjectPublicKeyInfo subjectPublicKeyInfo =
        SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

    X509v3CertificateBuilder certBuilder =
        new X509v3CertificateBuilder(
            issuer, serialNumber, startDate, endDate, subjectName, subjectPublicKeyInfo);
    // Device Identifier - must be ASN.1 encoded as OCTET STRING
    certBuilder.addExtension(
        new ASN1ObjectIdentifier("1.3.6.1.4.1.41482.2"),
        false,
        new DEROctetString(hexStringToByteArray(deviceIdentifier)));
    // AAGUID - must be ASN.1 encoded as OCTET STRING containing 16 bytes
    certBuilder.addExtension(
        new ASN1ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"),
        false,
        new DEROctetString(hexStringToByteArray(aaguid.toString())));

    String signingAlgorithm = getSigningAlgorithmForKey(keyPair.getPrivate());

    ContentSigner signer =
        new JcaContentSignerBuilder(signingAlgorithm)
            .setProvider(new BouncyCastleProvider())
            .build(keyPair.getPrivate());

    X509CertificateHolder certHolder = certBuilder.build(signer);
    return new JcaX509CertificateConverter()
        .setProvider(new BouncyCastleProvider())
        .getCertificate(certHolder);
  }

  private static String getSigningAlgorithmForKey(PrivateKey privateKey) {
    String algorithm = privateKey.getAlgorithm();
    return switch (algorithm) {
      case "EC" -> "SHA256withECDSA";
      case "RSA" -> "SHA256withRSA";
      case "Ed25519", "EdDSA" -> "Ed25519";
      default -> throw new IllegalArgumentException("Unsupported key algorithm: " + algorithm);
    };
  }

  /**
   * Converts a hexadecimal string to a byte array.
   *
   * @param hexString the hex string to convert (may contain hyphens or other separators)
   * @return the byte array representation of the hex string
   * @throws RuntimeException if the hex string has an odd number of characters
   */
  public static byte[] hexStringToByteArray(String hexString) {
    if (hexString == null) {
      return new byte[] {};
    }

    hexString = hexString.replaceAll("[^0-9A-Fa-f]", "");

    if (hexString.length() % 2 != 0) {
      throw new RuntimeException("Hex string must have an even number of characters");
    }

    int len = hexString.length();
    byte[] data = new byte[len / 2];

    for (int i = 0; i < len; i += 2) {
      data[i / 2] =
          (byte)
              ((Character.digit(hexString.charAt(i), 16) << 4)
                  + Character.digit(hexString.charAt(i + 1), 16));
    }

    return data;
  }

  /**
   * Generates a random credential ID.
   *
   * @return a 16-byte random credential identifier
   */
  public static byte[] generateCredentialId() {
    byte[] credentialId = new byte[16];
    new SecureRandom().nextBytes(credentialId);
    return credentialId;
  }

  /**
   * Encodes a public key in COSE (CBOR Object Signing and Encryption) format.
   *
   * @param publicKey the public key to encode
   * @param algorithm the COSE algorithm identifier for the key
   * @return the COSE-encoded public key as a byte array
   * @throws IllegalArgumentException if the public key type is not supported
   */
  public static byte[] encodeCOSEPublicKey(PublicKey publicKey, COSEAlgorithmIdentifier algorithm) {
    CBORObject coseKey = CBORObject.NewMap();

    if (publicKey instanceof ECPublicKey ecPublicKey) {
      // EC2 key type
      coseKey.Add(1, 2); // kty: EC2
      coseKey.Add(3, algorithm.getValue()); // alg

      // Determine the curve
      int curve =
          switch (algorithm) {
            case ES256 -> 1; // P-256
            case ES384 -> 2; // P-384
            case ES512 -> 3; // P-521
            default -> throw new IllegalArgumentException("Unsupported EC algorithm: " + algorithm);
          };
      coseKey.Add(-1, curve); // crv

      // Extract x and y coordinates
      byte[] x = ecPublicKey.getW().getAffineX().toByteArray();
      byte[] y = ecPublicKey.getW().getAffineY().toByteArray();

      // Remove leading zero byte if present (for positive BigInteger)
      x = removeLeadingZero(x);
      y = removeLeadingZero(y);

      coseKey.Add(-2, x); // x coordinate
      coseKey.Add(-3, y); // y coordinate
    } else {
      throw new IllegalArgumentException(
          "Unsupported public key type: " + publicKey.getClass().getName());
    }

    // Use upokecenter CBOR library for definite-length encoding
    return coseKey.EncodeToBytes();
  }

  private static byte[] removeLeadingZero(byte[] bytes) {
    if (bytes.length > 0 && bytes[0] == 0) {
      byte[] result = new byte[bytes.length - 1];
      System.arraycopy(bytes, 1, result, 0, result.length);
      return result;
    }
    return bytes;
  }

  /**
   * Creates the attested credential data structure as defined in the WebAuthn specification.
   *
   * @param aaguid the authenticator attestation GUID (16 bytes)
   * @param credentialId the credential identifier
   * @param credentialPublicKey the COSE-encoded credential public key
   * @return the attested credential data structure
   */
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
}
