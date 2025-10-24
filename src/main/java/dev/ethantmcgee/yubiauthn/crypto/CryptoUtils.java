package dev.ethantmcgee.yubiauthn.crypto;

import static dev.ethantmcgee.yubiauthn.crypto.CryptoConstants.*;

import com.upokecenter.cbor.CBORObject;
import dev.ethantmcgee.yubiauthn.exception.CryptographicException;
import dev.ethantmcgee.yubiauthn.model.COSEAlgorithmIdentifier;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
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
    keyGen.initialize(RSA_KEY_SIZE_BITS, new SecureRandom());
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
   * @throws CryptographicException if signing fails
   */
  public static byte[] sign(byte[] data, PrivateKey privateKey, COSEAlgorithmIdentifier algorithm)
      throws CryptographicException {
    if (data == null || data.length == 0) {
      throw new CryptographicException("Data to sign must not be null or empty");
    }
    if (privateKey == null) {
      throw new CryptographicException("Private key must not be null");
    }
    if (algorithm == null) {
      throw new CryptographicException("Algorithm must not be null");
    }

    try {
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
    } catch (Exception e) {
      throw new CryptographicException("Failed to sign data with algorithm " + algorithm, e);
    }
  }

  /**
   * Generates an X.509 attestation certificate for the authenticator.
   *
   * @param keyPair the key pair to include in the certificate
   * @param deviceIdentifier the device identifier to include in the certificate extension
   * @param aaguid the authenticator AAGUID to include in the certificate extension
   * @return a self-signed X.509 certificate
   * @throws CryptographicException if certificate generation fails
   */
  public static X509Certificate generateAttestationCertificate(
      KeyPair keyPair, String deviceIdentifier, UUID aaguid) throws CryptographicException {
    if (keyPair == null) {
      throw new CryptographicException("Key pair must not be null");
    }
    if (aaguid == null) {
      throw new CryptographicException("AAGUID must not be null");
    }

    try {
      long now = System.currentTimeMillis();
      Date startDate = new Date(now);
      Date endDate = new Date(now + CERTIFICATE_VALIDITY_DAYS * MILLISECONDS_PER_DAY);

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
      if (deviceIdentifier != null) {
        certBuilder.addExtension(
            new ASN1ObjectIdentifier(OID_DEVICE_IDENTIFIER),
            false,
            new DEROctetString(hexStringToByteArray(deviceIdentifier)));
      }

      // AAGUID - must be ASN.1 encoded as OCTET STRING containing 16 bytes
      // Convert UUID to raw 16-byte representation (not hex string)
      byte[] aaguidBytes = uuidToBytes(aaguid);
      certBuilder.addExtension(
          new ASN1ObjectIdentifier(OID_AAGUID), false, new DEROctetString(aaguidBytes));

      String signingAlgorithm = getSigningAlgorithmForKey(keyPair.getPrivate());

      ContentSigner signer =
          new JcaContentSignerBuilder(signingAlgorithm)
              .setProvider(new BouncyCastleProvider())
              .build(keyPair.getPrivate());

      X509CertificateHolder certHolder = certBuilder.build(signer);
      return new JcaX509CertificateConverter()
          .setProvider(new BouncyCastleProvider())
          .getCertificate(certHolder);
    } catch (Exception e) {
      throw new CryptographicException("Failed to generate attestation certificate", e);
    }
  }

  /**
   * Converts a UUID to its 16-byte binary representation.
   *
   * @param uuid the UUID to convert
   * @return 16-byte array representation of the UUID
   */
  private static byte[] uuidToBytes(UUID uuid) {
    ByteBuffer buffer = ByteBuffer.wrap(new byte[AAGUID_LENGTH_BYTES]);
    buffer.putLong(uuid.getMostSignificantBits());
    buffer.putLong(uuid.getLeastSignificantBits());
    return buffer.array();
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
    byte[] credentialId = new byte[CREDENTIAL_ID_LENGTH_BYTES];
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
    if (publicKey == null) {
      throw new IllegalArgumentException("Public key must not be null");
    }
    if (algorithm == null) {
      throw new IllegalArgumentException("Algorithm must not be null");
    }

    CBORObject coseKey = CBORObject.NewMap();

    if (publicKey instanceof ECPublicKey ecPublicKey) {
      // EC2 key type
      coseKey.Add(COSE_KEY_PARAM_KTY, COSE_KTY_EC2);
      coseKey.Add(COSE_KEY_PARAM_ALG, algorithm.getValue());

      // Determine the curve
      int curve =
          switch (algorithm) {
            case ES256 -> COSE_CURVE_P256;
            case ES384 -> COSE_CURVE_P384;
            case ES512 -> COSE_CURVE_P521;
            default -> throw new IllegalArgumentException("Unsupported EC algorithm: " + algorithm);
          };
      coseKey.Add(COSE_KEY_PARAM_CRV, curve);

      // Extract x and y coordinates
      byte[] x = ecPublicKey.getW().getAffineX().toByteArray();
      byte[] y = ecPublicKey.getW().getAffineY().toByteArray();

      // Remove leading zero byte if present (for positive BigInteger)
      x = removeLeadingZero(x);
      y = removeLeadingZero(y);

      coseKey.Add(COSE_KEY_PARAM_X, x);
      coseKey.Add(COSE_KEY_PARAM_Y, y);
    } else if (publicKey instanceof RSAPublicKey rsaPublicKey) {
      // RSA key type
      coseKey.Add(COSE_KEY_PARAM_KTY, COSE_KTY_RSA);
      coseKey.Add(COSE_KEY_PARAM_ALG, algorithm.getValue());

      // Extract modulus and exponent
      byte[] n = rsaPublicKey.getModulus().toByteArray();
      byte[] e = rsaPublicKey.getPublicExponent().toByteArray();

      // Remove leading zero byte if present (for positive BigInteger)
      n = removeLeadingZero(n);
      e = removeLeadingZero(e);

      coseKey.Add(COSE_KEY_PARAM_N, n);
      coseKey.Add(COSE_KEY_PARAM_E, e);
    } else if (publicKey instanceof EdECPublicKey edPublicKey) {
      // OKP (Octet string key pairs) key type for EdDSA
      coseKey.Add(COSE_KEY_PARAM_KTY, COSE_KTY_OKP);
      coseKey.Add(COSE_KEY_PARAM_ALG, algorithm.getValue());
      coseKey.Add(COSE_KEY_PARAM_CRV, COSE_CURVE_ED25519);

      // For EdDSA, we need to extract the raw public key bytes
      // The EdECPublicKey interface provides the point as a BigInteger or byte array
      byte[] xCoord = getEdDSAPublicKeyBytes(edPublicKey);
      coseKey.Add(COSE_KEY_PARAM_X, xCoord);
    } else {
      throw new IllegalArgumentException(
          "Unsupported public key type: " + publicKey.getClass().getName());
    }

    // Use upokecenter CBOR library for definite-length encoding
    return coseKey.EncodeToBytes();
  }

  /**
   * Extracts the raw public key bytes from an EdDSA public key.
   *
   * @param edPublicKey the EdDSA public key
   * @return the raw public key bytes (32 bytes for Ed25519)
   */
  private static byte[] getEdDSAPublicKeyBytes(EdECPublicKey edPublicKey) {
    // For EdDSA keys, we need to extract the raw public key point
    // The encoded form has ASN.1 structure, so we need to extract just the key bytes
    byte[] encoded = edPublicKey.getEncoded();
    // For Ed25519, the public key is the last 32 bytes of the encoded form
    // SubjectPublicKeyInfo format: typically the last 32 bytes are the actual key
    return Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
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
        ByteBuffer.allocate(AAGUID_LENGTH_BYTES + 2 + credentialId.length + credentialPublicKey.length);
    buffer.put(aaguid);
    buffer.putShort((short) credentialId.length);
    buffer.put(credentialId);
    buffer.put(credentialPublicKey);
    return buffer.array();
  }

  /**
   * Creates the signature data for FIDO U2F attestation format.
   *
   * <p>The U2F signature is computed over: 0x00 || rpIdHash || clientDataHash || credentialId ||
   * publicKey
   *
   * @param rpIdHash the SHA-256 hash of the RP ID (32 bytes)
   * @param clientDataHash the SHA-256 hash of the client data JSON (32 bytes)
   * @param credentialId the credential identifier
   * @param publicKey the uncompressed EC public key (65 bytes: 0x04 || x || y)
   * @return the signature data for U2F attestation
   * @throws CryptographicException if signature data creation fails
   */
  public static byte[] createU2FSignatureData(
      byte[] rpIdHash, byte[] clientDataHash, byte[] credentialId, byte[] publicKey)
      throws CryptographicException {
    if (rpIdHash == null || rpIdHash.length != 32) {
      throw new CryptographicException("RP ID hash must be 32 bytes");
    }
    if (clientDataHash == null || clientDataHash.length != 32) {
      throw new CryptographicException("Client data hash must be 32 bytes");
    }
    if (credentialId == null || credentialId.length == 0) {
      throw new CryptographicException("Credential ID must not be null or empty");
    }
    if (publicKey == null || publicKey.length != U2F_PUBLIC_KEY_LENGTH) {
      throw new CryptographicException(
          "Public key must be " + U2F_PUBLIC_KEY_LENGTH + " bytes (uncompressed EC point)");
    }

    try {
      ByteArrayOutputStream sigData = new ByteArrayOutputStream();
      sigData.write(U2F_RESERVED_BYTE);
      sigData.write(rpIdHash);
      sigData.write(clientDataHash);
      sigData.write(credentialId);
      sigData.write(publicKey);
      return sigData.toByteArray();
    } catch (IOException e) {
      throw new CryptographicException("Failed to create U2F signature data", e);
    }
  }

  /**
   * Encodes an EC public key in uncompressed format for U2F attestation.
   *
   * <p>Returns 65 bytes: 0x04 || x-coordinate (32 bytes) || y-coordinate (32 bytes)
   *
   * @param publicKey the EC public key (must be P-256)
   * @return the uncompressed public key bytes
   * @throws CryptographicException if encoding fails or key is not P-256
   */
  public static byte[] encodeU2FPublicKey(ECPublicKey publicKey) throws CryptographicException {
    if (publicKey == null) {
      throw new CryptographicException("Public key must not be null");
    }

    // Extract x and y coordinates
    byte[] x = publicKey.getW().getAffineX().toByteArray();
    byte[] y = publicKey.getW().getAffineY().toByteArray();

    // Remove leading zero byte if present and pad to 32 bytes
    x = padTo32Bytes(removeLeadingZero(x));
    y = padTo32Bytes(removeLeadingZero(y));

    ByteBuffer buffer = ByteBuffer.allocate(U2F_PUBLIC_KEY_LENGTH);
    buffer.put(UNCOMPRESSED_POINT_INDICATOR);
    buffer.put(x);
    buffer.put(y);
    return buffer.array();
  }

  /**
   * Pads a byte array to 32 bytes by prepending zeros if necessary.
   *
   * @param bytes the input byte array
   * @return a 32-byte array
   * @throws CryptographicException if input is longer than 32 bytes
   */
  private static byte[] padTo32Bytes(byte[] bytes) throws CryptographicException {
    if (bytes.length > EC_P256_COORDINATE_LENGTH) {
      throw new CryptographicException(
          "Coordinate is longer than " + EC_P256_COORDINATE_LENGTH + " bytes");
    }
    if (bytes.length == EC_P256_COORDINATE_LENGTH) {
      return bytes;
    }
    byte[] padded = new byte[EC_P256_COORDINATE_LENGTH];
    System.arraycopy(bytes, 0, padded, EC_P256_COORDINATE_LENGTH - bytes.length, bytes.length);
    return padded;
  }
}
