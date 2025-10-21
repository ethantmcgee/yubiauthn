package dev.ethantmcgee.yubiauthn.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import dev.ethantmcgee.yubiauthn.model.COSEAlgorithmIdentifier;
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

/**
 * Cryptographic utility methods for WebAuthn operations.
 *
 * <p>This class provides essential cryptographic operations needed for WebAuthn authenticator
 * implementations, including key pair generation, COSE key encoding, digital signatures, and
 * attestation certificate generation.
 *
 * <p>Supports multiple cryptographic algorithms as specified in the COSE (CBOR Object Signing and
 * Encryption) specification, including:
 *
 * <ul>
 *   <li>ECDSA with P-256, P-384, and P-521 curves
 *   <li>RSA with SHA-256, SHA-384, and SHA-512
 *   <li>EdDSA (Ed25519)
 * </ul>
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges">W3C WebAuthn -
 *     Cryptographic Challenges</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8152">RFC 8152 - COSE</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-attestation">W3C WebAuthn - Attestation</a>
 */
public class CryptoUtils {
  private static final ObjectMapper cborMapper = createCborMapper();

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * Creates a properly configured ObjectMapper for CBOR encoding.
   *
   * <p>This method configures Jackson's CBORFactory to ensure compatibility with WebAuthn
   * specification requirements. WebAuthn requires canonical CBOR encoding with definite-length
   * maps and arrays (not indefinite-length).
   *
   * @return A configured ObjectMapper for CBOR encoding with definite-length encoding
   */
  private static ObjectMapper createCborMapper() {
    // Configure CBOR factory to use definite-length encoding (required by WebAuthn spec)
    // This prevents the use of CBOR indefinite-length maps (0xBF...0xFF) and arrays
    CBORFactory cborFactory =
        CBORFactory.builder()
            .disable(com.fasterxml.jackson.dataformat.cbor.CBORGenerator.Feature.WRITE_TYPE_HEADER)
            .enable(com.fasterxml.jackson.dataformat.cbor.CBORGenerator.Feature.WRITE_MINIMAL_INTS)
            .build();
    return new ObjectMapper(cborFactory);
  }

  /**
   * Generates a cryptographic key pair for the specified COSE algorithm.
   *
   * <p>This method creates a new key pair suitable for use with WebAuthn credentials. The type of
   * key pair (EC, RSA, or EdDSA) depends on the specified algorithm.
   *
   * @param algorithm The COSE algorithm identifier specifying which algorithm to use
   * @return A newly generated key pair appropriate for the algorithm
   * @throws NoSuchAlgorithmException If the algorithm is not available
   * @throws InvalidAlgorithmParameterException If the algorithm parameters are invalid
   * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-public-key-easy">W3C WebAuthn - Public Key
   *     Credential</a>
   */
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

  private static KeyPair generateEdDSAKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", new BouncyCastleProvider());
    return keyGen.generateKeyPair();
  }

  /**
   * Encodes a public key in COSE format according to RFC 8152.
   *
   * <p>The encoded public key is suitable for inclusion in WebAuthn authenticator data as the
   * credential public key. The format follows the COSE key structure with appropriate parameters
   * for the key type (EC2 for elliptic curve keys).
   *
   * @param publicKey The public key to encode (currently supports EC public keys)
   * @param algorithm The COSE algorithm identifier
   * @return The CBOR-encoded COSE key bytes
   * @throws IOException If CBOR encoding fails
   * @throws IllegalArgumentException If the public key type is unsupported
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc8152#section-13">RFC 8152 - COSE Key
   *     Objects</a>
   * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-encoded-credPubKey-examples">W3C WebAuthn
   *     - Credential Public Key Examples</a>
   */
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

    // Use Jackson CBOR mapper instead of manual encoding
    return cborMapper.writeValueAsBytes(coseKey);
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
   * Creates a digital signature over the provided data using the specified private key and
   * algorithm.
   *
   * <p>This method is used to generate signatures for WebAuthn assertion responses and attestation
   * statements. The signature algorithm is determined by the COSE algorithm identifier.
   *
   * @param data The data to sign
   * @param privateKey The private key to use for signing
   * @param algorithm The COSE algorithm identifier specifying the signature algorithm
   * @return The digital signature bytes
   * @throws Exception If signature generation fails
   * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion">W3C WebAuthn - Signature
   *     Generation</a>
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
   * Generates a self-signed X.509 attestation certificate for WebAuthn attestation.
   *
   * <p>This certificate is used in the attestation statement to provide cryptographic proof of the
   * authenticator's characteristics. The certificate is self-signed and valid for one year.
   *
   * @param keyPair The key pair for which to generate the certificate
   * @param subject The X.500 distinguished name for the certificate subject (e.g.,
   *     "CN=MyAuthenticator")
   * @return A self-signed X.509 certificate
   * @throws Exception If certificate generation fails
   * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-attestation">W3C WebAuthn -
   *     Attestation</a>
   * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C WebAuthn - Packed
   *     Attestation</a>
   */
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

    // Determine the signing algorithm based on the key type
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

  /**
   * Determines the appropriate signing algorithm for a given private key.
   *
   * @param privateKey The private key
   * @return The signing algorithm name (e.g., "SHA256withECDSA")
   */
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
   * Creates the attested credential data structure for inclusion in authenticator data.
   *
   * <p>The attested credential data contains the AAGUID, credential ID, and credential public key
   * in the format specified by the WebAuthn specification. This data is included in the
   * authenticator data during credential creation.
   *
   * @param aaguid The Authenticator Attestation GUID (16 bytes)
   * @param credentialId The unique identifier for this credential
   * @param credentialPublicKey The COSE-encoded credential public key
   * @return The encoded attested credential data bytes
   * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">W3C WebAuthn -
   *     Attested Credential Data</a>
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

  /**
   * Generates a cryptographically random credential ID.
   *
   * <p>This method creates a new 16-byte (128-bit) credential ID using a secure random number
   * generator. The credential ID is used to uniquely identify a credential.
   *
   * @return A 16-byte random credential ID
   * @see <a href="https://www.w3.org/TR/webauthn-3/#credential-id">W3C WebAuthn - Credential ID</a>
   */
  public static byte[] generateCredentialId() {
    byte[] credentialId = new byte[16];
    new SecureRandom().nextBytes(credentialId);
    return credentialId;
  }

  /**
   * Converts a COSE-encoded public key to FIDO U2F raw format.
   *
   * <p>FIDO U2F requires the public key in raw EC point format: 0x04 || X || Y (65 bytes for
   * P-256). This method extracts the X and Y coordinates from the COSE key structure and formats
   * them accordingly.
   *
   * @param cosePublicKey The CBOR-encoded COSE public key
   * @return The raw EC public key in U2F format (65 bytes: 0x04 || X || Y)
   * @throws IOException If CBOR decoding fails
   * @throws IllegalArgumentException If the key is not a valid EC2 key
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#registration-response-message-success">FIDO
   *     U2F Raw Message Formats</a>
   */
  public static byte[] cosePublicKeyToU2F(byte[] cosePublicKey) throws IOException {
    // Decode the COSE key structure
    // Jackson may decode integer keys as either Integer or String, so we need to handle both
    @SuppressWarnings("unchecked")
    Map<Object, Object> coseKey = cborMapper.readValue(cosePublicKey, Map.class);

    // Verify it's an EC2 key (kty = 2)
    Object ktyObj = getMapValue(coseKey, 1);
    Integer kty = toInteger(ktyObj);
    if (kty == null || kty != 2) {
      throw new IllegalArgumentException("Not an EC2 key: kty=" + kty);
    }

    // Extract X and Y coordinates
    byte[] x = (byte[]) getMapValue(coseKey, -2);
    byte[] y = (byte[]) getMapValue(coseKey, -3);

    if (x == null || y == null) {
      throw new IllegalArgumentException("Missing X or Y coordinate in COSE key");
    }

    // Ensure X and Y are 32 bytes each (for P-256)
    x = padOrTrimTo32Bytes(x);
    y = padOrTrimTo32Bytes(y);

    // Build U2F format: 0x04 || X || Y
    byte[] u2fKey = new byte[65];
    u2fKey[0] = 0x04; // Uncompressed point indicator
    System.arraycopy(x, 0, u2fKey, 1, 32);
    System.arraycopy(y, 0, u2fKey, 33, 32);

    return u2fKey;
  }

  /**
   * Extracts a single CBOR-encoded value from a byte array starting at the specified offset.
   *
   * <p>This method parses the CBOR structure to determine the exact length of a single CBOR value,
   * which is essential when extracting COSE public keys from authenticator data that may contain
   * additional data (like extensions) after the public key.
   *
   * @param data The byte array containing CBOR data
   * @param offset The offset where the CBOR value starts
   * @return The extracted CBOR value bytes (including CBOR structure)
   * @throws IOException If CBOR parsing fails or data is malformed
   */
  public static byte[] extractCborValue(byte[] data, int offset) throws IOException {
    // Use a JsonParser (CBOR implementation) to determine the exact length of the CBOR value
    com.fasterxml.jackson.core.JsonParser parser =
        cborMapper.getFactory().createParser(data, offset, data.length - offset);

    // Read one complete token/value to advance the parser
    parser.nextToken();
    // Skip children if this is a structured value (map, array)
    parser.skipChildren();

    // The current location tells us where the CBOR value ends
    long bytesConsumed = parser.getCurrentLocation().getByteOffset();

    parser.close();

    // Extract exactly those bytes
    return java.util.Arrays.copyOfRange(data, offset, offset + (int) bytesConsumed);
  }

  /**
   * Helper method to get a value from a map that may have integer or string keys.
   *
   * @param map The map
   * @param key The integer key
   * @return The value, or null if not found
   */
  private static Object getMapValue(Map<Object, Object> map, int key) {
    // Try integer key first
    Object value = map.get(key);
    if (value != null) {
      return value;
    }
    // Try string key
    return map.get(String.valueOf(key));
  }

  /**
   * Converts an object to an Integer if possible.
   *
   * @param obj The object to convert
   * @return The integer value, or null if conversion fails
   */
  private static Integer toInteger(Object obj) {
    if (obj instanceof Integer) {
      return (Integer) obj;
    } else if (obj instanceof Number) {
      return ((Number) obj).intValue();
    } else if (obj instanceof String) {
      try {
        return Integer.parseInt((String) obj);
      } catch (NumberFormatException e) {
        return null;
      }
    }
    return null;
  }

  /**
   * Pads or trims a byte array to exactly 32 bytes.
   *
   * @param bytes The input byte array
   * @return A 32-byte array
   */
  private static byte[] padOrTrimTo32Bytes(byte[] bytes) {
    if (bytes.length == 32) {
      return bytes;
    } else if (bytes.length > 32) {
      // Trim from the left (remove leading zeros)
      byte[] trimmed = new byte[32];
      System.arraycopy(bytes, bytes.length - 32, trimmed, 0, 32);
      return trimmed;
    } else {
      // Pad with leading zeros
      byte[] padded = new byte[32];
      System.arraycopy(bytes, 0, padded, 32 - bytes.length, bytes.length);
      return padded;
    }
  }
}
