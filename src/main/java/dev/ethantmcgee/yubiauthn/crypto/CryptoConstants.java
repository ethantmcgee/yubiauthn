package dev.ethantmcgee.yubiauthn.crypto;

/**
 * Cryptographic and WebAuthn-related constants used throughout the library.
 *
 * <p>This class centralizes magic numbers and string constants to improve code readability and
 * maintainability.
 */
public final class CryptoConstants {
  // Prevent instantiation
  private CryptoConstants() {}

  /** Length of credential ID in bytes. */
  public static final int CREDENTIAL_ID_LENGTH_BYTES = 16;

  /** Length of AAGUID in bytes. */
  public static final int AAGUID_LENGTH_BYTES = 16;

  /** Length of EC P-256 coordinate in bytes. */
  public static final int EC_P256_COORDINATE_LENGTH = 32;

  /** Length of EC P-384 coordinate in bytes. */
  public static final int EC_P384_COORDINATE_LENGTH = 48;

  /** Length of EC P-521 coordinate in bytes. */
  public static final int EC_P521_COORDINATE_LENGTH = 66;

  /** Length of uncompressed EC point for U2F (1 byte prefix + x + y for P-256). */
  public static final int U2F_PUBLIC_KEY_LENGTH = 65;

  /** Uncompressed EC point format indicator. */
  public static final byte UNCOMPRESSED_POINT_INDICATOR = 0x04;

  /** Reserved byte for U2F signature data. */
  public static final byte U2F_RESERVED_BYTE = 0x00;

  /** Certificate validity period in days. */
  public static final long CERTIFICATE_VALIDITY_DAYS = 365;

  /** Milliseconds per day for certificate validity calculations. */
  public static final long MILLISECONDS_PER_DAY = 24L * 60 * 60 * 1000;

  /** OID for device identifier in attestation certificates (Yubico-specific). */
  public static final String OID_DEVICE_IDENTIFIER = "1.3.6.1.4.1.41482.2";

  /** OID for AAGUID in attestation certificates (FIDO Alliance). */
  public static final String OID_AAGUID = "1.3.6.1.4.1.45724.1.1.4";

  /** RSA key size in bits. */
  public static final int RSA_KEY_SIZE_BITS = 2048;

  /** COSE key type for OKP (Octet string key pairs, used for EdDSA). */
  public static final int COSE_KTY_OKP = 1;

  /** COSE key type for EC2 (Elliptic Curve keys with x and y coordinates). */
  public static final int COSE_KTY_EC2 = 2;

  /** COSE key type for RSA. */
  public static final int COSE_KTY_RSA = 3;

  /** COSE curve identifier for P-256. */
  public static final int COSE_CURVE_P256 = 1;

  /** COSE curve identifier for P-384. */
  public static final int COSE_CURVE_P384 = 2;

  /** COSE curve identifier for P-521. */
  public static final int COSE_CURVE_P521 = 3;

  /** COSE curve identifier for Ed25519. */
  public static final int COSE_CURVE_ED25519 = 6;

  /** COSE key parameter: key type (kty). */
  public static final int COSE_KEY_PARAM_KTY = 1;

  /** COSE key parameter: algorithm (alg). */
  public static final int COSE_KEY_PARAM_ALG = 3;

  /** COSE key parameter: curve (crv). */
  public static final int COSE_KEY_PARAM_CRV = -1;

  /** COSE key parameter: x-coordinate or x-value. */
  public static final int COSE_KEY_PARAM_X = -2;

  /** COSE key parameter: y-coordinate (EC2 only). */
  public static final int COSE_KEY_PARAM_Y = -3;

  /** COSE key parameter: RSA modulus. */
  public static final int COSE_KEY_PARAM_N = -1;

  /** COSE key parameter: RSA public exponent. */
  public static final int COSE_KEY_PARAM_E = -2;
}
