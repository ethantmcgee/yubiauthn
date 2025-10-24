package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * COSE (CBOR Object Signing and Encryption) algorithm identifiers.
 *
 * <p>This enum defines the cryptographic algorithms that can be used with WebAuthn credentials. The
 * values are COSE algorithm identifiers as registered in the IANA COSE Algorithms registry.
 *
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions#algorithm_identifiers">MDN
 *     - Algorithm Identifiers</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier">W3C WebAuthn - Algorithm
 *     Identifiers</a>
 * @see <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms
 *     Registry</a>
 */
@Getter
@RequiredArgsConstructor
public enum COSEAlgorithmIdentifier {
  /** ECDSA with SHA-256. */
  ES256(-7),
  /** EdDSA signature algorithm. */
  EdDSA(-8),
  /** ECDSA with SHA-384. */
  ES384(-35),
  /** ECDSA with SHA-512. */
  ES512(-36),
  /** RSASSA-PKCS1-v1_5 with SHA-256. */
  RS256(-257),
  /** RSASSA-PKCS1-v1_5 with SHA-384. */
  RS384(-258),
  /** RSASSA-PKCS1-v1_5 with SHA-512. */
  RS512(-259);

  @JsonValue private final int value;
}
