package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum COSEAlgorithmIdentifier {
  ES256(-7), // ECDSA with SHA-256
  EdDSA(-8), // EdDSA
  ES384(-35), // ECDSA with SHA-384
  ES512(-36), // ECDSA with SHA-512
  RS256(-257), // RSASSA-PKCS1-v1_5 with SHA-256
  RS384(-258), // RSASSA-PKCS1-v1_5 with SHA-384
  RS512(-259); // RSASSA-PKCS1-v1_5 with SHA-512

  @JsonValue private final int value;
}
