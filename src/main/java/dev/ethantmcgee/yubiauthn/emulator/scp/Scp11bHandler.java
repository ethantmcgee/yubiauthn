package dev.ethantmcgee.yubiauthn.emulator.scp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Handles SCP11b secure channel protocol for YubiKey emulation.
 *
 * <p>SCP11b is a secure channel protocol that uses ECDH key agreement with ephemeral keys on both
 * sides to establish session keys for encryption and MAC operations.
 */
public record Scp11bHandler(KeyPair sdEckaKeyPair, List<X509Certificate> certificates) {
  /**
   * Processes an INTERNAL AUTHENTICATE command for SCP11b key agreement.
   *
   * @param commandData the command data containing ephemeral OCE public key
   * @return a pair containing the response data and the established ScpState
   * @throws Exception if key agreement fails
   */
  public Scp11bResult processInternalAuthenticate(byte[] commandData) throws Exception {
    // Parse the command data
    // Expected format:
    // A6 (params): 90 (SCP params), 95 (key usage), 80 (key type), 81 (key len)
    // 5F49 (ephemeral OCE public key)

    List<Tlv> tlvs = Tlv.parseAll(commandData);

    byte[] keyUsage = null;
    byte[] keyType = null;
    byte[] keyLen = null;
    byte[] epkOceEncodedPoint = null;

    for (Tlv tlv : tlvs) {
      if (tlv.tag == 0xA6) {
        // Parse nested TLVs in A6
        List<Tlv> nestedTlvs = Tlv.parseAll(tlv.value);
        for (Tlv nested : nestedTlvs) {
          switch (nested.tag) {
            case 0x95 -> keyUsage = nested.value;
            case 0x80 -> keyType = nested.value;
            case 0x81 -> keyLen = nested.value;
          }
        }
      } else if (tlv.tag == 0x5F49) {
        epkOceEncodedPoint = tlv.value;
      }
    }

    if (epkOceEncodedPoint == null) {
      throw new IllegalArgumentException("Missing ephemeral OCE public key");
    }
    if (keyUsage == null) keyUsage = new byte[] {0x3C};
    if (keyType == null) keyType = new byte[] {(byte) 0x88};
    if (keyLen == null) keyLen = new byte[] {0x10};

    // Generate ephemeral SD key pair
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair ephemeralSdEcka = kpg.generateKeyPair();

    // Get the ephemeral SD public key as encoded point
    ECPublicKey ephemeralSdPubKey = (ECPublicKey) ephemeralSdEcka.getPublic();
    byte[] epkSdEncodedPoint = encodeEcPoint(ephemeralSdPubKey);

    // Decode the OCE ephemeral public key
    ECPublicKey epkOce = decodeEcPoint(epkOceEncodedPoint);

    // Perform ECDH key agreements
    // ka1 = ECDH(ephemeral_sd_private, ephemeral_oce_public)
    KeyAgreement ka1Agreement = KeyAgreement.getInstance("ECDH");
    ka1Agreement.init(ephemeralSdEcka.getPrivate());
    ka1Agreement.doPhase(epkOce, true);
    byte[] ka1 = ka1Agreement.generateSecret();

    // ka2 = ECDH(static_sd_private, ephemeral_oce_public) for SCP11b
    KeyAgreement ka2Agreement = KeyAgreement.getInstance("ECDH");
    ka2Agreement.init(sdEckaKeyPair.getPrivate());
    ka2Agreement.doPhase(epkOce, true);
    byte[] ka2 = ka2Agreement.generateSecret();

    // Concatenate shared secrets
    byte[] keyMaterial = ByteBuffer.allocate(ka1.length + ka2.length).put(ka1).put(ka2).array();

    // Build sharedInfo for KDF
    byte[] sharedInfo =
        ByteBuffer.allocate(keyUsage.length + keyType.length + keyLen.length)
            .put(keyUsage)
            .put(keyType)
            .put(keyLen)
            .array();

    // Derive keys using SHA-256 KDF
    List<SecretKey> keys = new ArrayList<>();
    int counter = 1;
    for (int i = 0; i < 3; i++) {
      MessageDigest hash = MessageDigest.getInstance("SHA256");
      hash.update(keyMaterial);
      hash.update(ByteBuffer.allocate(4).putInt(counter++).array());
      hash.update(sharedInfo);
      byte[] digest = hash.digest();
      keys.add(new SecretKeySpec(digest, 0, 16, "AES"));
      keys.add(new SecretKeySpec(digest, 16, 16, "AES"));
      Arrays.fill(digest, (byte) 0);
    }

    // Key assignment (from library's SessionKeys constructor order):
    // keys[0] = receipt key (used for receipt calculation only)
    // keys[1] = S-ENC (first param to SessionKeys)
    // keys[2] = S-MAC (second param)
    // keys[3] = S-RMAC (third param)
    // keys[4] = DEK (fourth param)

    // Build key agreement data for receipt calculation
    // keyAgreementData = commandData || epkSdTlv
    byte[] epkSdTlv = Tlv.encode(0x5F49, epkSdEncodedPoint);
    byte[] keyAgreementData =
        ByteBuffer.allocate(commandData.length + epkSdTlv.length)
            .put(commandData)
            .put(epkSdTlv)
            .array();

    // Calculate receipt = CMAC(receiptKey, keyAgreementData)
    Mac mac = Mac.getInstance("AESCMAC");
    mac.init(keys.getFirst());
    byte[] receipt = mac.doFinal(keyAgreementData);

    // Build response: 5F49 (ephemeral SD public key) || 86 (receipt)
    ByteArrayOutputStream response = new ByteArrayOutputStream();
    response.write(epkSdTlv);
    response.write(Tlv.encode(0x86, receipt));

    // Create SCP state with session keys
    // MAC chain is initialized with the receipt
    // Library order: SessionKeys(keys[1]=senc, keys[2]=smac, keys[3]=srmac, keys[4]=dek)
    ScpState scpState =
        new ScpState(
            keys.get(1), // S-ENC
            keys.get(2), // S-MAC
            keys.get(3), // S-RMAC
            keys.get(4), // DEK
            receipt // Initial MAC chain
            );

    return new Scp11bResult(response.toByteArray(), scpState);
  }

  /**
   * Encodes an EC public key as an uncompressed point.
   *
   * @param publicKey the EC public key
   * @return encoded point (0x04 || x || y)
   */
  private byte[] encodeEcPoint(ECPublicKey publicKey) {
    byte[] x = publicKey.getW().getAffineX().toByteArray();
    byte[] y = publicKey.getW().getAffineY().toByteArray();

    // Remove leading zero and pad to 32 bytes
    x = padTo32Bytes(removeLeadingZero(x));
    y = padTo32Bytes(removeLeadingZero(y));

    ByteBuffer buffer = ByteBuffer.allocate(65);
    buffer.put((byte) 0x04);
    buffer.put(x);
    buffer.put(y);
    return buffer.array();
  }

  /**
   * Decodes an uncompressed EC point to a public key.
   *
   * @param encodedPoint the encoded point (0x04 || x || y)
   * @return the EC public key
   */
  private ECPublicKey decodeEcPoint(byte[] encodedPoint) throws Exception {
    if (encodedPoint[0] != 0x04 || encodedPoint.length != 65) {
      throw new IllegalArgumentException("Invalid uncompressed EC point");
    }

    byte[] x = Arrays.copyOfRange(encodedPoint, 1, 33);
    byte[] y = Arrays.copyOfRange(encodedPoint, 33, 65);

    java.math.BigInteger xInt = new java.math.BigInteger(1, x);
    java.math.BigInteger yInt = new java.math.BigInteger(1, y);

    java.security.spec.ECPoint point = new java.security.spec.ECPoint(xInt, yInt);

    // Get P-256 parameters
    java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("EC");
    params.init(new ECGenParameterSpec("secp256r1"));
    java.security.spec.ECParameterSpec ecParams =
        params.getParameterSpec(java.security.spec.ECParameterSpec.class);

    java.security.spec.ECPublicKeySpec keySpec =
        new java.security.spec.ECPublicKeySpec(point, ecParams);
    java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("EC");
    return (ECPublicKey) keyFactory.generatePublic(keySpec);
  }

  private byte[] removeLeadingZero(byte[] bytes) {
    if (bytes.length > 0 && bytes[0] == 0) {
      return Arrays.copyOfRange(bytes, 1, bytes.length);
    }
    return bytes;
  }

  private byte[] padTo32Bytes(byte[] bytes) {
    if (bytes.length >= 32) {
      return Arrays.copyOfRange(bytes, bytes.length - 32, bytes.length);
    }
    byte[] padded = new byte[32];
    System.arraycopy(bytes, 0, padded, 32 - bytes.length, bytes.length);
    return padded;
  }

  /** Result of SCP11b INTERNAL AUTHENTICATE processing. */
  public record Scp11bResult(byte[] responseData, ScpState scpState) {}

  /** Simple TLV parsing utility. */
  public static class Tlv {
    public final int tag;
    public final byte[] value;

    public Tlv(int tag, byte[] value) {
      this.tag = tag;
      this.value = value;
    }

    public static List<Tlv> parseAll(byte[] data) {
      List<Tlv> result = new ArrayList<>();
      int offset = 0;
      while (offset < data.length) {
        int tag = data[offset++] & 0xFF;
        if ((tag & 0x1F) == 0x1F) {
          // Multi-byte tag
          tag = (tag << 8) | (data[offset++] & 0xFF);
        }

        int length = data[offset++] & 0xFF;
        if (length == 0x81) {
          length = data[offset++] & 0xFF;
        } else if (length == 0x82) {
          length = ((data[offset++] & 0xFF) << 8) | (data[offset++] & 0xFF);
        }

        byte[] value = Arrays.copyOfRange(data, offset, offset + length);
        offset += length;
        result.add(new Tlv(tag, value));
      }
      return result;
    }

    public static byte[] encode(int tag, byte[] value) {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      try {
        if (tag > 0xFF) {
          out.write((tag >> 8) & 0xFF);
          out.write(tag & 0xFF);
        } else {
          out.write(tag);
        }

        if (value.length < 0x80) {
          out.write(value.length);
        } else if (value.length < 0x100) {
          out.write(0x81);
          out.write(value.length);
        } else {
          out.write(0x82);
          out.write((value.length >> 8) & 0xFF);
          out.write(value.length & 0xFF);
        }
        out.write(value);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
      return out.toByteArray();
    }
  }
}
