package dev.ethantmcgee.yubiauthn.emulator.scp;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import lombok.Getter;

/**
 * Manages SCP11b secure channel state and cryptographic operations.
 *
 * <p>This class handles encryption, decryption, and MAC operations for the SCP11b secure channel
 * protocol used by YubiKey devices.
 */
public class ScpState {
  @Getter private final SecretKey senc; // Session encryption key
  @Getter private final SecretKey smac; // Session MAC key
  @Getter private final SecretKey srmac; // Session response MAC key
  @Getter private final SecretKey dek; // Data encryption key (optional)

  private byte[] macChain;
  private int encCounter = 1;

  public ScpState(SecretKey senc, SecretKey smac, SecretKey srmac, SecretKey dek, byte[] macChain) {
    this.senc = senc;
    this.smac = smac;
    this.srmac = srmac;
    this.dek = dek;
    this.macChain = macChain;
  }

  /**
   * Encrypts response data using S-ENC key. Uses the current encCounter - 1 because decrypt()
   * already incremented it. Response encryption uses 0x80 prefix in IV.
   *
   * @param data plaintext data to encrypt
   * @return encrypted data
   */
  public byte[] encrypt(byte[] data) {
    int padLen = 16 - data.length % 16;
    byte[] padded = Arrays.copyOf(data, data.length + padLen);
    padded[data.length] = (byte) 0x80;

    byte[] result;
    try {
      Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, senc);
      // Response encryption uses 0x80 prefix and encCounter - 1 (the counter used for decryption)
      byte[] ivData =
          ByteBuffer.allocate(16).put((byte) 0x80).put(new byte[11]).putInt(encCounter - 1).array();
      System.out.println("Encrypt using counter: " + (encCounter - 1) + " with 0x80 prefix");
      byte[] iv = cipher.doFinal(ivData);
      System.out.println("Encrypt IV: " + bytesToHex(iv));

      cipher = Cipher.getInstance("AES/CBC/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, senc, new IvParameterSpec(iv));
      result = cipher.doFinal(padded);
    } catch (NoSuchPaddingException
        | NoSuchAlgorithmException
        | IllegalBlockSizeException
        | BadPaddingException
        | InvalidAlgorithmParameterException
        | InvalidKeyException e) {
      throw new RuntimeException(e);
    } finally {
      Arrays.fill(padded, (byte) 0);
    }

    return result;
  }

  /**
   * Decrypts incoming command data using S-ENC key. Uses the current encCounter value (not
   * encCounter - 1) because this is the counter the sender used to encrypt.
   *
   * @param encrypted encrypted data to decrypt
   * @return decrypted plaintext data
   * @throws IllegalArgumentException if padding is invalid
   */
  public byte[] decrypt(byte[] encrypted) {
    try {
      Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, senc);
      // Command decryption uses counter (0x00 prefix)
      int counterToUse = encCounter++;
      byte[] ivData = ByteBuffer.allocate(16).put(new byte[12]).putInt(counterToUse).array();
      System.out.println("Decrypt using counter: " + counterToUse);
      byte[] iv = cipher.doFinal(ivData);
      System.out.println("Decrypt IV: " + bytesToHex(iv));

      cipher = Cipher.getInstance("AES/CBC/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, senc, new IvParameterSpec(iv));
      byte[] decrypted = cipher.doFinal(encrypted);
      System.out.println("Raw decrypted: " + bytesToHex(decrypted));

      // Find and remove padding
      // Padding is 0x80 followed by zero or more 0x00 bytes
      int i = decrypted.length - 1;
      while (i >= 0) {
        if (decrypted[i] == (byte) 0x80) {
          byte[] result = Arrays.copyOf(decrypted, i);
          Arrays.fill(decrypted, (byte) 0);
          return result;
        }
        if (decrypted[i] != 0) {
          System.out.println(
              "Bad padding at position " + i + ": " + String.format("%02x", decrypted[i]));
          Arrays.fill(decrypted, (byte) 0);
          throw new IllegalArgumentException("Bad padding");
        }
        i--;
      }
      Arrays.fill(decrypted, (byte) 0);
      throw new IllegalArgumentException("Bad padding");
    } catch (NoSuchPaddingException
        | NoSuchAlgorithmException
        | IllegalBlockSizeException
        | BadPaddingException
        | InvalidAlgorithmParameterException
        | InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }

  private static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  /**
   * Computes MAC for command data using S-MAC key.
   *
   * @param data command data to MAC
   * @return 8-byte MAC
   */
  public byte[] mac(byte[] data) {
    try {
      Mac mac = Mac.getInstance("AESCMAC");
      mac.init(smac);
      mac.update(macChain);
      macChain = mac.doFinal(data);
      return Arrays.copyOf(macChain, 8);
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new UnsupportedOperationException("Cryptography provider does not support AESCMAC", e);
    }
  }

  /**
   * Computes response MAC for outgoing data.
   *
   * @param data response data (without MAC)
   * @param sw status word
   * @return 8-byte response MAC
   */
  public byte[] computeResponseMac(byte[] data, short sw) {
    byte[] msg = ByteBuffer.allocate(data.length + 2).put(data).putShort(sw).array();

    try {
      Mac mac = Mac.getInstance("AESCMAC");
      mac.init(srmac);
      mac.update(macChain);
      return Arrays.copyOf(mac.doFinal(msg), 8);
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new UnsupportedOperationException("Cryptography provider does not support AESCMAC", e);
    }
  }
}
